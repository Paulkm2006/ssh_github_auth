use pam_sys::{PamHandle, PamReturnCode, PamFlag, PamItemType, wrapped::get_user};
use std::ffi::{CStr, CString};
use std::ptr;
use std::fs::OpenOptions;
use std::io::Write;
use libc;

pub mod github;


use std::collections::HashMap;

// Parse arguments into a HashMap for easy access
fn parse_args(argc: libc::c_int, argv: *const *const libc::c_char) -> HashMap<String, String> {
    let mut args_map = HashMap::new();
    let mut flags = Vec::new();
    
    for i in 0..argc {
        unsafe {
            let arg_ptr = *argv.offset(i as isize);
            let arg = CStr::from_ptr(arg_ptr).to_string_lossy().into_owned();
            
            // Check if the argument is a key=value pair
            if let Some(pos) = arg.find('=') {
                let (key, value) = arg.split_at(pos);
                // Skip the '=' character
                args_map.insert(key.to_string(), value[1..].to_string());
            } else {
                // It's a flag
                flags.push(arg);
            }
        }
    }
    
    // Add flags as keys with empty values
    for flag in flags {
        args_map.insert(flag, String::new());
    }
    
    args_map
}


// Helper function to prompt for input
fn prompt_user(pamh: *mut PamHandle, prompt: &str, echo: bool) -> Result<String, PamReturnCode> {
    let response_ptr: *const libc::c_char;
    let c_prompt = CString::new(prompt).unwrap();
    
    // Style parameter for conversation
    let style = match echo{
        true => pam_sys::PamMessageStyle::PROMPT_ECHO_ON,
        false => pam_sys::PamMessageStyle::PROMPT_ECHO_OFF,
    };
    
    let ret = unsafe {
        // Get conversation function
        let conv_ptr: *const pam_sys::PamConversation = ptr::null();
        let status = pam_sys::get_item(
            &*pamh,
            PamItemType::CONV,
            &mut (conv_ptr as *const libc::c_void),
        );
        
        if status != PamReturnCode::SUCCESS || conv_ptr.is_null() {
            return Err(PamReturnCode::CONV_ERR);
        }
        
        // Create message
        let msg = pam_sys::PamMessage {
            msg_style: style as i32,
            msg: c_prompt.as_ptr(),
        };
        
        let msgs = vec![&msg as *const pam_sys::PamMessage];
        let mut resp: *mut pam_sys::PamResponse = ptr::null_mut();
        
        // Call conversation function
        let conv_fn = (*conv_ptr).conv.expect("Conversation function is null");
        let conv_data = (*conv_ptr).data_ptr;
        
        let status_i32 = conv_fn(
            1,
            msgs.as_ptr() as *mut *mut pam_sys::PamMessage,
            &mut resp,
            conv_data,
        );
        
        if PamReturnCode::from(status_i32) != PamReturnCode::SUCCESS || resp.is_null() {
            return Err(PamReturnCode::CONV_ERR);
        }
        
        // Get response
        response_ptr = (*resp).resp;
        status
    };
    
    if ret != PamReturnCode::SUCCESS {
        return Err(ret);
    }
    
    if response_ptr.is_null() {
        return Err(PamReturnCode::CONV_ERR);
    }
    
    let response = unsafe { CStr::from_ptr(response_ptr) }
        .to_string_lossy()
        .into_owned();
    
    // Free the response memory allocated by PAM
    unsafe { libc::free(response_ptr as *mut libc::c_void) };
    
    Ok(response)
}

// Optional: Log to a file for debugging
fn log_to_file(message: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/github_ssh.log")
        .unwrap_or_else(|_| panic!("Failed to open log file"));
    
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    writeln!(file, "[{}] {}", timestamp, message)
        .unwrap_or_else(|_| panic!("Failed to write to log file"));
}

// PAM authentication function
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: PamFlag,
    argc: libc::c_int,
    argv: *const *const libc::c_char,
) -> PamReturnCode {

    let args = parse_args(argc, argv);
    
    // Check if the required arguments are present
    let org = match args.get("org") {
        Some(org) => org,
        None => {
            log_to_file("Missing organization name");
            return PamReturnCode::SERVICE_ERR;
        }
    };
    let client_id = match args.get("client_id") {
        Some(client_id) => client_id,
        None => {
            log_to_file("Missing client ID");
            return PamReturnCode::SERVICE_ERR;
        }
    };

    // Get username
    let mut user = ptr::null();
    let username = match unsafe { get_user(&*pamh, &mut user, ptr::null()) } {
        PamReturnCode::SUCCESS => {
            let username_cstr = unsafe { CStr::from_ptr(user) };
            username_cstr.to_string_lossy().into_owned()
        },
        code => {
            log_to_file(&format!("Failed to get username: {:?}", code));
            return code;
        }
    };

    log_to_file(&format!("Authentication request for username: {}", username));

    // Prompt for device auth
    let (device_code, user_code) = match github::get_auth_code(&client_id) {
        Ok(code) => code,
        Err(err) => {
            log_to_file(&format!("Failed to get device code: {:?}", err));
            return PamReturnCode::SERVICE_ERR;
        }
    };

    // Prompt user for device code
    let prompt = format!(
        "Please visit https://github.com/login/device and enter the following code: {}\n\
        You have 10 minutes to complete this step.
        \nAfter a successful login, press Enter to continue...",
        user_code
    );
    println!("\n{}", prompt);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let device_code = device_code.trim().to_string();

    // Retrieve user info
    let github_user = match github::GithubUser::from_device_code(&device_code, client_id, &username, org) {
        Ok(user) => user,
        Err(err) => {
            match err {
                github::GithubError::NotFound => {
                    log_to_file("User not found in organization");
                    return PamReturnCode::USER_UNKNOWN;
                }
                github::GithubError::InvalidUser(info) => {
                    log_to_file(&format!("Invalid user: {:?}", info));
                    return PamReturnCode::USER_UNKNOWN;
                }
                _ => {
                    log_to_file(&format!("Unexpected error: {:?}", err));
                    return PamReturnCode::SERVICE_ERR;
                }
            }
        }
    };


    if let Some(team) = args.get("team") {
        let is_in_team = match github_user.is_in_team(team) {
            Ok(in_team) => in_team,
            Err(err) => {
                log_to_file(&format!("Failed to check team membership: {:?}", err));
                return PamReturnCode::SERVICE_ERR;
            }
        };
        if !is_in_team {
            log_to_file("User is not in the specified team");
            return PamReturnCode::USER_UNKNOWN;
        }
    }
    

    log_to_file(&format!("Authentication successful for user {}", username));
    PamReturnCode::SUCCESS
}


// Required PAM functions that we need to implement
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: PamFlag,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> PamReturnCode {
    PamReturnCode::SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut PamHandle,
    _flags: PamFlag,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> PamReturnCode {
    PamReturnCode::SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_open_session(
    _pamh: *mut PamHandle,
    _flags: PamFlag,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> PamReturnCode {
    PamReturnCode::SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: PamFlag,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> PamReturnCode {
    PamReturnCode::SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_chauthtok(
    _pamh: *mut PamHandle,
    _flags: PamFlag,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> PamReturnCode {
    PamReturnCode::SUCCESS
}
