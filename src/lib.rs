use pam_sys::{PamHandle, PamReturnCode, PamFlag, PamItemType, wrapped::get_user};
use user::ensure_user_exists;
use std::ffi::{CStr, CString};
use std::ptr;
use std::collections::HashMap;
use libc;

pub mod github;
pub mod user;
pub mod logging;


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



fn prompt_user(pamh: *mut PamHandle, prompt: &str, style: pam_sys::PamMessageStyle) -> Result<String, PamReturnCode> {
    let c_prompt = CString::new(prompt).unwrap();
    

    // Create message structure
    let msg = pam_sys::PamMessage {
        msg_style: style as i32,
        msg: c_prompt.as_ptr(),
    };
    
    // Create pointer to message
    let pmsg = [&msg as *const pam_sys::PamMessage];
    
    // Prepare response pointer
    let mut response_ptr: *mut pam_sys::PamResponse = ptr::null_mut();
    
    // Get conversation function
    let mut conv_ptr: *const libc::c_void = ptr::null();
    let ret = unsafe {
        pam_sys::get_item(
            &*pamh, 
            PamItemType::CONV, 
            &mut conv_ptr
        )
    };

    // After get_item completes, cast to the right type
    let conv_ptr = conv_ptr as *const pam_sys::PamConversation;
    
    if ret != PamReturnCode::SUCCESS || conv_ptr.is_null() {
        println!("Failed to get conversation function");
        return Err(PamReturnCode::CONV_ERR);
    }
    
    // Call conversation function
    let conv = unsafe { &*conv_ptr };
    let ret = 
        if let Some(conv_fn) = conv.conv {
            PamReturnCode::from(conv_fn(
                1,
                pmsg.as_ptr() as *mut *mut pam_sys::PamMessage,
                &mut response_ptr as *mut *mut pam_sys::PamResponse,
                conv.data_ptr
            ))
        } else {
            println!("Conversation function is null");
            PamReturnCode::CONV_ERR
        };



    if ret != PamReturnCode::SUCCESS {
        return Err(ret);
    }
    
    if response_ptr.is_null() {
        println!("Response pointer is null");
        return Err(PamReturnCode::CONV_ERR);
    }

    
    if style == pam_sys::PamMessageStyle::PROMPT_ECHO_OFF || style == pam_sys::PamMessageStyle::PROMPT_ECHO_ON {
        let resp_ptr = unsafe { (*response_ptr).resp };
        let response = unsafe { CStr::from_ptr(resp_ptr) }
            .to_string_lossy()
            .into_owned();
        
        unsafe { libc::free(response_ptr as *mut libc::c_void) };
        return Ok(response);
    } 
    
    Ok("".to_string())
}



#[unsafe(no_mangle)]
#[allow(improper_ctypes_definitions)]
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
            logging::log_to_file("Missing organization name");
            return PamReturnCode::SERVICE_ERR;
        }
    };
    let client_id = match args.get("client_id") {
        Some(client_id) => client_id,
        None => {
            logging::log_to_file("Missing client ID");
            return PamReturnCode::SERVICE_ERR;
        }
    };
    let auto_create_user = args.contains_key("auto_create_user");
    let auto_create_user_sudoer = if auto_create_user {
        match args.get("auto_create_user") {
            Some(sudoer) => match sudoer.as_str() {
                "sudoer" => true,
                _ => false

            },
            None => false
        }
    } else {
        false
    };
    let allow_import_keys = args.contains_key("allow_import_keys");

    // Get username
    let mut user = ptr::null();
    let username = match unsafe { get_user(&*pamh, &mut user, ptr::null()) } {
        PamReturnCode::SUCCESS => {
            let username_cstr = unsafe { CStr::from_ptr(user) };
            username_cstr.to_string_lossy().into_owned()
        },
        code => {
            logging::log_to_file(&format!("Failed to get username: {:?}", code));
            return code;
        }
    }.to_ascii_lowercase();

    logging::log_to_file(&format!("Authentication request for username: {}", username));

    // Prompt for device auth
    let (device_code, user_code) = match github::get_auth_code(&client_id) {
        Ok(code) => code,
        Err(err) => {
            logging::log_to_file(&format!("Failed to get device code: {:?}", err));
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


    let _ = match prompt_user(pamh, &prompt, pam_sys::PamMessageStyle::PROMPT_ECHO_OFF) {
        Ok(resp) => resp,
        Err(err) => {
            logging::log_to_file(&format!("Failed to prompt user: {:?}", err));
            return PamReturnCode::SERVICE_ERR;
        }
    };



    let device_code = device_code.trim().to_string();

    // Retrieve user info
    let github_user = match github::GithubUser::from_device_code(&device_code, client_id, &username, org) {
        Ok(user) => user,
        Err(err) => {
            match err {
                github::GithubError::NotFound => {
                    logging::log_to_file("User not found in organization");
                    let _ = prompt_user(pamh, "User not found in organization", pam_sys::PamMessageStyle::ERROR_MSG);
                    return PamReturnCode::USER_UNKNOWN;
                }
                github::GithubError::InvalidUser(info) => {
                    logging::log_to_file(&format!("Invalid user: {:?}", info));
                    return PamReturnCode::USER_UNKNOWN;
                }
                github::GithubError::Unauthorized => {
                    logging::log_to_file("Unauthorized access");
                    let _ = prompt_user(pamh, "Unauthorized access", pam_sys::PamMessageStyle::ERROR_MSG);
                    return PamReturnCode::USER_UNKNOWN;
                }
                _ => {
                    logging::log_to_file(&format!("Unexpected error: {:?}", err));
                    return PamReturnCode::SERVICE_ERR;
                }
            }
        }
    };


    if let Some(team) = args.get("team") {
        let is_in_team = match github_user.is_in_team(team) {
            Ok(in_team) => in_team,
            Err(err) => {
                logging::log_to_file(&format!("Failed to check team membership: {:?}", err));
                return PamReturnCode::SERVICE_ERR;
            }
        };
        if !is_in_team {
            let _ = prompt_user(pamh, "User is not in the specified team", pam_sys::PamMessageStyle::ERROR_MSG);
            logging::log_to_file("User is not in the specified team");
            return PamReturnCode::USER_UNKNOWN;
        }
    }

    let _ = match prompt_user(pamh, "Authentication successful", pam_sys::PamMessageStyle::TEXT_INFO) {
        Ok(_) => {},
        Err(err) => {
            logging::log_to_file(&format!("Failed to prompt user: {:?}", err));
            return PamReturnCode::SERVICE_ERR;
        }
    };
    logging::log_to_file(&format!("Authentication successful for user {}", username));


    if auto_create_user {
        match ensure_user_exists(&username, auto_create_user_sudoer) {
            Ok(existed) => {
                if existed {
                    logging::log_to_file(&format!("User {} already exists", username));
                } else {
                    logging::log_to_file(&format!("Created user {}", username));
                }
            },
            Err(err) => {
                logging::log_to_file(&format!("Failed to create user: {}", err));
                return PamReturnCode::SERVICE_ERR;
            }
        }
    }

    if allow_import_keys {
        let ans = prompt_user(
            pamh,
            "Do you want to import your SSH keys from GitHub? (y/n) ",
            pam_sys::PamMessageStyle::PROMPT_ECHO_ON,
        );
        if let Err(err) = ans {
            logging::log_to_file(&format!("Failed to prompt user: {:?}", err));
            return PamReturnCode::SERVICE_ERR;
        }
        let ans = ans.unwrap();
        let ans = ans.trim().to_lowercase();
        if ans.trim().to_lowercase() != "y" {
            logging::log_to_file("User declined to import keys");
            return PamReturnCode::SUCCESS;
        }
        logging::log_to_file("User accepted to import keys");
        match github_user.get_keys() {
            Ok(_) => {
                let keys = github_user.get_keys().unwrap();
                if let Err(e) = user::add_authorized_key(&username, &keys) {
                    logging::log_to_file(&format!("Failed to import keys: {}", e));
                    return PamReturnCode::SERVICE_ERR;
                }
                logging::log_to_file(&format!("Imported keys for user {}", username));
            },
            Err(err) => {
                logging::log_to_file(&format!("Failed to import keys: {:?}", err));
                return PamReturnCode::SERVICE_ERR;
            }
        }
    }

    PamReturnCode::SUCCESS
}



#[allow(improper_ctypes_definitions)]
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
#[allow(improper_ctypes_definitions)]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut PamHandle,
    _flags: PamFlag,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> PamReturnCode {
    PamReturnCode::SUCCESS
}

#[unsafe(no_mangle)]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn pam_sm_open_session(
    _pamh: *mut PamHandle,
    _flags: PamFlag,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> PamReturnCode {
    PamReturnCode::SUCCESS
}

#[unsafe(no_mangle)]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: PamFlag,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> PamReturnCode {
    PamReturnCode::SUCCESS
}

#[unsafe(no_mangle)]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn pam_sm_chauthtok(
    _pamh: *mut PamHandle,
    _flags: PamFlag,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> PamReturnCode {
    PamReturnCode::SUCCESS
}
