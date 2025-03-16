use std::process::Command;
use std::path::Path;

use crate::logging;

pub fn ensure_user_exists(username: &str, add_sudo: bool) -> Result<bool, String> {
    // Check if user exists
    let user_exists = Command::new("id")
        .arg(username)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    if user_exists {
        return Ok(true);
    }

    logging::log_to_file(&format!("Creating user: {}", username));
    
    let output = Command::new("sudo")
        .args([
            "useradd",
            "-m",
            "-s", "/bin/bash",
            username
        ])
        .output()
        .map_err(|e| format!("Failed to execute useradd: {}", e))?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to create user: {}", error));
    }

    // Create .ssh directory and authorized_keys file using sudo
    let home_dir = format!("/home/{}", username);
    let ssh_dir = format!("{}/.ssh", home_dir);
    
    // Create .ssh directory with sudo if it doesn't exist
    if !Path::new(&ssh_dir).exists() {
        let mkdir_output = Command::new("sudo")
            .args(["mkdir", "-p", &ssh_dir])
            .output()
            .map_err(|e| format!("Failed to create .ssh directory: {}", e))?;
            
        if !mkdir_output.status.success() {
            let error = String::from_utf8_lossy(&mkdir_output.stderr);
            return Err(format!("Failed to create .ssh directory: {}", error));
        }
    }

    // Create empty authorized_keys file if it doesn't exist
    let auth_keys_path = format!("{}/authorized_keys", ssh_dir);
    if !Path::new(&auth_keys_path).exists() {
        let touch_output = Command::new("sudo")
            .args(["touch", &auth_keys_path])
            .output()
            .map_err(|e| format!("Failed to create authorized_keys file: {}", e))?;
            
        if !touch_output.status.success() {
            let error = String::from_utf8_lossy(&touch_output.stderr);
            return Err(format!("Failed to create authorized_keys file: {}", error));
        }
    }

    // Set proper permissions using sudo
    let chmod_ssh_output = Command::new("sudo")
        .args(["chmod", "700", &ssh_dir])
        .output()
        .map_err(|e| format!("Failed to set permissions on .ssh directory: {}", e))?;
        
    if !chmod_ssh_output.status.success() {
        let error = String::from_utf8_lossy(&chmod_ssh_output.stderr);
        return Err(format!("Failed to set permissions on .ssh directory: {}", error));
    }

    let chmod_keys_output = Command::new("sudo")
        .args(["chmod", "600", &auth_keys_path])
        .output()
        .map_err(|e| format!("Failed to set permissions on authorized_keys file: {}", e))?;
        
    if !chmod_keys_output.status.success() {
        let error = String::from_utf8_lossy(&chmod_keys_output.stderr);
        return Err(format!("Failed to set permissions on authorized_keys file: {}", error));
    }

    // Change ownership of home directory and contents to the new user
    let chown_output = Command::new("sudo")
        .args([
            "chown",
            "-R",
            &format!("{}:{}", username, username),
            &home_dir
        ])
        .output()
        .map_err(|e| format!("Failed to execute chown: {}", e))?;

    if !chown_output.status.success() {
        let error = String::from_utf8_lossy(&chown_output.stderr);
        return Err(format!("Failed to set ownership: {}", error));
    }

    // Add user to sudoers if requested
    if add_sudo {
        if let Err(err) = add_user_to_sudoers(username) {
            logging::log_to_file(&format!("Warning: Failed to add user to sudoers: {}", err));
        } else {
            logging::log_to_file(&format!("Added user {} to sudoers", username));
        }
    }

    Ok(false)
}

fn add_user_to_sudoers(username: &str) -> Result<(), String> {

    let sudoers_file = format!("/etc/sudoers.d/{}", username);
    

    if Path::new(&sudoers_file).exists() {
        return Ok(());
    }
    
	// change this if you would like to use a different sudoers permission
    let sudoers_content = format!("{}  ALL=(ALL) NOPASSWD:ALL", username);
    

    let output = Command::new("sudo")
        .args([
            "bash", "-c", 
            &format!("echo '{}' > {} && chmod 0440 {}", 
                sudoers_content, sudoers_file, sudoers_file)
        ])
        .output()
        .map_err(|e| format!("Failed to create sudoers file: {}", e))?;
        
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to create sudoers file: {}", error));
    }
    
    // Verify the sudoers file syntax
    let visudo_check = Command::new("sudo")
        .args(["visudo", "-c", "-f", &sudoers_file])
        .output()
        .map_err(|e| format!("Failed to verify sudoers file: {}", e))?;
    
    if !visudo_check.status.success() {
        // If the syntax check failed, remove the file and return an error
        let _ = Command::new("sudo")
            .args(["rm", "-f", &sudoers_file])
            .status();
        let error = String::from_utf8_lossy(&visudo_check.stderr);
        return Err(format!("Invalid sudoers syntax: {}", error));
    }
    
    logging::log_to_file(&format!("Created sudoers file for {}", username));
    Ok(())
}

pub fn add_authorized_key(username: &str, key: &str) -> Result<(), String> {
	let ssh_dir = format!("/home/{}/.ssh", username);
	let auth_keys_path = format!("{}/authorized_keys", ssh_dir);

	// Append the key to the authorized_keys file
	let output = Command::new("sudo")
		.args(["bash", "-c", &format!("echo '{}' >> {}", key, auth_keys_path)])
		.output()
		.map_err(|e| format!("Failed to add key to authorized_keys: {}", e))?;

	if !output.status.success() {
		let error = String::from_utf8_lossy(&output.stderr);
		return Err(format!("Failed to add key to authorized_keys: {}", error));
	}

	Ok(())
}