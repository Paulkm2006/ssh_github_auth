use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;

pub fn log_to_file(message: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/github_ssh.log") 
    {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = writeln!(file, "[{}] {}", timestamp, message);
    }
    
    // Also log to system log
    let _ = Command::new("logger")
        .args(["-t", "github_ssh_auth", message])
        .status();
}