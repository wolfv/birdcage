//! Windows sandbox integration test.

#[cfg(target_os = "windows")]
mod windows_tests {
    use std::process::Command;
    use birdcage::{Birdcage, Exception, Sandbox};

    #[test]
    fn test_basic_windows_sandbox() {
        let mut sandbox = Birdcage::new();
        
        // Allow basic Windows system access
        sandbox
            .add_exception(Exception::ExecuteAndRead("C:\\Windows\\System32".into()))
            .unwrap();
        sandbox
            .add_exception(Exception::ExecuteAndRead("C:\\Windows\\SysWOW64".into()))
            .unwrap();

        // Test running a simple command
        let mut command = birdcage::process::Command::new("cmd");
        command.args(&["/C", "echo", "Hello from sandbox"]);
        
        let mut child = sandbox.spawn(command).unwrap();
        let status = child.wait().unwrap();
        
        assert!(status.success());
    }

    #[test]
    fn test_windows_sandbox_with_networking() {
        let mut sandbox = Birdcage::new();
        
        // Allow networking
        sandbox.add_exception(Exception::Networking).unwrap();
        
        // Allow system access
        sandbox
            .add_exception(Exception::ExecuteAndRead("C:\\Windows\\System32".into()))
            .unwrap();

        let mut command = birdcage::process::Command::new("ping");
        command.args(&["-n", "1", "127.0.0.1"]);
        
        let mut child = sandbox.spawn(command).unwrap();
        let status = child.wait().unwrap();
        
        // Ping should succeed with networking enabled
        assert!(status.success());
    }

    #[test]
    fn test_windows_sandbox_environment_restriction() {
        let mut sandbox = Birdcage::new();
        
        // Only allow specific environment variable
        sandbox.add_exception(Exception::Environment("PATH".to_string())).unwrap();
        
        // Allow system access
        sandbox
            .add_exception(Exception::ExecuteAndRead("C:\\Windows\\System32".into()))
            .unwrap();

        let mut command = birdcage::process::Command::new("cmd");
        command.args(&["/C", "set"]);
        
        let mut child = sandbox.spawn(command).unwrap();
        let status = child.wait().unwrap();
        
        assert!(status.success());
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("Windows sandbox tests can only run on Windows");
}