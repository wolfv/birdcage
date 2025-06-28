//! Windows sandbox integration test.

use birdcage::{Birdcage, Exception, Sandbox};
use std::process;

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("Windows sandbox tests can only run on Windows");
}

#[cfg(target_os = "windows")]
fn main() {
    println!("Running Windows sandbox integration tests...");

    // Run tests and collect results
    let mut passed = 0;
    let mut total = 0;

    total += 1;
    if run_test("Basic command execution", test_basic_command) {
        passed += 1;
    }

    total += 1;
    if run_test("Networking", test_networking) {
        passed += 1;
    }

    total += 1;
    if run_test("Environment variable access", test_environment) {
        passed += 1;
    }

    println!("\nTest Results: {}/{} passed", passed, total);

    if passed != total {
        process::exit(1);
    }
}

#[cfg(target_os = "windows")]
fn run_test<F>(name: &str, test_fn: F) -> bool
where
    F: Fn() -> Result<(), Box<dyn std::error::Error>>,
{
    print!("Testing {}... ", name);
    match test_fn() {
        Ok(()) => {
            println!("✓ PASSED");
            true
        },
        Err(e) => {
            println!("✗ FAILED: {}", e);
            false
        },
    }
}

#[cfg(target_os = "windows")]
fn test_basic_command() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Birdcage::new();

    // Allow basic Windows system access
    sandbox.add_exception(Exception::ExecuteAndRead("C:\\Windows\\System32".into()))?;
    sandbox.add_exception(Exception::ExecuteAndRead("C:\\Windows\\SysWOW64".into()))?;

    // Test running a simple command
    let mut command = birdcage::process::Command::new("cmd");
    command.args(&["/C", "echo", "Hello from sandbox"]);

    let mut child = sandbox.spawn(command)?;
    let status = child.wait()?;

    if !status.success() {
        return Err("Command execution failed".into());
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn test_networking() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Birdcage::new();

    // Allow networking
    sandbox.add_exception(Exception::Networking)?;

    // Allow system access
    sandbox.add_exception(Exception::ExecuteAndRead("C:\\Windows\\System32".into()))?;

    let mut command = birdcage::process::Command::new("ping");
    command.args(&["-n", "1", "127.0.0.1"]);

    let mut child = sandbox.spawn(command)?;
    let status = child.wait()?;

    if !status.success() {
        return Err("Networking test failed".into());
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn test_environment() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = Birdcage::new();

    // Allow specific environment variables
    sandbox.add_exception(Exception::Environment("PATH".to_string()))?;
    sandbox.add_exception(Exception::Environment("COMSPEC".to_string()))?;

    // Allow system access
    sandbox.add_exception(Exception::ExecuteAndRead("C:\\Windows\\System32".into()))?;

    let mut command = birdcage::process::Command::new("cmd");
    command.args(&["/C", "echo", "%PATH%"]);

    let mut child = sandbox.spawn(command)?;
    let status = child.wait()?;

    if !status.success() {
        return Err("Environment variable test failed".into());
    }

    Ok(())
}
