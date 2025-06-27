#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use crate::process::linux::{
    Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio,
};
#[cfg(target_os = "macos")]
pub use crate::process::macos::{
    Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio,
};
#[cfg(target_os = "windows")]
pub use crate::process::windows::WindowsChild as Child;
#[cfg(target_os = "windows")]
pub use std::process::{Command, ExitStatus, Output, Stdio};
#[cfg(target_os = "windows")]
pub use std::process::{ChildStderr, ChildStdin, ChildStdout};
