//! Windows-specific process implementation.

use std::io;
use std::process::ExitStatus;

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
    System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE},
};

use crate::error::Result;

/// Windows process child handle.
pub struct WindowsChild {
    handle: HANDLE,
    job_handle: Option<HANDLE>,
}

impl WindowsChild {
    pub fn new(process_handle: u32, job_handle: Option<u32>) -> Self {
        Self {
            handle: HANDLE(process_handle as isize),
            job_handle: job_handle.map(|h| HANDLE(h as isize)),
        }
    }

    pub fn wait(&mut self) -> Result<ExitStatus> {
        unsafe {
            // Wait for the process to complete
            WaitForSingleObject(self.handle, INFINITE);

            // Get the exit code
            let mut exit_code = 0u32;
            GetExitCodeProcess(self.handle, &mut exit_code)?;

            // Convert to Rust's ExitStatus
            Ok(ExitStatus::from_raw(exit_code))
        }
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        unsafe {
            // Check if process has exited without waiting
            match WaitForSingleObject(self.handle, 0) {
                WAIT_OBJECT_0 => {
                    let mut exit_code = 0u32;
                    GetExitCodeProcess(self.handle, &mut exit_code)?;
                    Ok(Some(ExitStatus::from_raw(exit_code)))
                }
                _ => Ok(None),
            }
        }
    }

    pub fn kill(&mut self) -> Result<()> {
        unsafe {
            windows::Win32::System::ProcessApi::TerminateProcess(self.handle, 1)?;
            Ok(())
        }
    }

    pub fn id(&self) -> u32 {
        unsafe { windows::Win32::System::ProcessApi::GetProcessId(self.handle) }
    }
}

impl Drop for WindowsChild {
    fn drop(&mut self) {
        unsafe {
            if let Some(job_handle) = self.job_handle {
                let _ = CloseHandle(job_handle);
            }
            let _ = CloseHandle(self.handle);
        }
    }
}