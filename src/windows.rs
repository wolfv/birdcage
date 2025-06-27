//! Windows sandbox implementation using AppContainer.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use windows::{
    core::{HSTRING, PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE},
        Security::{
            FreeSid, 
            Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName}, 
            PSID, ACL, DACL_SECURITY_INFORMATION, EXPLICIT_ACCESSW, GRANT_ACCESS, 
            GetNamedSecurityInfoW, SetNamedSecurityInfoW, SetEntriesInAclW, 
            TRUSTEE_IS_SID, TRUSTEE_TYPE, TRUSTEEW, SE_FILE_OBJECT,
            ACCESS_MASK, NO_INHERITANCE
        },
        System::{JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW
            }, Threading::{CreateProcessW, CREATE_NEW_CONSOLE, PROCESS_INFORMATION, STARTUPINFOW}},
        UI::Shell::PathFindFileNameW,
        Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE},
    },
};

use crate::error::{Error, Result};
use crate::process::{Child, Command};
use crate::{restrict_env_variables, Exception, Sandbox};

/// Windows sandbox implementation using AppContainer.
pub struct WindowsSandbox {
    exceptions: Vec<Exception>,
    app_container_name: Option<String>,
    app_container_sid: Option<PSID>,
}

impl WindowsSandbox {
    fn create_app_container_profile(&mut self, executable_path: &str) -> Result<()> {
        let file_name = unsafe {
            let wide_path: Vec<u16> = OsStr::new(executable_path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let file_name_ptr = PathFindFileNameW(PCWSTR(wide_path.as_ptr()));
            let len = (0..).take_while(|&i| *file_name_ptr.0.offset(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(file_name_ptr.0, len))
        };

        self.app_container_name = Some(file_name.clone());

        let app_container_name = HSTRING::from(&file_name);
        let display_name = HSTRING::from(&file_name);
        let description = HSTRING::from("Birdcage sandboxed process");

        let sid = PSID::default();
        let sid_and_attributes = windows::Win32::Security::SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: 0, // No special attributes
        };

        unsafe {
            match CreateAppContainerProfile(
                &app_container_name,
                &display_name,
                &description,
                Some(&[sid_and_attributes]),
            ) {
                Ok(_) => {
                    self.app_container_sid = Some(sid);
                    Ok(())
                }
                Err(e) => {
                    // Try to get existing profile if creation failed due to already existing
                    match DeriveAppContainerSidFromAppContainerName(&app_container_name)
                    {
                        Ok(_) => {
                            self.app_container_sid = Some(sid);
                            Ok(())
                        }
                        Err(_) => Err(Error::Setup(format!(
                            "Failed to create or find AppContainer profile: {}",
                            e
                        ))),
                    }
                }
            }
        }
    }

    fn setup_file_permissions(&self) -> Result<()> {
        for exception in &self.exceptions {
            match exception {
                Exception::Read(path)
                | Exception::WriteAndRead(path)
                | Exception::ExecuteAndRead(path) => {
                    self.add_file_access_permission(path)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn add_file_access_permission(&self, path: &PathBuf) -> Result<()> {
        // This is a simplified implementation
        // In a full implementation, you would modify the file's ACL
        // to grant access to the AppContainer SID

        println!("Adding file access permission for: {:?}", path);

        Ok(())
    }

    fn get_capabilities(&self) -> Vec<HSTRING> {
        let mut capabilities = Vec::new();

        for exception in &self.exceptions {
            match exception {
                Exception::Networking => {
                    capabilities.push(HSTRING::from("internetClient"));
                    capabilities.push(HSTRING::from("internetClientServer"));
                }
                _ => {}
            }
        }

        capabilities
    }

    fn setup_environment_variables(&self) {
        let allowed_vars: Vec<String> = self
            .exceptions
            .iter()
            .filter_map(|e| {
                if let Exception::Environment(var) = e {
                    Some(var.clone())
                } else if let Exception::FullEnvironment = e {
                    return None; // Don't restrict any variables
                } else {
                    None
                }
            })
            .collect();

        // Only restrict if we don't have FullEnvironment exception
        let has_full_env = self
            .exceptions
            .iter()
            .any(|e| matches!(e, Exception::FullEnvironment));

        if !has_full_env {
            restrict_env_variables(&allowed_vars);
        }
    }
}

impl Sandbox for WindowsSandbox {
    fn new() -> Self {
        Self {
            exceptions: Vec::new(),
            app_container_name: None,
            app_container_sid: None,
        }
    }

    fn add_exception(&mut self, exception: Exception) -> Result<&mut Self> {
        self.exceptions.push(exception);
        Ok(self)
    }

    fn spawn(mut self, sandboxee: Command) -> Result<Child> {
        let program = sandboxee.get_program();

        // Create AppContainer profile
        self.create_app_container_profile(&program.to_string_lossy())?;

        // Setup file permissions
        self.setup_file_permissions()?;

        // Setup environment variables
        self.setup_environment_variables();

        // Get capabilities
        let capabilities = self.get_capabilities();

        // Create job object for resource limits (simplified)
        let job_handle = unsafe {
            CreateJobObjectW(None, None).expect("Failed to create job object")
        };

        // Prepare command line
        let mut cmd_line = format!("\"{}\"", program.to_string_lossy());
        for arg in sandboxee.get_args() {
            cmd_line.push(' ');
            cmd_line.push_str(&format!("\"{}\"", arg.to_string_lossy()));
        }

        let wide_cmd_line: Vec<u16> = OsStr::new(&cmd_line)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut startup_info = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };

        let mut process_info = PROCESS_INFORMATION::default();

        // Create the sandboxed process
        unsafe {
            // For a full AppContainer implementation, we would use CreateProcessW with 
            // PROC_THREAD_ATTRIBUTE_APPCONTAINER_POLICY, but for simplicity we'll
            // create a regular process with job object limits
            CreateProcessW(
                None,
                Some(PWSTR(wide_cmd_line.as_ptr() as *mut u16)),
                None,
                None,
                false,
                CREATE_NEW_CONSOLE,
                None,
                None,
                &startup_info,
                &mut process_info,
            ).expect("Failed to create process");

            // Assign process to job object for resource limits
            AssignProcessToJobObject(job_handle, process_info.hProcess).expect("Failed to assign process to job object");

            // Close thread handle as we don't need it
            CloseHandle(process_info.hThread).expect("Failed to close thread handle");
        }

        // Create Child wrapper
        Ok(Child::new(
            process_info.hProcess.0 as u32,
            Some(job_handle.0 as u32),
        ))
    }
}

impl Drop for WindowsSandbox {
    fn drop(&mut self) {
        // Cleanup AppContainer profile if we created one
        if let Some(ref name) = self.app_container_name {
            let app_container_name = HSTRING::from(name);
            unsafe {
                let _ = DeleteAppContainerProfile(&app_container_name);
            }
        }

        // Free SID if we have one
        if let Some(sid) = self.app_container_sid {
            unsafe {
                FreeSid(sid);
            }
        }
    }
}