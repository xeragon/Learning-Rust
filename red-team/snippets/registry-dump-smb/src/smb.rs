use crate::error::map_smb_error;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{GetLastError, CloseHandle};
use windows_sys::Win32::Storage::FileSystem::CREATE_ALWAYS;

pub struct SmtWriter {
    path: String,
}

impl SmtWriter {
    pub fn connect(path: &str, username: Option<&str>, password: Option<&str>) -> Result<Self, i32> {
        unsafe {
            let path_wide: Vec<u16> = OsStr::new(path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            if let Some(user) = username {
                let user_wide: Vec<u16> = OsStr::new(user)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();
                let pass_wide: Vec<u16> = OsStr::new(password.unwrap_or(""))
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                let result = WNetAddConnectionW(
                    path_wide.as_ptr(),
                    pass_wide.as_ptr(),
                    user_wide.as_ptr(),
                );

                if result != 0 {
                    return Err(map_smb_error(result));
                }
            }
        }

        Ok(SmtWriter {
            path: path.to_string(),
        })
    }

    pub fn write_file(&self, filename: &str, data: &[u8]) -> Result<(), i32> {
        let full_path = format!("{}\\{}", self.path, filename);

        unsafe {
            let path_wide: Vec<u16> = OsStr::new(&full_path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let handle = CreateFileW(
                path_wide.as_ptr(),
                GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                0,
            );

            if handle == -1 {
                let err = GetLastError();
                return Err(map_smb_error(err));
            }

            let mut bytes_written = 0u32;
            let write_result = WriteFile(
                handle,
                data.as_ptr() as *const std::ffi::c_void,
                data.len() as u32,
                &mut bytes_written,
                std::ptr::null_mut(),
            );

            CloseHandle(handle);

            if write_result == 0 || bytes_written as usize != data.len() {
                return Err(map_smb_error(GetLastError()));
            }
        }

        Ok(())
    }
}

const GENERIC_WRITE: u32 = 0x40000000;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

unsafe extern "system" {
    fn WNetAddConnectionW(
        lpRemoteName: *const u16,
        lpPassword: *const u16,
        lpUserName: *const u16,
    ) -> u32;

    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *mut std::ffi::c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: isize,
    ) -> isize;

    fn WriteFile(
        hFile: isize,
        lpBuffer: *const std::ffi::c_void,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped: *mut std::ffi::c_void,
    ) -> u32;
}
