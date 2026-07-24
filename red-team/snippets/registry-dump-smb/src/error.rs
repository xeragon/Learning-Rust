#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    Success = 0,
    RegistryNotFound = 1,
    AccessDenied = 2,
    SmtAuthFailed = 3,
    SmtPathNotFound = 4,
    SmtWriteFailed = 5,
    OtherError = 6,
}

impl ErrorCode {
    pub fn as_exit_code(self) -> i32 {
        self as i32
    }
}

pub fn map_registry_error(win_error: u32) -> i32 {
    match win_error {
        2 => ErrorCode::RegistryNotFound as i32,     // ERROR_FILE_NOT_FOUND
        5 => ErrorCode::AccessDenied as i32,         // ERROR_ACCESS_DENIED
        _ => ErrorCode::OtherError as i32,
    }
}

pub fn map_smb_error(win_error: u32) -> i32 {
    match win_error {
        1326 => ErrorCode::SmtAuthFailed as i32,     // ERROR_LOGON_FAILURE
        53 | 67 => ErrorCode::SmtPathNotFound as i32, // ERROR_BAD_NETPATH, ERROR_BAD_NET_NAME
        112 => ErrorCode::SmtWriteFailed as i32,     // ERROR_DISK_FULL
        5 => ErrorCode::SmtWriteFailed as i32,       // ERROR_ACCESS_DENIED (SMB context)
        _ => ErrorCode::OtherError as i32,
    }
}
