use crate::error::map_registry_error;
use windows_sys::Win32::System::Registry::*;

const KEY_READ: u32 = 0x20019; // STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS

#[derive(Debug, Clone)]
pub struct RegistryValue {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RegistryKey {
    pub name: String,
    pub values: Vec<RegistryValue>,
    pub subkeys: Vec<RegistryKey>,
}

#[derive(Debug)]
pub struct RegistryHive {
    pub root: RegistryKey,
}

impl RegistryHive {
    pub fn read(hive_name: &str) -> Result<Self, i32> {
        let hkey = open_registry_key(hive_name)?;

        let root = unsafe {
            let result = enumerate_keys(hkey, hive_name);
            RegCloseKey(hkey);
            result
        }?;

        Ok(RegistryHive { root })
    }
}

fn open_registry_key(hive_name: &str) -> Result<HKEY, i32> {
    unsafe {
        let mut hkey: HKEY = 0;
        let hive_wide = format!("HKLM\\{}\0", hive_name)
            .encode_utf16()
            .collect::<Vec<u16>>();

        let result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            hive_wide.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );

        if result != 0 {
            return Err(map_registry_error(result));
        }

        Ok(hkey)
    }
}

fn enumerate_keys(hkey: HKEY, key_name: &str) -> Result<RegistryKey, i32> {
    let mut key = RegistryKey {
        name: key_name.to_string(),
        values: Vec::new(),
        subkeys: Vec::new(),
    };

    unsafe {
        // Enumerate values
        let mut index = 0u32;
        loop {
            let mut value_name: [u16; 256] = [0; 256];
            let mut value_name_len = 256u32;
            let mut value_type = 0u32;
            let mut value_data: [u8; 4096] = [0; 4096];
            let mut value_data_len = 4096u32;

            let result = RegEnumValueW(
                hkey,
                index,
                value_name.as_mut_ptr(),
                &mut value_name_len,
                std::ptr::null_mut(),
                &mut value_type,
                value_data.as_mut_ptr(),
                &mut value_data_len,
            );

            if result == 259 {
                break; // ERROR_NO_MORE_ITEMS
            }
            if result != 0 {
                break;
            }

            let name = String::from_utf16_lossy(&value_name[..value_name_len as usize])
                .to_string();
            let data = value_data[..value_data_len as usize].to_vec();

            key.values.push(RegistryValue {
                name,
                value_type,
                data,
            });

            index += 1;
        }

        // Enumerate subkeys
        index = 0;
        loop {
            let mut subkey_name: [u16; 256] = [0; 256];
            let mut subkey_name_len = 256u32;

            let result = RegEnumKeyExW(
                hkey,
                index,
                subkey_name.as_mut_ptr(),
                &mut subkey_name_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );

            if result == 259 {
                break; // ERROR_NO_MORE_ITEMS
            }
            if result != 0 {
                break;
            }

            let subkey_name_str = String::from_utf16_lossy(&subkey_name[..subkey_name_len as usize])
                .to_string();

            // Recursively enumerate subkey
            let mut subkey_hkey: HKEY = 0;
            if RegOpenKeyExW(
                hkey,
                subkey_name.as_ptr(),
                0,
                KEY_READ,
                &mut subkey_hkey,
            ) == 0 {
                if let Ok(subkey) = enumerate_keys(subkey_hkey, &subkey_name_str) {
                    key.subkeys.push(subkey);
                }
                RegCloseKey(subkey_hkey);
            }

            index += 1;
        }
    }

    Ok(key)
}
