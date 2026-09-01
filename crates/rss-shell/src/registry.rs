//! Explorer "Scan with RustySpaceSniffer" context-menu registration
//! (SPEC.md §3: optional, user-invoked, per-user `HKCU` — no admin needed).
//!
//! Registers under `HKCU\Software\Classes\Directory\shell` and
//! `HKCU\Software\Classes\Drive\shell` so both folders and drives offer the
//! verb; the command is `"<exe>" scan "%1"`, the documented SpaceSniffer
//! `.reg` recipe. The app otherwise never writes the registry (SPEC.md §3).
//!
//! Compile-check-only on this host — it is exercised by the Windows CI.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
};

/// Label shown in the Explorer context menu (SPEC.md §3).
pub const MENU_LABEL: &str = "Scan with RustySpaceSniffer";

/// Registry key suffix under `HKCU\Software\Classes` for folder background
/// items (`Directory`) and drives (`Drive`). `%1` semantics match for both.
const CLASS_KEYS: [&str; 2] = [
    "Software\\Classes\\Directory\\shell\\RustySpaceSniffer",
    "Software\\Classes\\Drive\\shell\\RustySpaceSniffer",
];

const ERROR_FILE_NOT_FOUND: u32 = 2;

/// Failure of a registry operation.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A Win32 registry call failed.
    #[error("registry {op} failed (Win32 error {code})")]
    Win32 {
        /// Which operation failed (e.g. `RegCreateKeyExW`).
        op: &'static str,
        /// The `WIN32_ERROR` code.
        code: u32,
    },
    /// The executable path is not valid Unicode.
    #[error("executable path is not valid Unicode: {}", .0.display())]
    NonUnicodeExe(std::path::PathBuf),
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// RAII guard closing an `HKEY` on drop.
struct KeyHandle(HKEY);
impl Drop for KeyHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live key handle returned by RegCreateKeyExW /
        // RegOpenKeyExW and closed exactly once here.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Create (or open) `subkey` under `HKCU` with write access.
fn create_key(subkey: &str) -> Result<KeyHandle, RegistryError> {
    let subkey = wide(OsStr::new(subkey));
    let mut hkey: HKEY = std::ptr::null_mut();
    // SAFETY: all pointers valid; `hkey` is a valid out-pointer; null class /
    // security attributes / disposition are documented as allowed.
    let code = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            std::ptr::null(),
            &mut hkey,
            std::ptr::null_mut(),
        )
    };
    if code != ERROR_SUCCESS {
        return Err(RegistryError::Win32 {
            op: "RegCreateKeyExW",
            code,
        });
    }
    Ok(KeyHandle(hkey))
}

/// Set a `REG_SZ` value (`name == None` → the key's default value).
fn set_string_value(key: &KeyHandle, name: Option<&str>, value: &str) -> Result<(), RegistryError> {
    let name = name.map(|n| wide(OsStr::new(n)));
    let name_ptr = name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr());
    let data = wide(OsStr::new(value));
    // SAFETY: `data` is read for `cbdata` bytes only; the count includes the
    // terminating NUL, as REG_SZ requires.
    let code = unsafe {
        RegSetValueExW(
            key.0,
            name_ptr,
            0,
            REG_SZ,
            data.as_ptr().cast::<u8>(),
            (data.len() * 2) as u32,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(RegistryError::Win32 {
            op: "RegSetValueExW",
            code,
        });
    }
    Ok(())
}

/// Register the per-user "Scan with RustySpaceSniffer" Explorer context-menu
/// entry pointing at `exe` (SPEC.md §3). Idempotent.
pub fn register_explorer_context_menu(exe: &Path) -> Result<(), RegistryError> {
    let exe_str = exe
        .to_str()
        .ok_or_else(|| RegistryError::NonUnicodeExe(exe.to_path_buf()))?;
    let command = format!("\"{exe_str}\" scan \"%1\"");
    for class_key in CLASS_KEYS {
        let shell_key = create_key(class_key)?;
        set_string_value(&shell_key, None, MENU_LABEL)?;
        set_string_value(&shell_key, Some("Icon"), exe_str)?;
        let command_key = create_key(&format!("{class_key}\\command"))?;
        set_string_value(&command_key, None, &command)?;
    }
    Ok(())
}

/// Remove the context-menu entry. Succeeds even when nothing is registered.
pub fn unregister_explorer_context_menu() -> Result<(), RegistryError> {
    for class_key in CLASS_KEYS {
        let subkey = wide(OsStr::new(class_key));
        // SAFETY: `subkey` is a valid NUL-terminated UTF-16 string.
        let code = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, subkey.as_ptr()) };
        if code != ERROR_SUCCESS && code != ERROR_FILE_NOT_FOUND {
            return Err(RegistryError::Win32 {
                op: "RegDeleteTreeW",
                code,
            });
        }
    }
    Ok(())
}

/// Whether the context-menu entry is currently registered (drives the
/// settings toggle, SPEC.md §3).
pub fn explorer_context_menu_registered() -> bool {
    let subkey = wide(OsStr::new(CLASS_KEYS[0]));
    let mut hkey: HKEY = std::ptr::null_mut();
    // SAFETY: all pointers valid; `hkey` is a valid out-pointer.
    let code = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey) };
    if code != ERROR_SUCCESS {
        return false;
    }
    // Close the probe handle.
    let _ = KeyHandle(hkey);
    true
}
