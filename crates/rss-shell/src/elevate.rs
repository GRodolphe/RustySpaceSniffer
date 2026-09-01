//! Self-elevation via `ShellExecuteW("runas")` (SPEC.md §3, FR-2.5): relaunch
//! the current executable as administrator, e.g. to unlock the MFT fast path.
//!
//! Compile-check-only on this host — it is exercised by the Windows CI.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

/// Failure to relaunch the current process elevated.
#[derive(Debug, thiserror::Error)]
pub enum ElevateError {
    /// The path of the running executable could not be determined.
    #[error("could not locate the current executable: {0}")]
    CurrentExe(std::io::Error),
    /// The executable path is not valid Unicode (cannot be passed to
    /// `ShellExecuteW`).
    #[error("current executable path is not valid Unicode: {}", .0.display())]
    NonUnicodeExe(PathBuf),
    /// The user declined the UAC prompt (`SE_ERR_ACCESSDENIED`). Not a real
    /// failure — the UI should simply continue unelevated.
    #[error("elevation declined by the user")]
    Declined,
    /// `ShellExecuteW` failed; the value is its return code (`<= 32`).
    #[error("ShellExecuteW(\"runas\") failed (code {0})")]
    Launch(isize),
}

/// Relaunch the current executable as administrator with `args` as its
/// command line (FR-2.5: "rescan as administrator").
///
/// On success a *new* elevated process has been started and this one should
/// exit (or hand off) — elevation never applies to the running process.
/// Typical args for a rescan: `["scan", "C:\\", "--elevated"]`.
pub fn relaunch_as_admin(args: &[&OsStr]) -> Result<(), ElevateError> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    let exe = std::env::current_exe().map_err(ElevateError::CurrentExe)?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| ElevateError::NonUnicodeExe(exe.clone()))?;
    let verb = wide(OsStr::new("runas"));
    let file = wide(OsStr::new(exe_str));
    let params = wide(&join_args(args));

    // SAFETY: all string pointers are valid NUL-terminated UTF-16 buffers
    // that outlive the call; null hwnd/directory are documented as allowed.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // Per MSDN: a return value greater than 32 is success; anything else is
    // an error code (2 = file not found, 5 = access denied / UAC declined).
    const SE_ERR_ACCESSDENIED: isize = 5;
    match result as isize {
        r if r > 32 => Ok(()),
        SE_ERR_ACCESSDENIED => Err(ElevateError::Declined),
        code => Err(ElevateError::Launch(code)),
    }
}

/// Join arguments into a Windows command line, quoting per
/// `CommandLineToArgvW` rules so paths with spaces survive the relaunch.
fn join_args(args: &[&OsStr]) -> OsString {
    let mut out = OsString::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            out.push(" ");
        }
        out.push(quote_arg(arg));
    }
    out
}

/// Quote one argument if it contains whitespace or quotes (minimal
/// `CommandLineToArgvW`-compatible quoting; backslashes before a closing
/// quote are doubled).
fn quote_arg(arg: &OsStr) -> OsString {
    let s = arg.to_string_lossy();
    if !s.is_empty() && !s.contains([' ', '\t', '"']) {
        return OsString::from(s.into_owned());
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for ch in s.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(ch);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    OsString::from(out)
}
