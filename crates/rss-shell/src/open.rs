//! "Open containing folder in Explorer" (FR-6.3).
//!
//! Windows: `explorer.exe /select,<path>` opens the parent folder with the
//! item selected. Other hosts (development convenience only — SPEC.md §N2
//! makes non-Windows a stretch goal): `xdg-open` on the containing folder.

use std::path::Path;
use std::process::Command;

/// Failure to launch the file-manager process.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The file-manager process could not be spawned.
    #[error("could not launch {program}: {source}")]
    Spawn {
        /// The program that failed to start (`explorer.exe`, `xdg-open`).
        program: &'static str,
        /// The underlying OS error.
        source: std::io::Error,
    },
}

/// The folder that should be opened to "contain" `path`: its parent, or the
/// path itself when there is no parent (filesystem root).
///
/// Only the non-Windows branch uses this (Windows selects the item inside its
/// parent via `explorer.exe /select,`), hence the cfg.
#[cfg(not(windows))]
fn containing_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(path)
}

/// Spawn `command` detached: the child is reaped on a helper thread so a
/// long-running GUI app never accumulates zombie processes, and the file
/// manager's exit status is deliberately ignored (see below).
fn spawn_detached(mut command: Command, program: &'static str) -> Result<(), OpenError> {
    let mut child = command
        .spawn()
        .map_err(|source| OpenError::Spawn { program, source })?;
    std::thread::spawn(move || {
        // Ignore the exit status: explorer.exe is notorious for returning 1
        // even when /select succeeded, and a closed xdg-open is not an error
        // we can act on either.
        let _ = child.wait();
    });
    Ok(())
}

/// Open the containing folder of `path` in the system file manager, selecting
/// `path` where the file manager supports it (FR-6.3).
///
/// On Windows this is `explorer.exe /select,<path>`. `path` should be
/// absolute; `explorer.exe /select` does not resolve relative paths reliably.
///
/// This call is cheap and non-blocking: it only spawns the file-manager
/// process and returns immediately.
pub fn open_containing_folder(path: &Path) -> Result<(), OpenError> {
    spawn_detached(reveal_command(path), reveal_program())
}

/// The program used by [`open_containing_folder`] on this platform.
fn reveal_program() -> &'static str {
    if cfg!(windows) {
        "explorer.exe"
    } else {
        "xdg-open"
    }
}

/// Build the file-manager command for `path`. Factored out so the Windows
/// `/select,` argument construction can be unit-tested by the Windows CI job.
fn reveal_command(path: &Path) -> Command {
    #[cfg(windows)]
    {
        // explorer.exe wants the /select, switch with a literal comma and an
        // unquoted path argument (Command passes it as one argv entry).
        let mut cmd = Command::new("explorer.exe");
        cmd.arg(format!("/select,{}", path.display()));
        cmd
    }
    #[cfg(not(windows))]
    {
        let mut cmd = Command::new("xdg-open");
        cmd.arg(containing_dir(path));
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn containing_dir_is_parent() {
        assert_eq!(
            containing_dir(Path::new("/home/user/file.txt")),
            Path::new("/home/user")
        );
        assert_eq!(
            containing_dir(Path::new("/home/user/dir")),
            Path::new("/home/user")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn containing_dir_of_root_is_root() {
        assert_eq!(containing_dir(Path::new("/")), Path::new("/"));
    }

    #[cfg(not(windows))]
    #[test]
    fn containing_dir_of_bare_name_is_the_name() {
        // A relative single-component path has an empty parent; open it as-is
        // rather than passing "" to the file manager.
        assert_eq!(containing_dir(Path::new("file.txt")), Path::new("file.txt"));
    }

    /// Verifies the `explorer.exe /select,<path>` construction (FR-6.3).
    /// Compiles everywhere but only exercises the Windows branch in CI.
    #[cfg(windows)]
    #[test]
    fn reveal_command_uses_explorer_select() {
        let cmd = reveal_command(Path::new("C:\\data\\file.txt"));
        assert_eq!(cmd.get_program(), "explorer.exe");
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, [std::ffi::OsStr::new("/select,C:\\data\\file.txt")]);
    }

    /// Actually spawns the platform file manager — opens a real window, so it
    /// only runs on explicit request:
    /// `RSS_SHELL_TEST_OPEN=1 cargo test -p rss-shell open_really_ -- --ignored`
    #[test]
    #[ignore = "opens a real file-manager window"]
    fn open_really_launches_file_manager() {
        if std::env::var_os("RSS_SHELL_TEST_OPEN").is_none() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"x").unwrap();
        let path: std::path::PathBuf = dir.path().join("file.txt");
        open_containing_folder(&path).unwrap();
        // Give the spawned process a moment to start before the tempdir drops.
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
