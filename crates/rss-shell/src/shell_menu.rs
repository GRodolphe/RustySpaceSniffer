//! Windows Explorer shell context menu (FR-6.1), invoked on a worker thread
//! with a watchdog so a hung third-party shell extension can never freeze the
//! UI (FR-6.2, SPEC.md §9.5).
//!
//! # Why this exists
//!
//! SpaceSniffer's right-click menu is the real Explorer `IContextMenu`; a
//! misbehaving shell extension can hang inside `QueryContextMenu` and freeze
//! the whole app. This module runs the entire COM sequence on a dedicated
//! worker thread and reports progress through a channel in two phases:
//!
//! 1. **Setup + population** — COM init, PIDL resolution, `GetUIObjectOf`,
//!    `QueryContextMenu`. This is where shell extensions run and where hangs
//!    happen, so the caller applies the watchdog here
//!    ([`ShellMenuInvocation::wait_ready`]).
//! 2. **Modal menu** — `TrackPopupMenu` blocks until the user picks or
//!    dismisses an item. That is user-paced, *not* a hang, so no timeout
//!    applies after `Ready` ([`ShellMenuInvocation::wait_finished`]).
//!
//! On watchdog timeout the worker thread is deliberately **abandoned**
//! (leaked): a thread stuck inside a third-party COM extension cannot be
//! killed safely. The UI reports the failure and stays responsive; each
//! timeout leaks one thread until process exit.
//!
//! # Integrator wiring (rss-app)
//!
//! Our own egui menu opens immediately on right-click; "Windows shell menu"
//! is an item in it. When clicked, call [`spawn_shell_context_menu`] with the
//! view's HWND and the cursor's screen position, then every frame:
//!
//! - `wait_ready(Duration::ZERO)` / `try_recv`-style polling (or block once
//!   with [`DEFAULT_WATCHDOG_TIMEOUT`] from a helper thread),
//! - on [`ShellMenuError::Timeout`], drop the invocation, show a warning in
//!   the log console, and forget it,
//! - after `Ready`, poll `wait_finished`-style for the verb result.
//!
//! # unsafe policy
//!
//! `windows-sys` deliberately ships no COM interfaces, so the `IShellFolder`
//! and `IContextMenu` vtables are declared manually in [`com`] from the public
//! SDK headers (`shobjidl_core.h`, immutable since Windows XP). **All** unsafe
//! code in this crate lives in this module; every block carries a SAFETY
//! comment. This module is compile-checked (`cargo check --target
//! x86_64-pc-windows-msvc`) but cannot be run on the Linux dev host — the
//! first Windows CI run must exercise it (SPEC.md §10.3).

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use windows_sys::Win32::Foundation::HWND;

/// How long the UI waits for the shell menu to be populated before declaring
/// the shell (or one of its extensions) hung (FR-6.2).
pub const DEFAULT_WATCHDOG_TIMEOUT: Duration = Duration::from_secs(5);

/// Failure modes of a shell-menu invocation.
#[derive(Debug, thiserror::Error)]
pub enum ShellMenuError {
    /// `path` must be absolute for `SHParseDisplayName`.
    #[error("shell context menu needs an absolute path, got {}", .0.display())]
    NotAbsolute(PathBuf),
    /// A COM / shell call failed. The value is the `HRESULT` as `u32`.
    #[error("{op} failed (HRESULT 0x{hresult:08X})")]
    Shell {
        /// Which call failed (e.g. `SHParseDisplayName`).
        op: &'static str,
        /// The failure `HRESULT`, bit-pattern as `u32`.
        hresult: u32,
    },
    /// `CreatePopupMenu` returned null.
    #[error("CreatePopupMenu failed")]
    PopupMenu,
    /// The watchdog expired while the menu was being set up or populated —
    /// the classic hung-shell-extension case (FR-6.2). The worker thread was
    /// abandoned (leaked); the UI must not wait for it.
    #[error("shell menu did not respond within the watchdog timeout")]
    Timeout,
    /// The worker thread died without reporting (panic or channel drop).
    #[error("shell menu worker terminated unexpectedly")]
    WorkerDisconnected,
}

/// Progress of one shell-menu invocation, delivered over the channel in
/// order: `Ready` once, then `Finished` once.
#[derive(Debug)]
pub enum ShellMenuEvent {
    /// The menu is populated and about to be shown; the watchdog window is
    /// over. After this, the modal menu waits for the *user*, so no timeout
    /// applies.
    Ready,
    /// The invocation ended: `Ok` (verb executed, or the user dismissed the
    /// menu — dismissal is not an error) or a [`ShellMenuError`].
    Finished(Result<(), ShellMenuError>),
}

/// Handle to a running worker-thread shell-menu invocation.
pub struct ShellMenuInvocation {
    rx: Receiver<ShellMenuEvent>,
}

impl ShellMenuInvocation {
    /// Wait up to `timeout` for [`ShellMenuEvent::Ready`] (the watchdog,
    /// FR-6.2). Any earlier failure surfaces here too.
    ///
    /// `Duration::ZERO` makes this a non-blocking poll, suitable for calling
    /// once per egui frame; track the deadline on the UI side in that case.
    pub fn wait_ready(&self, timeout: Duration) -> Result<(), ShellMenuError> {
        match self.rx.recv_timeout(timeout) {
            Ok(ShellMenuEvent::Ready) => Ok(()),
            Ok(ShellMenuEvent::Finished(Ok(()))) => {
                // Finished before Ready should not happen; treat as a dead worker.
                Err(ShellMenuError::WorkerDisconnected)
            }
            Ok(ShellMenuEvent::Finished(Err(e))) => Err(e),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(ShellMenuError::Timeout),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(ShellMenuError::WorkerDisconnected)
            }
        }
    }

    /// Wait (without timeout) for the final outcome. Only meaningful after
    /// `Ready`; blocks for as long as the user leaves the menu open.
    pub fn wait_finished(&self) -> Result<(), ShellMenuError> {
        match self.rx.recv() {
            Ok(ShellMenuEvent::Finished(result)) => result,
            // A duplicate Ready or a dropped channel both mean the worker
            // misbehaved.
            _ => Err(ShellMenuError::WorkerDisconnected),
        }
    }
}

/// Spawn the worker thread that shows the Windows Explorer context menu for
/// `path` at screen position `(x, y)`, owned by window `owner`.
///
/// The path is resolved up front; pass an absolute path (e.g. from
/// `rss_core::Tree::path` rooted at a drive). The returned
/// [`ShellMenuInvocation`] is the watchdog handle — see the module docs for
/// the two-phase protocol.
/// Send-able wrapper around `HWND` (a raw pointer in windows-sys).
///
/// SAFETY: an HWND is a process-wide opaque handle, not owned memory; using
/// it from another thread (to own the modal menu) is sound as long as the
/// window stays alive, which is the integrator's contract documented on
/// [`spawn_shell_context_menu`].
struct SendHwnd(HWND);
unsafe impl Send for SendHwnd {}

pub fn spawn_shell_context_menu(path: &Path, owner: HWND, x: i32, y: i32) -> ShellMenuInvocation {
    let (tx, rx) = std::sync::mpsc::channel();
    let path = path.to_path_buf();
    let owner = SendHwnd(owner);
    std::thread::spawn(move || {
        // Bind the whole wrapper: capturing `owner.0` directly would capture
        // only the raw-pointer field (not `Send`), failing `spawn`'s bound.
        let owner = owner;
        // A panic in our own glue must surface as a typed error, not a silent
        // channel drop (SPEC.md §5.9: no panics across FFI boundaries).
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            worker_main(&path, owner.0, x, y, &tx)
        }));
        if result.is_err() {
            let _ = tx.send(ShellMenuEvent::Finished(Err(
                ShellMenuError::WorkerDisconnected,
            )));
        }
    });
    ShellMenuInvocation { rx }
}

/// Worker-thread body: validate, then run the COM sequence.
fn worker_main(path: &Path, owner: HWND, x: i32, y: i32, tx: &Sender<ShellMenuEvent>) {
    let outcome = if path.is_absolute() {
        // SAFETY: `com::run_shell_menu` only touches `path` by reference,
        // `owner` must be a valid window handle (integrator contract: keep
        // the view window alive for the duration of the invocation).
        unsafe { com::run_shell_menu(path, owner, x, y, tx) }
    } else {
        Err(ShellMenuError::NotAbsolute(path.to_path_buf()))
    };
    // If the receiver is gone (watchdog timeout → UI abandoned us), there is
    // no one left to report to; dropping the result is correct.
    let _ = tx.send(ShellMenuEvent::Finished(outcome));
}

/// Raw COM interop — the only unsafe code in `rss-shell`.
///
/// `windows-sys` ships functions and structs but no COM interfaces, so the
/// two vtables we need are declared by hand from `shobjidl_core.h`. The
/// layouts and IIDs are part of the stable Windows ABI and match the public
/// SDK headers exactly; only the three vtable slots we actually call
/// (`Release`, `GetUIObjectOf`, `QueryContextMenu`, `InvokeCommand`) are ever
/// invoked, the rest exist only to keep the vtable layout correct.
mod com {
    use super::*;

    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::core::{GUID, HRESULT, PCSTR, PCWSTR};
    use windows_sys::Win32::Foundation::LPARAM;
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_APARTMENTTHREADED,
        COINIT_DISABLE_OLE1DDE,
    };
    use windows_sys::Win32::UI::Shell::Common::ITEMIDLIST;
    use windows_sys::Win32::UI::Shell::{
        SHBindToParent, SHParseDisplayName, CMF_EXPLORE, CMF_NORMAL, CMINVOKECOMMANDINFO,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreatePopupMenu, DestroyMenu, TrackPopupMenu, HMENU, SW_SHOWNORMAL, TPM_RETURNCMD,
    };

    /// `IID_IShellFolder` (`shobjidl_core.h`: 000214E6-0000-0000-C000-000000000046).
    const IID_ISHELLFOLDER: GUID = GUID::from_u128(0x000214E6_0000_0000_C000_000000000046);
    /// `IID_IContextMenu` (`shobjidl_core.h`: 000214E4-0000-0000-C000-000000000046).
    const IID_ICONTEXTMENU: GUID = GUID::from_u128(0x000214E4_0000_0000_C000_000000000046);

    /// Command ids handed to `QueryContextMenu` start here; the verb passed to
    /// `InvokeCommand` is the chosen id minus this offset.
    const ID_CMD_FIRST: u32 = 1;

    // ----- hand-declared COM interfaces (see module docs) -----

    #[repr(C)]
    struct IShellFolder {
        vtable: *const IShellFolderVtbl,
    }

    #[repr(C)]
    struct IShellFolderVtbl {
        // IUnknown
        query_interface:
            unsafe extern "system" fn(*mut IShellFolder, *const GUID, *mut *mut c_void) -> HRESULT,
        add_ref: unsafe extern "system" fn(*mut IShellFolder) -> u32,
        release: unsafe extern "system" fn(*mut IShellFolder) -> u32,
        // IShellFolder
        parse_display_name: unsafe extern "system" fn(
            *mut IShellFolder,
            HWND,
            *mut c_void,
            PCWSTR,
            *mut u32,
            *mut *mut ITEMIDLIST,
            *mut u32,
        ) -> HRESULT,
        enum_objects:
            unsafe extern "system" fn(*mut IShellFolder, HWND, u32, *mut *mut c_void) -> HRESULT,
        bind_to_object: unsafe extern "system" fn(
            *mut IShellFolder,
            *const ITEMIDLIST,
            *mut c_void,
            *const GUID,
            *mut *mut c_void,
        ) -> HRESULT,
        bind_to_storage: unsafe extern "system" fn(
            *mut IShellFolder,
            *const ITEMIDLIST,
            *mut c_void,
            *const GUID,
            *mut *mut c_void,
        ) -> HRESULT,
        compare_ids: unsafe extern "system" fn(
            *mut IShellFolder,
            LPARAM,
            *const ITEMIDLIST,
            *const ITEMIDLIST,
        ) -> HRESULT,
        create_view_object: unsafe extern "system" fn(
            *mut IShellFolder,
            HWND,
            *const GUID,
            *mut *mut c_void,
        ) -> HRESULT,
        get_attributes_of: unsafe extern "system" fn(
            *mut IShellFolder,
            u32,
            *const *const ITEMIDLIST,
            *mut u32,
        ) -> HRESULT,
        get_ui_object_of: unsafe extern "system" fn(
            *mut IShellFolder,
            HWND,
            u32,
            *const *const ITEMIDLIST,
            *const GUID,
            *mut u32,
            *mut *mut c_void,
        ) -> HRESULT,
        get_display_name_of: unsafe extern "system" fn(
            *mut IShellFolder,
            *const ITEMIDLIST,
            u32,
            *mut c_void,
        ) -> HRESULT,
        set_name_of: unsafe extern "system" fn(
            *mut IShellFolder,
            HWND,
            *const ITEMIDLIST,
            PCWSTR,
            u32,
            *mut *mut ITEMIDLIST,
        ) -> HRESULT,
    }

    #[repr(C)]
    struct IContextMenu {
        vtable: *const IContextMenuVtbl,
    }

    #[repr(C)]
    struct IContextMenuVtbl {
        // IUnknown
        query_interface:
            unsafe extern "system" fn(*mut IContextMenu, *const GUID, *mut *mut c_void) -> HRESULT,
        add_ref: unsafe extern "system" fn(*mut IContextMenu) -> u32,
        release: unsafe extern "system" fn(*mut IContextMenu) -> u32,
        // IContextMenu
        query_context_menu:
            unsafe extern "system" fn(*mut IContextMenu, HMENU, u32, u32, u32, u32) -> HRESULT,
        invoke_command:
            unsafe extern "system" fn(*mut IContextMenu, *const CMINVOKECOMMANDINFO) -> HRESULT,
        get_command_string: unsafe extern "system" fn(
            *mut IContextMenu,
            usize,
            u32,
            *mut u32,
            *mut u8,
            u32,
        ) -> HRESULT,
    }

    // ----- RAII guards so every error path releases what it acquired -----

    /// Balances a successful `CoInitializeEx` with `CoUninitialize`.
    struct ComApartment;
    impl Drop for ComApartment {
        fn drop(&mut self) {
            // SAFETY: paired with a successful CoInitializeEx on this thread.
            unsafe { CoUninitialize() }
        }
    }

    /// Frees a PIDL allocated by the shell (`SHParseDisplayName`).
    struct ShellPidl(*mut ITEMIDLIST);
    impl Drop for ShellPidl {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: PIDLs from SHParseDisplayName are allocated from the
                // shell task allocator and must be freed with CoTaskMemFree.
                unsafe { CoTaskMemFree(self.0.cast()) }
            }
        }
    }

    /// Destroys a Win32 menu on drop.
    struct PopupMenuHandle(HMENU);
    impl Drop for PopupMenuHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is a live HMENU created by CreatePopupMenu.
                unsafe { DestroyMenu(self.0) };
            }
        }
    }

    /// Releases a COM object on drop. `T` is one of the hand-declared
    /// interfaces above; only their `Release` vtable slot is used.
    struct ComObject<T> {
        ptr: *mut T,
        release: unsafe extern "system" fn(*mut T) -> u32,
    }
    impl<T> Drop for ComObject<T> {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                // SAFETY: `ptr` is a live COM object acquired during this call;
                // `release` is its own vtable's Release slot.
                unsafe { (self.release)(self.ptr) };
            }
        }
    }

    fn wide(path: &OsStr) -> Vec<u16> {
        path.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn failed(op: &'static str, hr: HRESULT) -> ShellMenuError {
        ShellMenuError::Shell {
            op,
            hresult: hr as u32,
        }
    }

    /// The full `IContextMenu` sequence for one path. Runs entirely on the
    /// worker thread spawned by `spawn_shell_context_menu`.
    ///
    /// SAFETY (for the whole function): `owner` must be a valid HWND for the
    /// duration of the call (integrator contract); all pointers are validated
    /// for null before use; every acquired resource is held in an RAII guard.
    /// `TrackPopupMenu` runs its own modal message loop, so no extra pump is
    /// needed on this thread.
    pub(super) unsafe fn run_shell_menu(
        path: &Path,
        owner: HWND,
        x: i32,
        y: i32,
        tx: &Sender<ShellMenuEvent>,
    ) -> Result<(), ShellMenuError> {
        // COINIT_APARTMENTTHREADED: shell extensions expect an STA.
        // SAFETY: plain COM initialization on the current thread.
        let hr = unsafe {
            CoInitializeEx(
                null_mut(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            )
        };
        if hr < 0 {
            return Err(failed("CoInitializeEx", hr));
        }
        let _com = ComApartment;

        let wide_path = wide(path.as_os_str());
        let mut pidl: *mut ITEMIDLIST = null_mut();
        // SAFETY: `wide_path` is a valid NUL-terminated UTF-16 string; `pidl`
        // is a valid out-pointer. On success `pidl` is owned by us (RAII).
        let hr =
            unsafe { SHParseDisplayName(wide_path.as_ptr(), null_mut(), &mut pidl, 0, null_mut()) };
        if hr < 0 {
            return Err(failed("SHParseDisplayName", hr));
        }
        let pidl = ShellPidl(pidl);

        let mut folder_raw: *mut c_void = null_mut();
        let mut child: *mut ITEMIDLIST = null_mut();
        // SAFETY: `pidl.0` is a live absolute PIDL; out-pointers are valid.
        // On success `folder_raw` is an IShellFolder we own, `child` is a
        // PIDL-relative borrowed from `pidl` (not freed separately).
        let hr = unsafe { SHBindToParent(pidl.0, &IID_ISHELLFOLDER, &mut folder_raw, &mut child) };
        if hr < 0 {
            return Err(failed("SHBindToParent", hr));
        }
        if folder_raw.is_null() || child.is_null() {
            return Err(ShellMenuError::Shell {
                op: "SHBindToParent",
                hresult: 0, // S_OK with null outputs: defensive, should not happen.
            });
        }
        let folder = folder_raw.cast::<IShellFolder>();
        // SAFETY: `folder` is a live IShellFolder; reading its vtable's
        // Release slot is valid.
        let folder = unsafe {
            ComObject {
                ptr: folder,
                release: (*(*folder).vtable).release,
            }
        };

        let mut menu_raw: *mut c_void = null_mut();
        let child_array: [*const ITEMIDLIST; 1] = [child];
        // SAFETY: all pointers valid; `child_array` borrows the child PIDL
        // which outlives the call. On success `menu_raw` is an IContextMenu.
        let hr = unsafe {
            ((*(*folder.ptr).vtable).get_ui_object_of)(
                folder.ptr,
                owner,
                1,
                child_array.as_ptr(),
                &IID_ICONTEXTMENU,
                null_mut(),
                &mut menu_raw,
            )
        };
        if hr < 0 {
            return Err(failed("IShellFolder::GetUIObjectOf(IContextMenu)", hr));
        }
        if menu_raw.is_null() {
            return Err(ShellMenuError::Shell {
                op: "IShellFolder::GetUIObjectOf(IContextMenu)",
                hresult: 0,
            });
        }
        let menu = menu_raw.cast::<IContextMenu>();
        // SAFETY: as above for the Release slot.
        let menu = unsafe {
            ComObject {
                ptr: menu,
                release: (*(*menu).vtable).release,
            }
        };

        // SAFETY: plain Win32 call; null checked below.
        let hmenu = unsafe { CreatePopupMenu() };
        if hmenu.is_null() {
            return Err(ShellMenuError::PopupMenu);
        }
        let hmenu = PopupMenuHandle(hmenu);

        // This is the call third-party shell extensions hang in (FR-6.2): it
        // runs on this worker thread, before `Ready` is signalled, so the UI's
        // watchdog covers it.
        // SAFETY: `menu` and `hmenu` are live; numeric id range per contract.
        let hr = unsafe {
            ((*(*menu.ptr).vtable).query_context_menu)(
                menu.ptr,
                hmenu.0,
                0,
                ID_CMD_FIRST,
                0x7FFF,
                CMF_NORMAL | CMF_EXPLORE,
            )
        };
        if hr < 0 {
            return Err(failed("IContextMenu::QueryContextMenu", hr));
        }

        // Watchdog window ends here. If the UI already gave up (receiver
        // dropped), do not flash a menu nobody is watching — bail quietly.
        if tx.send(ShellMenuEvent::Ready).is_err() {
            return Ok(());
        }

        // Modal, user-paced: blocks until a verb is picked or the menu is
        // dismissed. TPM_RETURNCMD makes it return the command id instead of
        // invoking it. SAFETY: valid HMENU and HWND.
        let cmd = unsafe { TrackPopupMenu(hmenu.0, TPM_RETURNCMD, x, y, 0, owner, null()) };
        if cmd == 0 {
            // Dismissed without a choice — not an error.
            return Ok(());
        }

        // MAKEINTRESOURCEA(cmd - ID_CMD_FIRST): low-word ordinal as a pointer.
        let info = CMINVOKECOMMANDINFO {
            cbSize: size_of::<CMINVOKECOMMANDINFO>() as u32,
            hwnd: owner,
            lpVerb: ((cmd as u32 - ID_CMD_FIRST) & 0xFFFF) as usize as PCSTR,
            nShow: SW_SHOWNORMAL,
            ..Default::default()
        };
        // SAFETY: `info` is fully initialized; `menu` is live.
        let hr = unsafe { ((*(*menu.ptr).vtable).invoke_command)(menu.ptr, &info) };
        if hr < 0 {
            return Err(failed("IContextMenu::InvokeCommand", hr));
        }
        Ok(())
    }
}
