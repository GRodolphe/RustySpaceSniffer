//! Shell integration for RustySpaceSniffer (SPEC.md §5.1, §4.6 FR-6.x).
//!
//! This crate owns every interaction with the operating system's shell:
//!
//! - **Recycle-bin delete** ([`delete_to_recycle_bin`], [`execute_plan`],
//!   [`DeletePlan`], FR-6.4) — cross-platform via the `trash` crate, with
//!   per-item error collection. [`DeletePlan`] is the data source for the
//!   FR-6.4 confirmation dialog (item list, true total bytes, filter-hiding
//!   warning); the dialog itself lives in `rss-app`.
//! - **Open containing folder** ([`open_containing_folder`], FR-6.3) —
//!   `explorer.exe /select,` on Windows, `xdg-open` elsewhere.
//! - **Windows shell context menu** (cfg(windows), `spawn_shell_context_menu`,
//!   FR-6.1/FR-6.2) — the real Explorer `IContextMenu`, invoked on a worker
//!   thread with a watchdog timeout so a hung shell extension cannot freeze
//!   the UI (SPEC.md §9.5).
//! - **Self-elevation** (cfg(windows), `relaunch_as_admin`, FR-2.5) —
//!   `ShellExecuteW("runas")` relaunch.
//! - **Explorer integration** (cfg(windows), `register_explorer_context_menu` /
//!   `unregister_explorer_context_menu`, SPEC.md §3) — the per-user `HKCU`
//!   "Scan with RustySpaceSniffer" context-menu entry.
//!
//! Per SPEC.md §5.1 this is the only crate (with `rss-scan`/`rss-watch`) that
//! touches platform shell APIs; all `unsafe` is confined to the cfg(windows)
//! `shell_menu` COM glue and the other cfg(windows) modules. Non-Windows hosts
//! get the trash and open-folder functionality (used for development and
//! tests); the Windows-only modules are compile-checked against
//! `x86_64-pc-windows-msvc` and exercised by the Windows CI.
//!
//! # Integrator guide (rss-app, M8 integration)
//!
//! - Right-click on a treemap item opens our **own** egui menu immediately.
//!   "Windows shell menu" is an item in it that calls
//!   `spawn_shell_context_menu` and drives the returned invocation per the
//!   `shell_menu` module's two-phase protocol (watchdog on `wait_ready`, no
//!   timeout after `Ready`).
//! - "Delete to Recycle Bin" builds a [`DeletePlan`] (via
//!   [`DeletePlan::from_tree`] for tree selections — the filter-hiding flag
//!   per node comes from the caller's `rss-filter` evaluation), renders the
//!   confirmation dialog from it, then runs [`execute_plan`] on a worker
//!   thread; the progress callback feeds the running freed-space counter
//!   (FR-6.4c).

mod delete;
mod open;

#[cfg(windows)]
mod elevate;
#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod shell_menu;

pub use delete::{
    delete_to_recycle_bin, execute_plan, DeleteError, DeleteFailure, DeleteItem, DeletePlan,
};
pub use open::{open_containing_folder, OpenError};

#[cfg(windows)]
pub use elevate::{relaunch_as_admin, ElevateError};
#[cfg(windows)]
pub use registry::{
    explorer_context_menu_registered, register_explorer_context_menu,
    unregister_explorer_context_menu, RegistryError, MENU_LABEL,
};
#[cfg(windows)]
pub use shell_menu::{
    spawn_shell_context_menu, ShellMenuError, ShellMenuEvent, ShellMenuInvocation,
    DEFAULT_WATCHDOG_TIMEOUT,
};
