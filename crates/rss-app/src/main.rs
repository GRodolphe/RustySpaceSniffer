//! Thin `rss` binary entry point (SPEC.md §5.1): CLI parsing and dispatch
//! live in `rss-app`. No arguments opens the GUI; subcommands run headless.

fn main() -> std::process::ExitCode {
    rss_app::cli::main_entry()
}
