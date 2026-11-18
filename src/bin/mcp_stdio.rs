//! Compatibility entry point for the legacy MCP stdio command line.

fn main() -> std::process::ExitCode {
    native_ce::native_cli::legacy_stdio::run()
}
