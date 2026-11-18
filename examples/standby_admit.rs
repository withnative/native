//! Legacy CLI wrapper for the product replica operations.
// Match the library: the supported-feature replica future exceeds the default
// compiler layout query depth when awaited by this entrypoint.
#![recursion_limit = "256"]

#[tokio::main]
async fn main() -> std::process::ExitCode {
    native_ce::native_cli::consumer::enable_bounded_verification_diagnostics();
    native_ce::native_cli::replica::run_legacy(&std::env::args().skip(1).collect::<Vec<_>>()).await
}
