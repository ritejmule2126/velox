//! The `velox` binary.

#![forbid(unsafe_code)]

use clap::Parser;
use std::process::ExitCode;

/// The global allocator. mimalloc keeps per-thread free lists, so the many
/// short-lived allocations of a busy proxy (header maps, buffers, compression
/// state) neither contend on a global lock nor fragment as badly as with a
/// general-purpose allocator. Only this binary registers it: every library crate
/// stays free of `unsafe` and of allocator choices. Build with
/// `--no-default-features` to use the system allocator.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = velox_cli::cli::Cli::parse();
    match velox_cli::cli::run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
