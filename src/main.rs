// The CLI reports errors on stderr.
#![allow(clippy::print_stderr)]

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

mod actions;
mod cli;

/// Prints warnings from the ejson library to stderr as `ejsonkms: warning: ...`.
///
/// ejson reports non-fatal problems (for example YAML numbers it left
/// unencrypted, or control characters dropped from an exported value) through
/// the `log` crate instead of writing to stderr itself.
struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            let level = match record.level() {
                log::Level::Error => "error",
                _ => "warning",
            };
            eprintln!("ejsonkms: {level}: {}", record.args());
        }
    }

    fn flush(&self) {}
}

fn main() -> ExitCode {
    // Cannot fail: no other logger has been installed yet.
    if log::set_logger(&StderrLogger).is_ok() {
        log::set_max_level(log::LevelFilter::Warn);
    }

    let cli = Cli::parse();

    // Every command handles secrets: private keys (keygen, decrypt, env) or
    // plaintext about to be encrypted (encrypt).
    disable_core_dumps();

    // What to print before the error if the command fails.
    let (failure, result) = match &cli.command {
        Command::Encrypt(args) => ("Encryption failed", actions::encrypt(args)),
        Command::Decrypt(args) => ("Decryption failed", block_on(actions::decrypt(args))),
        Command::Keygen(args) => ("Key generation failed", block_on(actions::keygen(args))),
        Command::Env(args) => (
            "error",
            block_on(actions::env(args, &mut std::io::stdout())),
        ),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{failure}: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Run a command that talks to KMS.
///
/// Each command makes one KMS request, so a single-threaded runtime is
/// enough, and `encrypt`, which makes none, starts no runtime at all.
fn block_on(
    command: impl Future<Output = Result<(), actions::CliError>>,
) -> Result<(), actions::CliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(command)
}

/// Keep private keys and decrypted secrets out of core dumps.
///
/// Zeroizing only wipes the final copy of a buffer, so a crash dump could
/// still contain key material or plaintext. Best effort: failures are
/// ignored, since none of this is needed for correctness.
fn disable_core_dumps() {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        let _ = setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        );
    }

    // Not dumpable also stops other processes of the same user from
    // attaching with ptrace or reading /proc/<pid>/mem.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    }
}
