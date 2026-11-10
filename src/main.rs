// The CLI reports errors on stderr.
#![allow(clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod actions;

#[derive(Parser)]
#[command(
    name = "ejsonkms",
    version,
    about = "manage encrypted secrets using EJSON & AWS KMS"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// (re-)encrypt one or more EJSON files
    Encrypt {
        /// EJSON file(s) to encrypt
        #[arg(value_name = "FILE", required = true)]
        files: Vec<PathBuf>,
    },
    /// decrypt an EJSON file
    Decrypt {
        /// print output to the provided file, rather than stdout
        #[arg(short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,
        /// AWS Region
        #[arg(long = "aws-region", env = "AWS_REGION")]
        aws_region: Option<String>,
        /// EJSON file to decrypt
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// generate a new EJSON keypair
    Keygen {
        /// KMS Key ID to encrypt the private key with
        #[arg(long = "kms-key-id")]
        kms_key_id: String,
        /// AWS Region
        #[arg(long = "aws-region", env = "AWS_REGION")]
        aws_region: Option<String>,
        /// write EJSON file to a file rather than stdout
        #[arg(short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,
        /// also print the unencrypted private key (it is not needed to use
        /// the file: KMS decrypts the copy stored in it)
        #[arg(long = "show-private-key")]
        show_private_key: bool,
    },
    /// print shell export statements
    Env {
        /// Suppress export statement
        #[arg(short, long)]
        quiet: bool,
        /// AWS Region
        #[arg(long = "aws-region", env = "AWS_REGION")]
        aws_region: Option<String>,
        /// EJSON file to read secrets from
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
}

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
    let (failure, result) = match cli.command {
        Command::Encrypt { files } => ("Encryption failed", actions::encrypt_action(&files)),
        Command::Decrypt {
            out,
            aws_region,
            file,
        } => (
            "Decryption failed",
            block_on(actions::decrypt_action(
                &file,
                aws_region.as_deref(),
                out.as_deref(),
            )),
        ),
        Command::Keygen {
            kms_key_id,
            aws_region,
            out,
            show_private_key,
        } => (
            "Key generation failed",
            block_on(actions::keygen_action(
                &kms_key_id,
                aws_region.as_deref(),
                out.as_deref(),
                show_private_key,
            )),
        ),
        Command::Env {
            quiet,
            aws_region,
            file,
        } => (
            "error",
            block_on(actions::env_action(
                &file,
                aws_region.as_deref(),
                quiet,
                &mut std::io::stdout(),
            )),
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
    command: impl std::future::Future<Output = Result<(), actions::CliError>>,
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
        use rustix::process::{setrlimit, Resource, Rlimit};
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
        use rustix::process::{set_dumpable_behavior, DumpableBehavior};
        let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    }
}
