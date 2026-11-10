// The CLI reports errors on stderr.
#![allow(clippy::print_stderr)]

use std::process::exit;

use clap::{Parser, Subcommand};

use ejsonkms::actions;

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
        files: Vec<String>,
    },
    /// decrypt an EJSON file
    Decrypt {
        /// print output to the provided file, rather than stdout
        #[arg(short = 'o', value_name = "FILE")]
        out: Option<String>,
        /// AWS Region
        #[arg(long = "aws-region", env = "AWS_REGION", default_value = "")]
        aws_region: String,
        /// EJSON file to decrypt
        #[arg(value_name = "FILE")]
        file: String,
    },
    /// generate a new EJSON keypair
    Keygen {
        /// KMS Key ID to encrypt the private key with
        #[arg(long = "kms-key-id")]
        kms_key_id: String,
        /// AWS Region
        #[arg(long = "aws-region", env = "AWS_REGION", default_value = "")]
        aws_region: String,
        /// write EJSON file to a file rather than stdout
        #[arg(short = 'o', value_name = "FILE")]
        out: Option<String>,
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
        #[arg(long = "aws-region", env = "AWS_REGION", default_value = "")]
        aws_region: String,
        /// EJSON file to read secrets from
        #[arg(value_name = "FILE")]
        file: String,
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

#[tokio::main]
async fn main() {
    // Cannot fail: no other logger has been installed yet.
    if log::set_logger(&StderrLogger).is_ok() {
        log::set_max_level(log::LevelFilter::Warn);
    }

    let cli = Cli::parse();

    // Every command handles secrets: private keys (keygen, decrypt, env) or
    // plaintext about to be encrypted (encrypt).
    disable_core_dumps();

    match cli.command {
        Command::Encrypt { files } => {
            if let Err(err) = actions::encrypt_action(&files) {
                eprintln!("Encryption failed: {err}");
                exit(1);
            }
        }
        Command::Decrypt {
            out,
            aws_region,
            file,
        } => {
            if let Err(err) = actions::decrypt_action(&file, &aws_region, out.as_deref()).await {
                eprintln!("Decryption failed: {err}");
                exit(1);
            }
        }
        Command::Keygen {
            kms_key_id,
            aws_region,
            out,
            show_private_key,
        } => {
            if let Err(err) =
                actions::keygen_action(&kms_key_id, &aws_region, out.as_deref(), show_private_key)
                    .await
            {
                eprintln!("Key generation failed: {err}");
                exit(1);
            }
        }
        Command::Env {
            quiet,
            aws_region,
            file,
        } => {
            let mut stdout = std::io::stdout();
            if let Err(err) = actions::env_action(&file, &aws_region, quiet, &mut stdout).await {
                eprintln!("error: {err}");
                exit(1);
            }
        }
    }
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
