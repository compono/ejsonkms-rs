//! The command-line interface: what each command accepts.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use ejson::env::{ExportStyle, Shell};
use ejson::{Scheme, UnderscorePrefix};
use ejsonkms::{Client, KeyBinding, KeygenOptions};

#[derive(Parser)]
#[command(
    name = "ejsonkms",
    version,
    about = "manage encrypted secrets using EJSON & AWS KMS"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// (re-)encrypt one or more EJSON files
    Encrypt(EncryptArgs),
    /// decrypt an EJSON file
    Decrypt(DecryptArgs),
    /// generate a new EJSON keypair
    Keygen(KeygenArgs),
    /// print shell export statements
    Env(EnvArgs),
    /// re-encrypt a file's private key with another KMS key
    Rewrap(RewrapArgs),
}

/// Where to find KMS; shared by every command that calls it.
#[derive(Args)]
pub(crate) struct AwsArgs {
    /// AWS Region
    #[arg(long = "aws-region", env = "AWS_REGION")]
    aws_region: Option<String>,
}

impl AwsArgs {
    /// A client for the requested region, or for the default AWS region
    /// chain when none was given.
    pub(crate) async fn client(&self) -> Client {
        let mut builder = Client::builder();
        if let Some(region) = &self.aws_region {
            builder = builder.region(region);
        }
        builder.build().await
    }
}

#[derive(Args)]
pub(crate) struct EncryptArgs {
    /// EJSON file(s) to encrypt
    #[arg(value_name = "FILE", required = true)]
    pub(crate) files: Vec<PathBuf>,
}

#[derive(Args)]
pub(crate) struct DecryptArgs {
    /// print output to the provided file, rather than stdout
    #[arg(short = 'o', value_name = "FILE")]
    pub(crate) out: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) aws: AwsArgs,
    /// EJSON file to decrypt
    #[arg(value_name = "FILE")]
    pub(crate) file: PathBuf,
}

#[derive(Args)]
pub(crate) struct KeygenArgs {
    /// KMS Key ID to encrypt the private key with
    #[arg(long = "kms-key-id")]
    pub(crate) kms_key_id: String,
    #[command(flatten)]
    pub(crate) aws: AwsArgs,
    /// write EJSON file to a file rather than stdout
    #[arg(short = 'o', value_name = "FILE")]
    pub(crate) out: Option<PathBuf>,
    /// also print the unencrypted private key (it is not needed to use
    /// the file: KMS decrypts the copy stored in it)
    #[arg(long = "show-private-key")]
    pub(crate) show_private_key: bool,
    /// Key scheme to generate: v1 (NaCl box, readable by every ejson
    /// and ejsonkms) or v2 (hybrid post-quantum)
    #[arg(long = "scheme", default_value = "v1")]
    scheme: Scheme,
    /// Generate a v2 hybrid X25519 + ML-KEM-768 keypair (alias for --scheme v2)
    #[arg(long = "pqc")]
    pqc: bool,
    /// bind the encrypted private key to the public key with a KMS
    /// encryption context (not readable by ejsonkms before 3.0 or the
    /// Go tool)
    #[arg(long = "bind-public-key")]
    bind_public_key: bool,
}

impl KeygenArgs {
    /// The kind of keypair the flags ask for.
    pub(crate) fn options(&self) -> KeygenOptions {
        KeygenOptions::default()
            .scheme(if self.pqc { Scheme::V2 } else { self.scheme })
            .binding(if self.bind_public_key {
                KeyBinding::PublicKey
            } else {
                KeyBinding::Unbound
            })
    }
}

#[derive(Args)]
pub(crate) struct EnvArgs {
    /// Suppress export statement
    #[arg(short, long)]
    quiet: bool,
    #[command(flatten)]
    pub(crate) aws: AwsArgs,
    /// Shell syntax to emit
    #[arg(long = "shell", value_enum, default_value_t = ShellArg::Posix)]
    shell: ShellArg,
    /// Remove the leading underscore from variable names (`_HOST` is
    /// exported as `HOST`)
    #[arg(long = "trim-underscore-prefix")]
    trim_underscore_prefix: bool,
    /// EJSON file to read secrets from
    #[arg(value_name = "FILE")]
    pub(crate) file: PathBuf,
}

#[derive(Args)]
pub(crate) struct RewrapArgs {
    /// KMS Key ID to encrypt the private key with from now on
    #[arg(long = "kms-key-id")]
    pub(crate) kms_key_id: String,
    #[command(flatten)]
    pub(crate) aws: AwsArgs,
    /// also bind the encrypted private key to the public key with a KMS
    /// encryption context (not readable by ejsonkms before 3.0 or the
    /// Go tool); without this the file's current binding is kept
    #[arg(long = "bind-public-key")]
    bind_public_key: bool,
    /// EJSON file(s) to rewrap
    #[arg(value_name = "FILE", required = true)]
    pub(crate) files: Vec<PathBuf>,
}

impl RewrapArgs {
    /// The binding the flags ask for, or `None` to keep the file's own.
    pub(crate) fn binding(&self) -> Option<KeyBinding> {
        self.bind_public_key.then_some(KeyBinding::PublicKey)
    }
}

/// Which shell syntax `env` writes.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ShellArg {
    /// POSIX-compatible shells (bash, zsh, sh, ...): `export KEY='value'`
    Posix,
    /// Fish shell: `set -gx KEY 'value'`
    Fish,
    /// Fish syntax if `$FISH_VERSION` is set, otherwise POSIX. Fish doesn't
    /// export it, so under fish this is usually POSIX, which fish also accepts.
    Auto,
}

impl EnvArgs {
    /// The shell syntax to write.
    pub(crate) fn shell(&self) -> Shell {
        match self.shell {
            ShellArg::Posix => Shell::Posix,
            ShellArg::Fish => Shell::Fish,
            ShellArg::Auto => Shell::detect(),
        }
    }

    /// Whether to export the variables or only assign them.
    pub(crate) fn style(&self) -> ExportStyle {
        if self.quiet {
            ExportStyle::Unexported
        } else {
            ExportStyle::Exported
        }
    }

    /// What to do with a leading underscore in variable names.
    pub(crate) fn underscore_prefix(&self) -> UnderscorePrefix {
        if self.trim_underscore_prefix {
            UnderscorePrefix::Trim
        } else {
            UnderscorePrefix::Keep
        }
    }
}
