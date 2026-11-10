//! The `ejsonkms` commands.

// These are the CLI's commands, so they print their results.
#![allow(clippy::print_stdout)]

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use ejson::FileFormat;

use ejsonkms::Error;

use crate::cli::{DecryptArgs, EncryptArgs, EnvArgs, KeygenArgs, RewrapArgs};

/// What a command failed with: an [`Error`], or an ejson error from
/// a step that doesn't involve KMS.
pub(crate) type CliError = Box<dyn std::error::Error>;

/// Write `data` to `path` so that it is readable only by its owner, creating
/// or atomically replacing the file.
///
/// The data goes to a new owner-only (`0600` on Unix) temporary file in the
/// same directory, which is synced and then renamed over `path`, so `path` is
/// never left half-written and never briefly has looser permissions (an
/// existing file's permissions are not reused). If anything fails, the
/// temporary file is removed so no partial copy of `data` is left on disk.
///
/// On non-Unix platforms the file gets the directory's default permissions.
fn write_private_file_atomically(path: &Path, data: &[u8]) -> Result<(), Error> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} has no file name", path.display()),
        )
    })?;

    // `NamedTempFile` is created owner-only and removes itself when dropped,
    // which covers every early return below.
    let mut prefix = std::ffi::OsString::from(".");
    prefix.push(name);
    prefix.push(".");
    let mut temp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .tempfile_in(parent)?;

    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;

    // Persist the rename itself. Best effort: not every platform can open or
    // sync a directory.
    #[cfg(unix)]
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// (Re-)encrypt one or more EJSON files in place.
pub(crate) fn encrypt(args: &EncryptArgs) -> Result<(), CliError> {
    for file_path in &args.files {
        let n = ejson::encrypt_file_in_place(file_path).map_err(Error::from)?;
        println!("Wrote {n} bytes to {}.", file_path.display());
    }
    Ok(())
}

/// Decrypt an EJSON file, writing the output to `-o FILE` (or stdout).
pub(crate) async fn decrypt(args: &DecryptArgs) -> Result<(), CliError> {
    let decrypted = args.aws.client().await.decrypt(&args.file).await?;

    match &args.out {
        Some(path) => write_private_file_atomically(path, &decrypted)?,
        None => std::io::stdout()
            .write_all(&decrypted)
            .map_err(Error::from)?,
    }
    Ok(())
}

/// Generate a new EJSON keypair, encrypting the private key with KMS.
///
/// Writes the EJSON file to `-o FILE` (or stdout).
///
/// The private key is not shown unless `--show-private-key` is given: it is
/// already in the file, encrypted with KMS, and anything printed ends up in
/// terminal scrollback and CI logs. When it is set, stdout carries
/// `Private Key: ...` first and, if the file also goes to stdout, an
/// `EJSON File:` line before it.
///
/// The output format follows the extension of the file (`.eyaml` -> YAML,
/// `.etoml` -> TOML, ...); JSON is used for stdout or unrecognized extensions.
///
/// The file must not exist yet: a keygen over a secrets file would discard
/// its encrypted values along with the only copy of their private key.
pub(crate) async fn keygen(args: &KeygenArgs) -> Result<(), CliError> {
    let out_file = args.out.as_deref();
    let show_private_key = args.show_private_key;

    // Fail before asking KMS for anything; `create_new` below still guards
    // against the file appearing in the meantime.
    if let Some(path) = out_file
        && path.exists()
    {
        return Err(Error::from(already_exists(path)).into());
    }

    let ejson_kms_keys = args
        .aws
        .client()
        .await
        .keygen(&args.kms_key_id, &args.options())
        .await?;

    let format = out_file
        .and_then(|path| FileFormat::from_path(path).ok())
        .unwrap_or(FileFormat::Json);
    let ejson_file = ejson_kms_keys.to_document(format)?;

    // Write the file before printing the private key, so a key is never
    // shown for a file that could not be written.
    if let Some(path) = out_file {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => already_exists(path),
                _ => e,
            })
            .and_then(|mut target| target.write_all(ejson_file.as_bytes()))
            .map_err(Error::from)?;
    }

    if show_private_key {
        println!("Private Key: {}", *ejson_kms_keys.private_key);
    }
    if out_file.is_none() {
        if show_private_key {
            println!("EJSON File:");
        }
        println!("{}", ejson_file.trim_end());
    }
    Ok(())
}

fn already_exists(path: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "{} already exists; refusing to overwrite it",
            path.display()
        ),
    )
}

/// Decrypt an EJSON file and write shell export statements for the values
/// under its `environment` key.
pub(crate) async fn env<W: Write>(args: &EnvArgs, output: &mut W) -> Result<(), CliError> {
    let env_values = args
        .aws
        .client()
        .await
        .decrypt_env(&args.file, args.underscore_prefix())
        .await?;

    // ejson quotes values so that POSIX shells and fish read them identically.
    ejson::env::export(output, &env_values, args.shell(), args.style())?;
    Ok(())
}

/// Re-encrypt the private key of one or more files with another KMS key.
pub(crate) async fn rewrap(args: &RewrapArgs) -> Result<(), CliError> {
    let client = args.aws.client().await;
    for file_path in &args.files {
        client
            .rewrap(file_path, &args.kms_key_id, args.binding())
            .await?;
        println!("Rewrapped {}.", file_path.display());
    }
    Ok(())
}
