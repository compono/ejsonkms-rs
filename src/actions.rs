//! The `ejsonkms` commands.

// These are the CLI's commands, so they print their results.
#![allow(clippy::print_stdout)]

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use ejson::FileFormat;
use ejson::env::{ExportStyle, Shell};

use ejsonkms::EjsonKmsError;

/// What a command failed with: an [`EjsonKmsError`], or an ejson error from
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
fn write_private_file_atomically(path: &Path, data: &[u8]) -> Result<(), EjsonKmsError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} has no file name", path.display()),
            )
        })?
        .to_string_lossy();

    let (temp_path, mut temp) = create_temp_file(parent, &name)?;

    let result = (|| -> std::io::Result<()> {
        temp.write_all(data)?;
        temp.sync_all()?;
        drop(temp);
        fs::rename(&temp_path, path)
    })();

    if let Err(err) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(err.into());
    }

    // Persist the rename itself. Best effort: not every platform can open or
    // sync a directory.
    #[cfg(unix)]
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Create a new, owner-only temporary file next to the file being written.
fn create_temp_file(dir: &Path, name: &str) -> std::io::Result<(PathBuf, File)> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    loop {
        let unique = format!(
            ".{name}.ejsonkms-{}-{}.tmp",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let temp_path = dir.join(unique);

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

/// (Re-)encrypt one or more EJSON files in place.
pub(crate) fn encrypt_action(file_paths: &[PathBuf]) -> Result<(), CliError> {
    for file_path in file_paths {
        let n = ejson::encrypt_file_in_place(file_path).map_err(EjsonKmsError::from)?;
        println!("Wrote {n} bytes to {}.", file_path.display());
    }
    Ok(())
}

/// Decrypt an EJSON file, writing the output to `out_file` (or stdout if `None`).
pub(crate) async fn decrypt_action(
    ejson_file_path: &Path,
    aws_region: Option<&str>,
    out_file: Option<&Path>,
) -> Result<(), CliError> {
    let decrypted = ejsonkms::decrypt(ejson_file_path, aws_region).await?;

    match out_file {
        Some(path) => write_private_file_atomically(path, &decrypted)?,
        None => std::io::stdout()
            .write_all(&decrypted)
            .map_err(EjsonKmsError::from)?,
    }
    Ok(())
}

/// Generate a new EJSON keypair, encrypting the private key with KMS.
///
/// Writes the EJSON file to `out_file` (or stdout if `None`).
///
/// The private key is not shown unless `show_private_key` is set: it is
/// already in the file, encrypted with KMS, and anything printed ends up in
/// terminal scrollback and CI logs. When it is set, stdout carries
/// `Private Key: ...` first and, if the file also goes to stdout, an
/// `EJSON File:` line before it.
///
/// The output format follows the extension of `out_file` (`.eyaml` -> YAML,
/// `.etoml` -> TOML, ...); JSON is used for stdout or unrecognized extensions.
///
/// `out_file` must not exist yet: a keygen over a secrets file would discard
/// its encrypted values along with the only copy of their private key.
pub(crate) async fn keygen_action(
    kms_key_id: &str,
    aws_region: Option<&str>,
    out_file: Option<&Path>,
    show_private_key: bool,
) -> Result<(), CliError> {
    // Fail before asking KMS for anything; `create_new` below still guards
    // against the file appearing in the meantime.
    if let Some(path) = out_file
        && path.exists()
    {
        return Err(EjsonKmsError::from(already_exists(path)).into());
    }

    let ejson_kms_keys = ejsonkms::keygen(kms_key_id, aws_region).await?;

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
            .map_err(EjsonKmsError::from)?;
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
pub(crate) async fn env_action<W: Write>(
    ejson_file_path: &Path,
    aws_region: Option<&str>,
    quiet: bool,
    output: &mut W,
) -> Result<(), CliError> {
    let style = if quiet {
        ExportStyle::Unexported
    } else {
        ExportStyle::Exported
    };

    let env_values = ejsonkms::decrypt_env(ejson_file_path, aws_region).await?;

    // POSIX `export KEY='value'` syntax, as before. ejson quotes values so
    // that fish reads them identically.
    ejson::env::export(output, &env_values, Shell::Posix, style)?;
    Ok(())
}
