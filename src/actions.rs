//! CLI actions for the `ejsonkms` binary.

// These are the CLI's commands, so they print their results.
#![allow(clippy::print_stdout)]

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use zeroize::Zeroizing;

use ejson::env::{ExportStyle, SecretEnvMap, Shell};
use ejson::{FileFormat, KeySource, UnderscorePrefix};

use crate::{
    decrypt, decrypt_private_key_with_kms, detect_format, extract_private_key_enc, keygen,
    read_file_checked, EjsonKmsError,
};

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
pub fn encrypt_action(file_paths: &[String]) -> Result<(), EjsonKmsError> {
    if file_paths.is_empty() {
        return Err(EjsonKmsError::Env(
            "at least one file path must be given".to_string(),
        ));
    }
    for file_path in file_paths {
        let n = ejson::encrypt_file_in_place(file_path)?;
        println!("Wrote {n} bytes to {file_path}.");
    }
    Ok(())
}

/// Decrypt an EJSON file, writing the output to `out_file` (or stdout if `None`).
pub async fn decrypt_action(
    ejson_file_path: &str,
    aws_region: &str,
    out_file: Option<&str>,
) -> Result<(), EjsonKmsError> {
    // Wipe the plaintext from memory once it has been written out.
    let decrypted = Zeroizing::new(decrypt(ejson_file_path, aws_region).await?);

    match out_file {
        Some(path) => write_private_file_atomically(Path::new(path), &decrypted)?,
        None => {
            std::io::stdout().write_all(&decrypted)?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct EjsonKmsFile {
    #[serde(rename = "_public_key")]
    public_key: String,
    #[serde(rename = "_private_key_enc")]
    private_key_enc: String,
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
pub async fn keygen_action(
    kms_key_id: &str,
    aws_region: &str,
    out_file: Option<&str>,
    show_private_key: bool,
) -> Result<(), EjsonKmsError> {
    // Fail before asking KMS for anything; `create_new` below still guards
    // against the file appearing in the meantime.
    if let Some(path) = out_file {
        if Path::new(path).exists() {
            return Err(already_exists(path).into());
        }
    }

    let ejson_kms_keys = keygen(kms_key_id, aws_region).await?;

    let ejson_kms_file = EjsonKmsFile {
        public_key: ejson_kms_keys.public_key.clone(),
        private_key_enc: ejson_kms_keys.private_key_enc.clone(),
    };

    let format = out_file
        .and_then(|path| detect_format(path).ok())
        .unwrap_or(FileFormat::Json);
    let ejson_file = match format {
        FileFormat::Json => {
            serde_json::to_string_pretty(&ejson_kms_file).map_err(EjsonKmsError::json)?
        }
        FileFormat::Yaml => {
            serde_norway::to_string(&ejson_kms_file).map_err(EjsonKmsError::yaml)?
        }
        FileFormat::Toml => toml::to_string(&ejson_kms_file).map_err(EjsonKmsError::toml)?,
        // `FileFormat` may gain formats in a minor release of ejson.
        other => return Err(EjsonKmsError::UnsupportedFormat(other)),
    };

    // Write the file before printing the private key, so a key is never
    // shown for a file that could not be written.
    if let Some(path) = out_file {
        let mut target = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => already_exists(path),
                _ => e,
            })?;
        target.write_all(ejson_file.as_bytes())?;
    }

    if show_private_key {
        println!("Private Key: {}", ejson_kms_keys.private_key);
    }
    if out_file.is_none() {
        if show_private_key {
            println!("EJSON File:");
        }
        println!("{}", ejson_file.trim_end());
    }
    Ok(())
}

fn already_exists(path: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("{path} already exists; refusing to overwrite it"),
    )
}

/// Decrypt an EJSON file and write shell export statements for the values
/// under its `environment` key.
pub async fn env_action<W: Write>(
    ejson_file_path: &str,
    aws_region: &str,
    quiet: bool,
    output: &mut W,
) -> Result<(), EjsonKmsError> {
    let style = if quiet {
        ExportStyle::Unexported
    } else {
        ExportStyle::Exported
    };

    let format = detect_format(ejson_file_path)?;

    // Read the file once
    let data = read_file_checked(ejson_file_path)?;

    let private_key_enc = extract_private_key_enc(&data, format)?;

    let kms_decrypted_private_key =
        decrypt_private_key_with_kms(&private_key_enc, aws_region).await?;

    // Decrypt using the already-read data
    let content = ejson::decrypt_bytes_typed(
        &data,
        KeySource::PrivateKey(&kms_decrypted_private_key),
        format,
        UnderscorePrefix::Keep,
    )?;

    // Extract env values; a missing or invalid "environment" key results in an
    // empty export rather than an error
    let env_values = match ejson::env::extract_env(&content) {
        Ok(values) => values,
        Err(e) if e.is_missing_environment() => SecretEnvMap::new(),
        Err(e) => {
            return Err(EjsonKmsError::Env(format!(
                "could not load environment from file: {e}"
            )))
        }
    };

    // POSIX `export KEY='value'` syntax, as before. ejson quotes values so
    // that fish reads them identically.
    ejson::env::export(output, &env_values, Shell::Posix, style)
        .map_err(|e| EjsonKmsError::Env(e.to_string()))
}
