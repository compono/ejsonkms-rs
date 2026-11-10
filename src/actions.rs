//! CLI actions for the `ejsonkms` binary.

use std::io::Write;

use serde::Serialize;

use ejson::env::{ExportStyle, SecretEnvMap, Shell};
use ejson::{FileFormat, KeySource, UnderscorePrefix};

use crate::{
    decrypt, decrypt_private_key_with_kms, detect_format, extract_private_key_enc, keygen,
    read_file_checked, EjsonKmsError,
};

/// Create (or truncate) a file for writing decrypted secrets.
///
/// On Unix the file is created with `0600` permissions so plaintext secrets
/// are not readable by other users.
fn create_secret_file(path: &str) -> Result<std::fs::File, EjsonKmsError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
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
        println!("Wrote {} bytes to {}.", n, file_path);
    }
    Ok(())
}

/// Decrypt an EJSON file, writing the output to `out_file` (or stdout if `None`).
pub async fn decrypt_action(
    ejson_file_path: &str,
    aws_region: &str,
    out_file: Option<&str>,
) -> Result<(), EjsonKmsError> {
    let decrypted = decrypt(ejson_file_path, aws_region).await?;

    match out_file {
        Some(path) => {
            let mut target = create_secret_file(path)?;
            target.write_all(&decrypted)?;
        }
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
/// Prints the private key to stdout and writes the EJSON file to `out_file`
/// (or stdout if `None`).
///
/// The output format follows the extension of `out_file` (`.eyaml` -> YAML,
/// `.etoml` -> TOML, ...); JSON is used for stdout or unrecognized extensions.
pub async fn keygen_action(
    kms_key_id: &str,
    aws_region: &str,
    out_file: Option<&str>,
) -> Result<(), EjsonKmsError> {
    let ejson_kms_keys = keygen(kms_key_id, aws_region).await?;

    let ejson_kms_file = EjsonKmsFile {
        public_key: ejson_kms_keys.public_key.clone(),
        private_key_enc: ejson_kms_keys.private_key_enc.clone(),
    };

    let format = out_file
        .and_then(|path| detect_format(path).ok())
        .unwrap_or(FileFormat::Json);
    let ejson_file = match format {
        FileFormat::Json => serde_json::to_string_pretty(&ejson_kms_file)?,
        FileFormat::Yaml => serde_norway::to_string(&ejson_kms_file)?,
        FileFormat::Toml => toml::to_string(&ejson_kms_file)?,
        // `FileFormat` may gain formats in a minor release of ejson.
        other => return Err(EjsonKmsError::UnsupportedFormat(other)),
    };

    println!("Private Key: {}", ejson_kms_keys.private_key);
    match out_file {
        Some(path) => {
            let mut target = std::fs::File::create(path)?;
            target.write_all(ejson_file.as_bytes())?;
        }
        None => {
            println!("EJSON File:");
            std::io::stdout().write_all(ejson_file.as_bytes())?;
        }
    }
    Ok(())
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
                "could not load environment from file: {}",
                e
            )))
        }
    };

    // POSIX `export KEY='value'` syntax, as before. ejson quotes values so
    // that fish reads them identically.
    ejson::env::export(output, &env_values, Shell::Posix, style)
        .map_err(|e| EjsonKmsError::Env(e.to_string()))
}
