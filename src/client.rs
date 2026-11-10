//! The entry point: a client that holds the KMS connection.

use std::path::Path;

use ejson::env::SecretEnvMap;
use ejson::{FileFormat, GeneratedKeypair, KeySource, UnderscorePrefix};
use zeroize::Zeroizing;

use crate::document::{detect_format, extract_private_key_enc, read_file_checked};
use crate::kms::{decrypt_private_key_with_kms, encrypt_private_key_with_kms, new_kms_client};
use crate::{EjsonKmsKeys, Error, KeyBinding, KeygenOptions, Result, RewrapError, rewrap};

/// Generates keypairs and decrypts secrets files, using AWS KMS to wrap and
/// unwrap the private key.
///
/// Creating a client loads the AWS configuration (region, credentials,
/// endpoint) once; reuse it for every file. Cloning is cheap and shares the
/// underlying connection.
///
/// ```no_run
/// # async fn example() -> Result<(), ejsonkms::Error> {
/// let client = ejsonkms::Client::builder()
///     .region("us-east-1")
///     .build()
///     .await;
/// let plaintext = client.decrypt("secrets.ejson").await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Client {
    kms: aws_sdk_kms::Client,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// A client using the default AWS configuration: the region from
    /// `AWS_REGION`, `AWS_DEFAULT_REGION` or the profile, and the standard
    /// credential chain.
    pub async fn new() -> Self {
        Self::builder().build().await
    }

    /// Configure a client before creating it.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Generate a keypair and encrypt its private key with the KMS key
    /// `kms_key_id` (a key id, key ARN, alias name or alias ARN).
    ///
    /// Write the result to a new secrets file with
    /// [`EjsonKmsKeys::to_document`].
    pub async fn keygen(&self, kms_key_id: &str, options: &KeygenOptions) -> Result<EjsonKmsKeys> {
        let scheme = options.scheme;
        let GeneratedKeypair {
            public_key,
            private_key,
            ..
        } = ejson::generate_keypair(scheme);

        let binding = options.binding;
        let bound_public_key = match binding {
            KeyBinding::Unbound => None,
            KeyBinding::PublicKey => Some(public_key.as_str()),
        };
        let private_key_enc =
            encrypt_private_key_with_kms(&self.kms, &private_key, kms_key_id, bound_public_key)
                .await?;

        Ok(EjsonKmsKeys {
            public_key,
            private_key_enc,
            private_key,
            scheme,
            binding,
        })
    }

    /// Decrypt an EJSON/EYAML/ETOML file, obtaining the private key from the
    /// embedded `_private_key_enc` field via KMS.
    ///
    /// The file format is auto-detected from the file extension:
    /// - `.ejson` or `.json` -> JSON format
    /// - `.etoml` or `.toml` -> TOML format
    /// - `.eyaml`, `.eyml`, `.yaml`, or `.yml` -> YAML format
    ///
    /// The decrypted document is wrapped in [`Zeroizing`], so it is wiped from
    /// memory when dropped.
    pub async fn decrypt(&self, ejson_file_path: impl AsRef<Path>) -> Result<Zeroizing<Vec<u8>>> {
        let file = self.open(ejson_file_path.as_ref()).await?;

        let mut output = Zeroizing::new(Vec::new());
        ejson::decrypt(&file.data[..], &mut *output, file.key(), file.format)?;

        Ok(output)
    }

    /// Decrypt an EJSON/EYAML/ETOML file and return the values under its
    /// `environment` key, obtaining the private key via KMS as
    /// [`decrypt`](Self::decrypt) does.
    ///
    /// A file with no `environment` key, or one that is not a map, gives an
    /// empty map rather than an error. Write the values as shell assignments
    /// with [`ejson::env::export`].
    pub async fn decrypt_env(&self, ejson_file_path: impl AsRef<Path>) -> Result<SecretEnvMap> {
        let file = self.open(ejson_file_path.as_ref()).await?;

        let content = ejson::decrypt_bytes_typed(
            &file.data,
            file.key(),
            file.format,
            UnderscorePrefix::Keep,
        )?;

        match ejson::env::extract_env(&content) {
            Ok(values) => Ok(values),
            Err(e) if e.is_missing_environment() => Ok(SecretEnvMap::new()),
            Err(e) => Err(Error::Env(e)),
        }
    }

    /// Re-encrypt a file's private key with the KMS key `kms_key_id` and
    /// write the new `_private_key_enc` back to the file.
    ///
    /// Use this to move a secrets file to another KMS key, or, with
    /// `binding` set to [`KeyBinding::PublicKey`], to bind an existing
    /// file's key to its public key. `None` keeps the file's current
    /// binding. A bound key cannot be made unbound.
    ///
    /// The keypair itself does not change, so the encrypted values stay as
    /// they are, and the rest of the file is kept byte for byte. The caller
    /// needs `kms:Decrypt` on the current key and `kms:Encrypt` on the new
    /// one. The private key exists in memory only between the two requests
    /// and is wiped afterwards.
    ///
    /// The file is replaced atomically, and only after the edited text has
    /// been read back and checked; on any error it is left untouched.
    pub async fn rewrap(
        &self,
        ejson_file_path: impl AsRef<Path>,
        kms_key_id: &str,
        binding: Option<KeyBinding>,
    ) -> Result<()> {
        let path = ejson_file_path.as_ref();
        let format = detect_format(path)?;
        let data = read_file_checked(path)?;
        let current = extract_private_key_enc(&data, format)?;

        let add_binding = match (current.binding, binding) {
            (KeyBinding::PublicKey, Some(KeyBinding::Unbound)) => {
                return Err(RewrapError::CannotUnbind.into());
            }
            (KeyBinding::Unbound, Some(KeyBinding::PublicKey)) => true,
            _ => false,
        };
        let new_bound_public_key = if add_binding {
            Some(
                current
                    .public_key
                    .as_deref()
                    .ok_or(Error::MissingPublicKey)?,
            )
        } else {
            current.bound_public_key.as_deref()
        };

        let private_key = decrypt_private_key_with_kms(
            &self.kms,
            &current.private_key_enc,
            current.bound_public_key.as_deref(),
        )
        .await?;
        let private_key_enc =
            encrypt_private_key_with_kms(&self.kms, &private_key, kms_key_id, new_bound_public_key)
                .await?;
        drop(private_key);

        let updated = rewrap::rewrite(&data, format, &current, &private_key_enc, add_binding)?;

        // Don't overwrite an edit made while KMS was being called.
        if read_file_checked(path)? != data {
            return Err(RewrapError::FileChanged.into());
        }
        rewrap::replace_file(path, &updated).map_err(|source| Error::WriteFile {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Read `path` and ask KMS to decrypt its `_private_key_enc`.
    async fn open(&self, path: &Path) -> Result<EncryptedFile> {
        let format = detect_format(path)?;
        let data = read_file_checked(path)?;
        let wrapped = extract_private_key_enc(&data, format)?;
        let private_key = decrypt_private_key_with_kms(
            &self.kms,
            &wrapped.private_key_enc,
            wrapped.bound_public_key.as_deref(),
        )
        .await?;

        Ok(EncryptedFile {
            data,
            format,
            private_key,
        })
    }
}

/// Settings for a [`Client`]; start with [`Client::builder`].
///
/// Anything not set here comes from the usual AWS configuration (environment
/// variables, the shared config and credentials files, instance or container
/// roles).
#[derive(Debug, Clone, Default)]
#[must_use = "a builder does nothing until `build` is called"]
pub struct ClientBuilder {
    region: Option<String>,
    endpoint_url: Option<String>,
}

impl ClientBuilder {
    /// Use this AWS region instead of the one from the AWS configuration.
    /// An empty string is treated as unset.
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Send KMS requests to this URL instead of the regional AWS endpoint,
    /// for example a VPC endpoint or a local KMS used in tests.
    pub fn endpoint_url(mut self, endpoint_url: impl Into<String>) -> Self {
        self.endpoint_url = Some(endpoint_url.into());
        self
    }

    /// Load the AWS configuration and create the client.
    pub async fn build(self) -> Client {
        Client {
            kms: new_kms_client(self.region.as_deref(), self.endpoint_url.as_deref()).await,
        }
    }
}

/// A secrets file read from disk, with its private key recovered via KMS.
struct EncryptedFile {
    data: Vec<u8>,
    format: FileFormat,
    private_key: Zeroizing<String>,
}

impl EncryptedFile {
    fn key(&self) -> KeySource<'_> {
        KeySource::PrivateKey(&self.private_key)
    }
}
