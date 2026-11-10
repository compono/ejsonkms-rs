//! Tests of the library API against the mock KMS.
//!
//! The AWS SDK takes its credentials from the process
//! environment, so everything lives in one test: it sets the environment
//! once, before any other thread could be reading it.

// Test helpers panic on failure by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{AWS_REGION, DENIED_KEY_ID, DENIED_PLAINTEXT, KMS_KEY_ID, MockKms};
use ejson::{FileFormat, Scheme};
use ejsonkms::{Client, EjsonKmsError, KeygenOptions, KmsError};
use serde_json::json;

#[test]
fn library_api_with_mock_kms() {
    let kms = MockKms::start();

    // SAFETY: this is the only test in the binary, and the only other
    // threads at this point are the mock's, which never read the
    // environment. The runtime and the SDK start afterwards.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "123");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "xyz");
        std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(library_api(&kms));
}

async fn library_api(kms: &MockKms) {
    // The endpoint and region are set on the client; only the credentials
    // come from the environment.
    let client = Client::builder()
        .region(AWS_REGION)
        .endpoint_url(&kms.url)
        .build()
        .await;

    // --- keygen ---
    let keys = client
        .keygen(KMS_KEY_ID, &KeygenOptions::default())
        .await
        .expect("keygen should succeed");
    assert_eq!(keys.scheme, Scheme::V1);
    assert_eq!(keys.public_key.len(), 64);
    assert_eq!(keys.private_key.len(), 64);
    assert_ne!(keys.public_key, *keys.private_key);
    // The wrapped key is the private key, as KMS encrypted it.
    let (wrapped, _) = common::unwrap(&keys.private_key_enc);
    assert_eq!(wrapped, keys.private_key.as_bytes());
    // `Debug` does not reveal the private key.
    assert!(!format!("{keys:?}").contains(&*keys.private_key));

    // --- to_document never includes the private key ---
    for format in [FileFormat::Json, FileFormat::Yaml, FileFormat::Toml] {
        let document = keys.to_document(format).unwrap();
        assert!(document.contains(&keys.public_key), "{format}");
        assert!(document.contains(&keys.private_key_enc), "{format}");
        assert!(!document.contains(&*keys.private_key), "{format}");
    }

    // --- encrypt a file, then decrypt it through KMS ---
    let dir = tempfile::TempDir::new().unwrap();
    let write = |name: &str, private_key_enc: &str, environment: serde_json::Value| {
        let path = dir.path().join(name);
        let contents = json!({
            "_public_key": keys.public_key,
            "_private_key_enc": private_key_enc,
            "environment": environment,
        });
        std::fs::write(&path, contents.to_string()).unwrap();
        ejson::encrypt_file_in_place(&path).unwrap();
        path
    };

    let secrets = write(
        "secrets.ejson",
        &keys.private_key_enc,
        json!({ "my_secret": "secret123" }),
    );
    assert!(
        !std::fs::read_to_string(&secrets)
            .unwrap()
            .contains("secret123")
    );

    let decrypted = client
        .decrypt(&secrets)
        .await
        .expect("decrypt should succeed");
    let decrypted: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(decrypted["environment"]["my_secret"], "secret123");

    // --- decrypt_env ---
    let environment = client
        .decrypt_env(&secrets)
        .await
        .expect("decrypt_env should succeed");
    let mut exported = Vec::new();
    ejson::env::export(
        &mut exported,
        &environment,
        ejson::env::Shell::Posix,
        ejson::env::ExportStyle::Exported,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(exported).unwrap(),
        "export my_secret='secret123'\n"
    );

    // --- a v2 (post-quantum hybrid) keypair works the same way ---
    let v2_keys = client
        .keygen(KMS_KEY_ID, &KeygenOptions::default().scheme(Scheme::V2))
        .await
        .expect("v2 keygen should succeed");
    assert_eq!(v2_keys.scheme, Scheme::V2);
    assert_ne!(v2_keys.public_key.len(), 64);

    let v2_secrets = dir.path().join("v2.ejson");
    let mut document: serde_json::Value =
        serde_json::from_str(&v2_keys.to_document(FileFormat::Json).unwrap()).unwrap();
    document["environment"] = json!({ "my_secret": "secret123" });
    std::fs::write(&v2_secrets, document.to_string()).unwrap();
    ejson::encrypt_file_in_place(&v2_secrets).unwrap();
    let encrypted = std::fs::read_to_string(&v2_secrets).unwrap();
    assert!(encrypted.contains("EJ[2:"), "{encrypted}");

    let decrypted = client
        .decrypt(&v2_secrets)
        .await
        .expect("v2 decrypt should succeed");
    let decrypted: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(decrypted["environment"]["my_secret"], "secret123");

    // --- errors are structured ---

    // No `_private_key_enc`: fails before touching KMS.
    let requests = kms.requests().len();
    let err = client
        .decrypt("testdata/test_no_private_key.ejson")
        .await
        .expect_err("decrypt should fail without _private_key_enc");
    assert!(
        matches!(err, EjsonKmsError::MissingPrivateKeyEnc),
        "{err:?}"
    );

    // `_private_key_enc` that is not base64 never reaches KMS either.
    let bad_base64 = write("bad_base64.ejson", "!!!", json!({}));
    let err = client
        .decrypt(&bad_base64)
        .await
        .expect_err("decrypt should fail on invalid base64");
    assert!(matches!(err, EjsonKmsError::Base64(_)), "{err:?}");
    assert_eq!(kms.requests().len(), requests);

    // KMS refuses to decrypt.
    let denied = write(
        "denied.ejson",
        &common::wrap(DENIED_PLAINTEXT, &json!({})),
        json!({}),
    );
    let err = client
        .decrypt(&denied)
        .await
        .expect_err("decrypt should fail when KMS refuses");
    assert!(
        matches!(&err, EjsonKmsError::Kms(KmsError::Decrypt(message)) if message.contains("AccessDeniedException")),
        "{err:?}"
    );

    // KMS refuses to encrypt.
    let err = client
        .keygen(DENIED_KEY_ID, &KeygenOptions::default())
        .await
        .expect_err("keygen should fail when KMS refuses");
    assert!(
        matches!(&err, EjsonKmsError::Kms(KmsError::Encrypt(message)) if message.contains("AccessDeniedException")),
        "{err:?}"
    );

    // A wrapped key that decrypts to something that isn't text.
    let not_utf8 = write(
        "not_utf8.ejson",
        &common::wrap(&[0xff, 0xfe], &json!({})),
        json!({}),
    );
    let err = client
        .decrypt(&not_utf8)
        .await
        .expect_err("decrypt should fail on a non-UTF-8 key");
    assert!(
        matches!(err, EjsonKmsError::Kms(KmsError::KeyNotUtf8)),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "KMS decrypted key is not valid UTF-8");

    // A wrapped key that is text but not an ejson private key.
    let not_a_key = write(
        "not_a_key.ejson",
        &common::wrap(b"not a key", &json!({})),
        json!({ "my_secret": "secret123" }),
    );
    let err = client
        .decrypt(&not_a_key)
        .await
        .expect_err("decrypt should fail on a malformed key");
    assert!(matches!(err, EjsonKmsError::Ejson(_)), "{err:?}");

    // An environment key that is not a valid variable name.
    let bad_env = write(
        "bad_env.ejson",
        &keys.private_key_enc,
        json!({ "not valid": "x" }),
    );
    let err = client
        .decrypt_env(&bad_env)
        .await
        .expect_err("decrypt_env should reject an invalid variable name");
    assert!(
        matches!(
            err,
            EjsonKmsError::Env(ejson::env::EnvError::InvalidIdentifier(_))
        ),
        "{err:?}"
    );
}
