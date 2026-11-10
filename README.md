# ejsonkms

`ejsonkms` combines the [ejson library](https://github.com/runlevel5/ejson-rs) with [AWS Key Management
Service](https://aws.amazon.com/kms/) to simplify deployments on AWS. The EJSON private key is encrypted with
KMS and stored inside the EJSON file as `_private_key_enc`. Access to decrypt secrets can be controlled with IAM
permissions on the KMS key.

In addition to JSON, TOML and YAML secrets files are supported. The format is detected from the file
extension:

| Format | Extensions                        |
|--------|-----------------------------------|
| JSON   | `.ejson`, `.json`                 |
| TOML   | `.etoml`, `.toml`                 |
| YAML   | `.eyaml`, `.eyml`, `.yaml`, `.yml` |

`keygen -o` writes the file in the format matching the output file's extension (JSON when writing to
stdout or an unrecognized extension).

## Install

### Fedora (COPR)

ejsonkms is packaged in the [tle/power](https://copr.fedorainfracloud.org/coprs/tle/power/) COPR repository:

```
sudo dnf copr enable tle/power
sudo dnf install ejsonkms
```

### From source

```
cargo install --path .
```

## Usage

Generating an EJSON file:

```
$ ejsonkms keygen --aws-region us-east-1 --kms-key-id bc436485-5092-42b8-92a3-0aa8b93536dc -o secrets.ejson
Private Key: ae5969d1fb70faab76198ee554bf91d2fffc44d027ea3d804a7c7f92876d518b
$ cat secrets.ejson
{
  "_public_key": "6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52",
  "_private_key_enc": "S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAAycRX5OBx6xGuYOPAmDJ1FombB1lFybMP42s7PGmoa24bAesPMMZtI9V0w0p0lEgLeeSvYdsPuoPROa4bwnQxJB28eC6fHgfWgY7jgDWY9uP/tgzuWL3zuIaq+9Q=="
}
```

> [!NOTE]
> If the `AWS_REGION` environment variable is set, it will be used implicitly for `--aws-region` when the
> flag is not provided. `AWS_DEFAULT_REGION` (and the usual AWS config chain) is used as a further fallback.

Encrypting:

```
$ ejsonkms encrypt secrets.ejson
```

Decrypting:

```
$ ejsonkms decrypt secrets.ejson
{
  "_public_key": "6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52",
  "_private_key_enc": "S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAAycRX5OBx6xGuYOPAmDJ1FombB1lFybMP42s7PGmoa24bAesPMMZtI9V0w0p0lEgLeeSvYdsPuoPROa4bwnQxJB28eC6fHgfWgY7jgDWY9uP/tgzuWL3zuIaq+9Q==",
  "environment": {
    "my_secret": "secret123"
  }
}
```

Exporting shell variables (compatible with [ejson2env](https://github.com/Shopify/ejson2env)):

```
$ exports=$(ejsonkms env secrets.ejson)
$ echo $exports
export my_secret=secret123
$ eval $exports
$ echo $my_secret
secret123
```

Note that only secrets under the "environment" key will be exported using the `env` command.

## Testing

Unit and integration tests run against an in-process mock KMS server, so no
external services are needed:

```
cargo test
```

To test the CLI manually against a real (fake) KMS, a
[local-kms](https://github.com/nsmithuk/local-kms) service seeded with a test
key is provided:

```
docker compose up -d awskms
export FAKE_AWSKMS_URL=http://localhost:8080
export AWS_ACCESS_KEY_ID=123 AWS_SECRET_ACCESS_KEY=xyz AWS_REGION=us-east-1
ejsonkms keygen --kms-key-id bc436485-5092-42b8-92a3-0aa8b93536dc -o secrets.ejson
```

When `FAKE_AWSKMS_URL` is set, the KMS client is pointed at that endpoint
instead of AWS.
