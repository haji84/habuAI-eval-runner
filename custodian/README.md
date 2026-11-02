# Offline custodian keys (review-required source, NO live secrets)

This local tool automates age encryption and Ed25519 signing key management
without giving ChatGPT, Codex, the public evaluation runner or the Habu AI
development GitHub connection access to the private keys.

## Separate macOS operating-system account REQUIRED

Use a dedicated macOS login account on a FileVault-protected Mac. Do not
run development AI tools or untrusted scripts under that login. Python
keyring's macOS documentation warns that other Python code under the same
account/executable may read keyring secrets without a new permission prompt.
A separate user and permissions are essential; simply naming separate roles
does not prove independent custody.

This code and the mocked tests are NOT an independent security review.
No real production key has been generated or tested on macOS yet.
A distinct reviewer must inspect the pinned code before initial activation.

## Key contents and dependencies

One macOS Keychain item per version contains:
- Native age X25519 encryption identity
- Ed25519 signing identity (cryptography)

A fresh key is generated only inside the dedicated macOS user process.
The public age recipient and Ed25519 verification key may be exported,
but raw secret keys, case labels and fixed witnesses never leave the
custodian via stdout, chat, Git, logs or command-line arguments.

Dependencies: Python 3.12, keyring 25.7.0, cryptography 46.0.4,
the official age + age-keygen binaries, macOS Keychain and FileVault.
They must be installed in a dedicated isolated Python virtual environment.
The age program is local and does not require a cloud API.

## After independent source review: one-time local activation

    python -m custodian.keykeeper init --version v1
    python -m custodian.keykeeper status --version v1

Both commands produce public identity/status only. The operating system
might request initial authorization. Do not send any private identity
or Keychain credential to ChatGPT.

## Automatic sealing, verification and signed manifests

A separately controlled custodian generator can stream its private synthetic
case pack to stdin, never to the public GitHub Actions runner:

    independent-generator | python -m custodian.keykeeper seal \
      --version v1 --output /absolute/trusted/private/cohort-001.age

The independent-generator is an interface example, not yet implemented.
Only existing output directories are accepted. Output creation is
exclusive, never overwrites, and writes ciphertext with permission 0600.
Decrypted answers never appear in logs.

    python -m custodian.keykeeper verify --version v1 \
      --input /absolute/trusted/private/cohort-001.age

The verify command checks authenticated decryption in memory and emits only
hashes/status. It does NOT prove semantic correctness of generated cases.

    cat frozen-manifest.json | python -m custodian.keykeeper sign --version v1

This prints only a manifest SHA-256 and Ed25519 signature. The independent
verifier must bind the public key to the real custodian, and verify what was
actually signed and executed.

## Key rotation and recovery

To create a new version without deleting or overwriting v1:

    python -m custodian.keykeeper init --version v2

Existing encrypted cohorts still need v1. Never delete old identities
before a separately verified migration and recovery.

For disaster recovery, an independently controlled SECOND age public
recipient must be supplied. The recovery file encrypts BOTH private
identities to that different recipient, without creating plaintext files:

    python -m custodian.keykeeper backup-recovery --version v1 \
      --recovery-recipient AGE_PUBLIC_KEY_OF_OTHER_CUSTODIAN \
      --output /absolute/trusted/private/recovery-v1.age

The receiving custodian must test restoration on a separate trusted device.
The recovery importer and real restore test are not yet implemented;
backup_restoration_independently_tested remains false. Until an independently
verified backup exists, the real assessment is blocked.

## Integration boundaries and why this is NOT an evaluation

The PRIVATE GitHub vault stays inaccessible to the development AI and does
not need any GitHub Actions runtime. A separate authorized local custodian
will later upload only authenticated ciphertext to its private vault
through isolated credentials, never through the public runner.

The real 40+ case pack must be created AFTER freeze, by a different
agent/evaluator, with >=20 verified BUG and >=20 CLEAN cases, then tested
on the fixed model and reviewed by an independent reviewer. Public mocked
tests are not genuine new sealed examples.

The test suite uses FAKE keyring, FAKE age ciphertext and real Ed25519
signature code. It proves control-flow behavior only, not actual age
cryptography, macOS Keychain enforcement or independent identity.
Do not claim QUALITY_QUALIFIED or change the production model.
