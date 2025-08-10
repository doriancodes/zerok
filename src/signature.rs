use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use std::fs;
use std::path::Path;

pub fn sign_file(path: &Path, signing_key: &SigningKey) -> Result<Signature> {
    let contents =
        fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;
    Ok(signing_key.sign(&contents))
}

pub fn verify_file(path: &Path, public_key: &VerifyingKey, signature: &Signature) -> Result<bool> {
    let contents =
        fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;
    Ok(public_key.verify(&contents, signature).is_ok())
}

pub fn load_keypair(path: &Path) -> Result<SigningKey> {
    let bytes = fs::read(path)
        .with_context(|| format!("Failed to read signing key file: {}", path.display()))?;

    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Expected 32 bytes for SigningKey"))?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn load_public_key(path: &Path) -> Result<VerifyingKey> {
    let bytes = fs::read(path)
        .with_context(|| format!("Failed to read public key file: {}", path.display()))?;

    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Expected 32 bytes for VerifyingKey"))?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

pub fn load_signature(path: &Path) -> Result<Signature> {
    let bytes = fs::read(path)
        .with_context(|| format!("Failed to read signature file: {}", path.display()))?;

    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Expected 64 bytes for Signature"))?;
    Ok(Signature::from_bytes(&arr))
}

pub fn save_signature(path: &Path, signature: &Signature) -> Result<()> {
    fs::write(path, signature.to_bytes())
        .with_context(|| format!("Failed to write signature file: {}", path.display()))
}

pub fn generate_keypair(secret_path: &Path, pub_path: &Path) -> Result<()> {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    fs::write(secret_path, signing_key.to_bytes()).context("Failed to write private key")?;
    fs::write(pub_path, verifying_key.to_bytes()).context("Failed to write public key")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn test_signature_cycle_roundtrip() -> Result<()> {
        // Use temp files for keys and signature
        let secret_file = NamedTempFile::new()?;
        let pub_file = NamedTempFile::new()?;
        let sig_dir = TempDir::new()?;
        let sig_path = sig_dir.path().join("test.sig");

        generate_keypair(secret_file.path(), pub_file.path())?;

        let signing_key = load_keypair(secret_file.path())?;
        let verifying_key = load_public_key(pub_file.path())?;

        let mut target = NamedTempFile::new()?;
        writeln!(target, "hello test")?;

        // Sign, save, reload, verify
        let sig = sign_file(target.path(), &signing_key)?;
        save_signature(&sig_path, &sig)?;
        let sig2 = load_signature(&sig_path)?;
        assert!(verify_file(target.path(), &verifying_key, &sig2)?);
        Ok(())
    }

    #[test]
    fn test_verify_fails_when_file_changed() -> Result<()> {
        let secret_file = NamedTempFile::new()?;
        let pub_file = NamedTempFile::new()?;
        generate_keypair(secret_file.path(), pub_file.path())?;
        let sk = load_keypair(secret_file.path())?;
        let vk = load_public_key(pub_file.path())?;

        let mut target = NamedTempFile::new()?;
        write!(target, "original")?;
        let sig = sign_file(target.path(), &sk)?;

        // Tamper with the file after signing
        write!(target, " (tampered)")?;

        let ok = verify_file(target.path(), &vk, &sig)?;
        assert!(!ok, "verification should fail after tampering");
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_wrong_public_key() -> Result<()> {
        // Keypair A
        let a_secret = NamedTempFile::new()?;
        let a_pub = NamedTempFile::new()?;
        generate_keypair(a_secret.path(), a_pub.path())?;
        let sk_a = load_keypair(a_secret.path())?;

        // Keypair B (wrong verifier)
        let b_secret = NamedTempFile::new()?;
        let b_pub = NamedTempFile::new()?;
        generate_keypair(b_secret.path(), b_pub.path())?;
        let vk_b = load_public_key(b_pub.path())?;

        let mut target = NamedTempFile::new()?;
        writeln!(target, "payload")?;
        let sig = sign_file(target.path(), &sk_a)?;

        let ok = verify_file(target.path(), &vk_b, &sig)?;
        assert!(!ok, "verification should fail with mismatched public key");
        Ok(())
    }

    #[test]
    fn test_load_keypair_rejects_wrong_size() {
        let bad = NamedTempFile::new().unwrap();
        // 31 bytes instead of 32
        std::fs::write(bad.path(), vec![0u8; 31]).unwrap();
        let err = load_keypair(bad.path()).expect_err("should reject bad key size");
        let msg = format!("{err:#}");
        assert!(msg.contains("Expected 32 bytes for SigningKey"));
    }

    #[test]
    fn test_load_public_key_rejects_wrong_size() {
        let bad = NamedTempFile::new().unwrap();
        // 33 bytes instead of 32
        std::fs::write(bad.path(), vec![0u8; 33]).unwrap();
        let err = load_public_key(bad.path()).expect_err("should reject bad pubkey size");
        let msg = format!("{err:#}");
        assert!(msg.contains("Expected 32 bytes for VerifyingKey"));
    }

    #[test]
    fn test_load_signature_rejects_wrong_size() {
        let bad = NamedTempFile::new().unwrap();
        // 63 bytes instead of 64
        std::fs::write(bad.path(), vec![0u8; 63]).unwrap();
        let err = load_signature(bad.path()).expect_err("should reject bad signature size");
        let msg = format!("{err:#}");
        assert!(msg.contains("Expected 64 bytes for Signature"));
    }

    #[test]
    fn test_sign_file_missing_returns_error() {
        let secret_file = NamedTempFile::new().unwrap();
        let pub_file = NamedTempFile::new().unwrap();
        generate_keypair(secret_file.path(), pub_file.path()).unwrap();
        let sk = load_keypair(secret_file.path()).unwrap();

        // Point to a non-existent file
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does_not_exist.bin");
        let err = sign_file(&missing, &sk).expect_err("should error for missing file");
        let msg = format!("{err:#}");
        assert!(msg.contains("Failed to read file"), "got: {msg}");
    }

    #[test]
    fn test_save_signature_and_reload_roundtrip() -> Result<()> {
        let secret_file = NamedTempFile::new()?;
        let pub_file = NamedTempFile::new()?;
        generate_keypair(secret_file.path(), pub_file.path())?;
        let sk = load_keypair(secret_file.path())?;

        let mut target = NamedTempFile::new()?;
        write!(target, "abc")?;

        let sig = sign_file(target.path(), &sk)?;
        let dir = TempDir::new()?;
        let path = dir.path().join("sig.bin");
        save_signature(&path, &sig)?;
        let loaded = load_signature(&path)?;
        assert_eq!(loaded.to_bytes(), sig.to_bytes());
        Ok(())
    }
}
