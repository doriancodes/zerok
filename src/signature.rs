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
