use anyhow::anyhow;
use base64::prelude::*;
use std::{fs, io::Read, path::PathBuf};
use zeroize::Zeroizing;

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use argon2::Argon2;
use serde::{Deserialize, Serialize};

use crate::{toml::toml, vault::home_dirr};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Fields {
    pub entry: Entry,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry {
    pub id: String,
    pub salt: String,
    pub nonce: String,
    pub data: String,
    pub note: Option<String>,
    pub date: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultExport {
    pub salt: String,
    pub nonce: String,
    pub vault: String,
}

pub fn read_json(ef: Option<&str>) -> anyhow::Result<Vec<Fields>> {
    let mut s = String::new();

    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    let mut o = if let Some(ef) = ef {
        let o = fs::File::open(home_dirr()?.join(ef));

        if o.as_ref()
            .is_err_and(|s| s.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(vec![]);
        }

        o?
    } else {
        fs::File::open(
            main_vault_path
                .join("gem.json")
                .to_string_lossy()
                .to_string(),
        )?
    };

    o.read_to_string(&mut s)?;

    if let Ok(vec) = serde_json::from_str::<Vec<Fields>>(s.trim()) {
        Ok(vec)
    } else {
        Err(anyhow!("Couldn't read json file"))
    }
}

pub fn enc(
    master_key: &str,
    username_email: &str,
    password: &str,
) -> anyhow::Result<([u8; 16], [u8; 12], Vec<u8>)> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let argon2 = Argon2::default();
    let mut out_master = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(master_key.as_bytes(), &salt, &mut *out_master)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&*out_master);
    let cip = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let format = Zeroizing::new(format!("{}|{}", username_email, password));

    let enc = cip
        .encrypt(&nonce, format.as_bytes())
        .map_err(|_| anyhow!("Couldn't enc data"))?;

    Ok((salt, nonce.into(), enc))
}

pub fn dec(master_key: &str, id: &str, ef: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let read_json = read_json(ef)?;

    let entry = if let Some(s) = read_json.iter().find(|s| s.entry.id == *id) {
        &s.entry
    } else {
        return Err(anyhow!("Couldn't get data"));
    };

    let (salt, nonce, data) = (
        BASE64_STANDARD.decode(&entry.salt)?,
        BASE64_STANDARD.decode(&entry.nonce)?,
        BASE64_STANDARD.decode(&entry.data)?,
    );

    let argon2 = Argon2::default();
    let mut out_pass = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(master_key.as_bytes(), &salt, &mut *out_pass)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&*out_pass);
    let cip = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce);

    let dec = cip
        .decrypt(nonce, data.as_ref())
        .map_err(|e| anyhow!("Couldn't dec data | try again with the correct master-key! <{e}>"))?;

    Ok(dec)
}

pub fn enc_vault(
    master_key: &str,
    _vault_: String,
) -> anyhow::Result<([u8; 16], [u8; 12], Vec<u8>)> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let argon2 = Argon2::default();
    let mut out_master = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(master_key.as_bytes(), &salt, &mut *out_master)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&*out_master);
    let cip = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let enc = cip
        .encrypt(&nonce, _vault_.as_bytes())
        .map_err(|_| anyhow!("Couldn't enc data"))?;

    Ok((salt, nonce.into(), enc))
}

fn read_json_import(ef: Option<&str>, name_of_vault: &str) -> anyhow::Result<Vec<VaultExport>> {
    let mut s = String::new();

    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    let mut o = if let Some(ef) = ef {
        fs::File::open(home_dirr()?.join(ef))?
    } else {
        fs::File::open(
            main_vault_path
                .join(name_of_vault)
                .to_string_lossy()
                .to_string(),
        )?
    };

    o.read_to_string(&mut s)?;

    if let Ok(vec) = serde_json::from_str::<VaultExport>(s.trim()) {
        Ok(vec![vec])
    } else {
        Err(anyhow!("Couldn't read json file"))
    }
}

pub fn dec_vault(master_key: &str, path_of_vault: &str) -> anyhow::Result<Vec<u8>> {
    let read_json = read_json_import(Some(path_of_vault), path_of_vault)?;

    if let Some(i) = read_json.into_iter().next() {
        let salt = i.salt;
        let nonce = i.nonce;
        let vault = i.vault;

        let (salt_decoded, nonce_decoded, vault_decoded) = (
            BASE64_STANDARD.decode(salt)?,
            BASE64_STANDARD.decode(nonce)?,
            BASE64_STANDARD.decode(vault)?,
        );

        let mut out_master = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(master_key.as_bytes(), &salt_decoded, &mut *out_master)
            .map_err(|e| anyhow!("Couldn't hash the master-key <{e}>"))?;

        let key = Key::<Aes256Gcm>::from_slice(&*out_master);
        let cip = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_decoded);

        let dec = cip.decrypt(nonce, &*vault_decoded).map_err(|e| {
            anyhow!("Couldn't dec data | try again with the correct master-key! <{e}>")
        })?;

        return Ok(dec);
    }
    Err(anyhow!(
        "Couldn't dec data | try again with the correct master-key!"
    ))
}
