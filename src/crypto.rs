use anyhow::anyhow;
use base64::prelude::*;
use colored::Colorize;
use std::{fs, io::Read, path::PathBuf};
use totp_rs::TOTP;
use zeroize::Zeroizing;
use sha2::Sha256;

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use argon2::Argon2;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};

use crate::{toml::toml, vault::home_dirr};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Fields {
    pub entry: Entry,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry {
    pub id: String,
    #[serde(default = "def_author")]
    pub author: String,
    pub salt: String,
    pub nonce: String,
    pub identifier: String,
    pub password: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default = "def_date")]
    pub date: String,
    pub _2fa_: _2fa_,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct _2fa_ {
    pub totp_secret: String,
    pub totp_nonce: String,
}

fn def_author() -> String {
    "def".to_string()
}

fn def_date() -> String {
    "def".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultExport {
    pub salt: String,
    pub nonce: String,
    pub _2fa_: _2fa_,
    pub vault: String,
}

pub const NONCE_SIZE: usize = 12;

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
        fs::File::open(main_vault_path)?
    };

    o.read_to_string(&mut s)?;

    if let Ok(vec) = serde_json::from_str::<Vec<Fields>>(s.trim()) {
        Ok(vec)
    } else {
        Err(anyhow!("Couldn't read json file"))
    }
}

pub type Encrypted = ([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

pub fn enc(
    master_key: &str,
    username_email: &str,
    password: &str,
    totp_s: &[u8],
) -> anyhow::Result<Encrypted> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let param = Params::new(256 * 1024, 3, 4, Some(32)).map_err(|_| {
        anyhow!("[Couldn't set argon2 perm] please dont use it if you got this err!")
    })?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, param);
    let mut out_master = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(master_key.as_bytes(), &salt, &mut *out_master)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&*out_master);
    let cip = Aes256Gcm::new(key);
    let username_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let password_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let totp_nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let username = cip
        .encrypt(&username_nonce, username_email.as_bytes())
        .map_err(|_| anyhow!("Couldn't enc data"))?;

    let password = cip
        .encrypt(&password_nonce, password.as_bytes())
        .map_err(|_| anyhow!("Couldn't enc data"))?;

    let totp_secret = cip
        .encrypt(&totp_nonce, totp_s)
        .map_err(|_| anyhow!("Couldn't enc totp secret"))?;

    let mut nonce = Vec::new();
    nonce.extend_from_slice(&password_nonce);
    nonce.extend_from_slice(&username_nonce);

    Ok((
        salt,
        nonce,
        username,
        password,
        totp_nonce.to_vec(),
        totp_secret,
    ))
}

pub fn dec(
    master_key: &str,
    id: &str,
    ef: Option<&str>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let read_json = read_json(ef)?;

    let entry = if let Some(s) = read_json.iter().find(|s| s.entry.id == *id) {
        &s.entry
    } else {
        return Err(anyhow!("Couldn't get data"));
    };

    let (salt, nonce, username, password, totp_n, totp_s) = (
        BASE64_STANDARD.decode(&entry.salt)?,
        BASE64_STANDARD.decode(&entry.nonce)?,
        BASE64_STANDARD.decode(&entry.identifier)?,
        BASE64_STANDARD.decode(&entry.password)?,
        BASE64_STANDARD.decode(&entry._2fa_.totp_nonce)?,
        BASE64_STANDARD.decode(&entry._2fa_.totp_secret)?,
    );

    let param = Params::new(256 * 1024, 3, 4, Some(32)).map_err(|_| {
        anyhow!("[Couldn't set argon2 perm] please dont use it if you got this err!")
    })?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, param);
    let mut out_pass = Zeroizing::new([0u8; 32]);
    let totp_s = Zeroizing::new(totp_s);

    argon2
        .hash_password_into(master_key.as_bytes(), &salt, &mut *out_pass)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&*out_pass);
    let cip = Aes256Gcm::new(key);

    let (password_nonce, useranme_nonce) = nonce.split_at(NONCE_SIZE);
    let password_nonce_n = Nonce::from_slice(password_nonce);
    let username_nonce_n = Nonce::from_slice(useranme_nonce);
    let totp_n = Nonce::from_slice(&totp_n);

    let username = cip
        .decrypt(username_nonce_n, username.as_ref())
        .map_err(|_| anyhow!("Couldn't dec data | try again with the correct master-key!"))?;
    let password = cip
        .decrypt(password_nonce_n, password.as_ref())
        .map_err(|_| anyhow!("Couldn't dec data | try again with the correct master-key!"))?;

    let totp_s = cip
        .decrypt(totp_n, totp_s.as_slice())
        .map_err(|_| anyhow!("Couldn't dec data | try again with the correct master-key!"))?;

    Ok((username, password, totp_s))
}

pub type EncV = ([u8; 32], [u8; 12], Vec<u8>, Vec<u8>, Vec<u8>);


pub fn enc_vault(master_key: &str, _vault_: String, _2fa_s: Vec<u8>) -> anyhow::Result<EncV> {

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let argon2 = Argon2::default();
    let mut out_master = Zeroizing::new([0u8; 32]);
    let _2fa_s = Zeroizing::new(_2fa_s);

    argon2
        .hash_password_into(master_key.as_bytes(), &salt, &mut *out_master)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let hk_c = Hkdf::<Sha256>::new(Some(&salt), &*out_master);
    let mut vault_key = [0u8;32];
    let mut totp_key = [0u8; 32];

    hk_c.expand(b"cip_vault", &mut vault_key)
        .map_err(|_| anyhow!("cip_vault failed [crypto.rs]"))?;

    hk_c.expand(b"cip_totp", &mut totp_key)
        .map_err(|_| anyhow!("cip_totp failed [crypto.rs]"))?;

    let cip_vault = Aes256Gcm::new_from_slice(&vault_key)?;
    let cip_totp  = Aes256Gcm::new_from_slice(&totp_key)?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let totp_nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let enc = cip_vault
        .encrypt(&nonce, _vault_.as_bytes())
        .map_err(|_| anyhow!("Couldn't enc data"))?;

    let totp_secret = cip_totp
        .encrypt(&totp_nonce, _2fa_s.as_slice())
        .map_err(|_| anyhow!("Couldn't enc totp secret"))?;

    Ok((salt, nonce.into(), enc, totp_nonce.to_vec(), totp_secret))
}

fn read_json_import(name_of_vault: &str) -> anyhow::Result<Vec<VaultExport>> {
    let mut s = String::new();
    let mut o = fs::File::open(
        home_dirr()?
            .join(name_of_vault)
            .to_string_lossy()
            .to_string(),
    )?;

    o.read_to_string(&mut s)?;

    if let Ok(vec) = serde_json::from_str::<VaultExport>(s.trim()) {
        Ok(vec![vec])
    } else {
        Err(anyhow!("Couldn't read json file"))
    }
}

pub fn dec_vault(master_key: &str, path_of_vault: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let read_json = read_json_import(path_of_vault)?;

    if let Some(i) = read_json.into_iter().next() {
        let salt = i.salt;
        let nonce = i.nonce;
        let vault = i.vault;
        let totp_n = i._2fa_.totp_nonce;
        let totp_s = i._2fa_.totp_secret;

        let (salt_decoded, nonce_decoded, vault_decoded, totp_n_dec, totp_s_dec) = (
            BASE64_STANDARD.decode(salt)?,
            BASE64_STANDARD.decode(nonce)?,
            BASE64_STANDARD.decode(vault)?,
            BASE64_STANDARD.decode(totp_n)?,
            BASE64_STANDARD.decode(totp_s)?,
        );

        let mut out_master = Zeroizing::new([0u8; 32]);
        let param = Params::new(256 * 1024, 3, 4, Some(32)).map_err(|_| {
            anyhow!("[Couldn't set argon2 perm] please dont use it if you got this err!")
        })?;
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, param)
            .hash_password_into(master_key.as_bytes(), &salt_decoded, &mut *out_master)
            .map_err(|e| anyhow!("Couldn't hash the master-key <{e}>"))?;

        let hk = Hkdf::<Sha256>::new(Some(&salt_decoded), &*out_master);
        let mut vault_key = [0u8;32];
        hk.expand(b"cip_vault", &mut vault_key)
            .map_err(|_| anyhow!("HKDF failed [crypto.rs]"))?;

        let mut totp_key = [0u8; 32];
        hk.expand(b"cip_totp", &mut totp_key)
            .map_err(|_| anyhow!("HKDF failed [crypto.rs]"))?;

        let cip_vault = Aes256Gcm::new_from_slice(&vault_key)?;
        let cip_totp = Aes256Gcm::new_from_slice(&totp_key)?;

        let nonce = Nonce::from_slice(&nonce_decoded);
        let nonce_totp = Nonce::from_slice(&totp_n_dec);

        let totp_s = Zeroizing::new(totp_s_dec);

        let dec = cip_vault.decrypt(nonce, &*vault_decoded).map_err(|_| {
            anyhow!("Couldn't dec data").context("try again with the correct master-key!")
        })?;

        let totp_s = cip_totp.decrypt(nonce_totp, totp_s.as_slice()).map_err(|_| {
            anyhow!("Couldn't dec data").context("try again with the correct master-key!")
        })?;

        return Ok((dec, totp_s));
    }
    Err(anyhow!(
        "Couldn't dec data | try again with the correct master-key!"
    ))
}

pub fn _2fa_auth(raw_s_totp: &[u8], id: &str) -> anyhow::Result<()> {
    let totp = TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        raw_s_totp.to_vec(),
        Some("diamond".to_string()),
        id.to_string(),
    )?;

    let code = rpassword::prompt_password(format!(
        ">>Enter 2fa code for <{}>: ",
        id.bright_yellow().bold()
    ))?;

    if totp.check_current(&code)? {
        println!(">>{}", "verified!".bright_green().bold());
        Ok(())
    } else {
        Err(anyhow!("Invalid 2fa code!"))
    }
}
