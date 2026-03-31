use anyhow::anyhow;
use base64::prelude::*;
use colored::Colorize;
use hkdf::Hkdf;
use hmac::Mac;
use sha2::Sha256;
use std::{fs, io::Read, path::PathBuf};
use totp_rs::TOTP;
use zeroize::Zeroizing;

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use argon2::Argon2;

#[cfg(not(feature = "dev"))]
use argon2::Params;

use serde::{Deserialize, Serialize};

use crate::{commands::ef_validator, toml::toml, vault::home_dirr};

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
    pub mac: String,
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
    #[serde(default = "def_author")]
    pub id: String,
    #[serde(default = "def_author")]
    pub author: String,
    pub salt: String,
    pub nonce: String,
    pub _2fa_: _2fa_,
    pub vault: String,
    pub mac: String,
    #[serde(default = "def_author")]
    pub date: String,
}

pub const NONCE_SIZE: usize = 12;

pub fn read_json(ef: Option<&str>) -> anyhow::Result<Vec<Fields>> {
    let mut s = String::new();

    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    let mut o = if let Some(ef) = ef {
        let mut ef: PathBuf = ef.into();
        if let Some(efc) = ef_validator(&ef)? {
            ef = efc;
        }

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

pub type Encrypted = (
    [u8; 32],
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);
pub type HamcSha256 = hmac::Hmac<Sha256>;

pub fn enc(
    master_key: &str,
    username_email: &str,
    password: &str,
    totp_s: &[u8],
    id: &str,
) -> anyhow::Result<Encrypted> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let mut out_master = Zeroizing::new([0u8; 32]);

    #[cfg(not(feature = "dev"))]
    {
        let param = Params::new(256 * 1024, 3, 4, Some(32)).map_err(|_| {
            anyhow!("[Couldn't set argon2 perm] please dont use it if you got this err!")
        })?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, param);
        argon2
            .hash_password_into(master_key.as_bytes(), &salt, &mut *out_master)
            .map_err(|_| anyhow!("Couldn't hash master key"))?;
    }

    #[cfg(feature = "dev")]
    {
        let argon2 = Argon2::default();
        argon2
            .hash_password_into(master_key.as_bytes(), &salt, &mut *out_master)
            .map_err(|_| anyhow!("Couldn't hash master key"))?;
    }

    let (id_key, mac_key, totp_key, password_key) = derive_keys(&out_master, salt.as_ref())?;

    let id_key = Key::<Aes256Gcm>::from_slice(&*id_key);
    let id_cip = Aes256Gcm::new(id_key);

    let password_key = Key::<Aes256Gcm>::from_slice(&*password_key);
    let password_cip = Aes256Gcm::new(password_key);

    let username_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let password_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let totp_nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let key_totp = Key::<Aes256Gcm>::from_slice(&*totp_key);
    let cip_totp = Aes256Gcm::new(key_totp);

    let username = id_cip
        .encrypt(&username_nonce, username_email.as_bytes())
        .map_err(|_| anyhow!("Couldn't enc data"))?;

    let password = password_cip
        .encrypt(&password_nonce, password.as_bytes())
        .map_err(|_| anyhow!("Couldn't enc data"))?;

    let totp_secret = cip_totp
        .encrypt(&totp_nonce, totp_s)
        .map_err(|_| anyhow!("Couldn't enc totp secret"))?;

    let mut nonce = Vec::new();
    nonce.extend_from_slice(&password_nonce);
    nonce.extend_from_slice(&username_nonce);

    let mut all = Vec::new();
    all.extend_from_slice(&salt);
    all.extend_from_slice(&nonce);
    all.extend_from_slice(&username);
    all.extend_from_slice(&password);
    all.extend_from_slice(&totp_nonce);
    all.extend_from_slice(&totp_secret);
    all.extend_from_slice(id.as_bytes());

    let mut mac = <HamcSha256 as Mac>::new_from_slice(&*mac_key)?;
    mac.update(&all);
    let mac_final = mac.finalize().into_bytes().to_vec();

    Ok((
        salt,
        nonce,
        username,
        password,
        totp_nonce.to_vec(),
        totp_secret,
        mac_final,
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

    let (salt, nonce, username, password, totp_n, totp_s, mac) = (
        BASE64_STANDARD.decode(&entry.salt)?,
        BASE64_STANDARD.decode(&entry.nonce)?,
        BASE64_STANDARD.decode(&entry.identifier)?,
        BASE64_STANDARD.decode(&entry.password)?,
        BASE64_STANDARD.decode(&entry._2fa_.totp_nonce)?,
        BASE64_STANDARD.decode(&entry._2fa_.totp_secret)?,
        BASE64_STANDARD.decode(&entry.mac)?,
    );

    let mut out_pass = Zeroizing::new([0u8; 32]);
    let totp_s = Zeroizing::new(totp_s);

    #[cfg(not(feature = "dev"))]
    {
        let param = Params::new(256 * 1024, 3, 4, Some(32)).map_err(|_| {
            anyhow!("[Couldn't set argon2 perm] please dont use it if you got this err!")
        })?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, param);

        argon2
            .hash_password_into(master_key.as_bytes(), &salt, &mut *out_pass)
            .map_err(|_| anyhow!("Couldn't hash master key"))?;
    }

    #[cfg(feature = "dev")]
    {
        let argon2 = Argon2::default();

        argon2
            .hash_password_into(master_key.as_bytes(), &salt, &mut *out_pass)
            .map_err(|_| anyhow!("Couldn't hash master key"))?;
    }

    let (id_key, mac_key, totp_key, password_key) = derive_keys(&out_pass, &salt)?;

    if !mac.is_empty() {
        let mut data = Vec::new();
        data.extend_from_slice(&salt);
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&username);
        data.extend_from_slice(&password);
        data.extend_from_slice(&totp_n);
        data.extend_from_slice(&totp_s);
        data.extend_from_slice(entry.id.as_bytes());

        let mut mac_new = <HamcSha256 as Mac>::new_from_slice(&*mac_key)?;
        mac_new.update(&data);
        mac_new
            .verify_slice(&mac)
            .map_err(|_| anyhow!("Integrity check failed! Vault may have been tampered with."))?;
    } else {
        return Err(anyhow!("MAC was not found!"));
    }

    let id_key = Key::<Aes256Gcm>::from_slice(&*id_key);
    let id_cip = Aes256Gcm::new(id_key);

    let password_key = Key::<Aes256Gcm>::from_slice(&*password_key);
    let password_cip = Aes256Gcm::new(password_key);

    let key_totp = Key::<Aes256Gcm>::from_slice(&*totp_key);
    let cip_totp = Aes256Gcm::new(key_totp);

    let (password_nonce, useranme_nonce) = nonce.split_at(NONCE_SIZE);
    let password_nonce_n = Nonce::from_slice(password_nonce);
    let username_nonce_n = Nonce::from_slice(useranme_nonce);
    let totp_n = Nonce::from_slice(&totp_n);

    let username = id_cip
        .decrypt(username_nonce_n, username.as_ref())
        .map_err(|_| anyhow!("Couldn't dec data | try again with the correct master-key!"))?;
    let password = password_cip
        .decrypt(password_nonce_n, password.as_ref())
        .map_err(|_| anyhow!("Couldn't dec data | try again with the correct master-key!"))?;

    let totp_s = cip_totp
        .decrypt(totp_n, totp_s.as_slice())
        .map_err(|_| anyhow!("Couldn't dec data | try again with the correct master-key!"))?;

    Ok((username, password, totp_s))
}

pub type EncV = ([u8; 32], [u8; 12], Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

pub fn enc_vault(master_key: &str, _vault_: String, _2fa_s: Vec<u8>) -> anyhow::Result<EncV> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let mut out_master = Zeroizing::new([0u8; 32]);
    let _2fa_s = Zeroizing::new(_2fa_s);

    #[cfg(feature = "dev")]
    {
        let argon2 = Argon2::default();
        argon2
            .hash_password_into(master_key.as_bytes(), &salt, &mut *out_master)
            .map_err(|_| anyhow!("Couldn't hash master key"))?;
    }

    #[cfg(not(feature = "dev"))]
    {
        let param = Params::new(256 * 1024, 3, 4, Some(32)).map_err(|_| {
            anyhow!("[Couldn't set argon2 perm] please dont use it if you got this err!")
        })?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, param);
        argon2
            .hash_password_into(master_key.as_bytes(), &salt, &mut *out_master)
            .map_err(|_| anyhow!("Couldn't hash master key"))?;
    }

    let (enc_key, mac_key, totp_key, _) = derive_keys(&out_master, salt.as_ref())?;

    let key = Key::<Aes256Gcm>::from_slice(&*enc_key);
    let cip = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let totp_nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let key_totp = Key::<Aes256Gcm>::from_slice(&*totp_key);
    let cip_totp = Aes256Gcm::new(key_totp);

    let mut new_mac = <HamcSha256 as Mac>::new_from_slice(&*mac_key)?;

    let enc = cip
        .encrypt(&nonce, _vault_.as_bytes())
        .map_err(|_| anyhow!("Couldn't enc data"))?;

    let totp_secret = cip_totp
        .encrypt(&totp_nonce, _2fa_s.as_slice())
        .map_err(|_| anyhow!("Couldn't enc totp secret"))?;

    let mut data = Vec::new();
    data.extend_from_slice(&salt);
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&enc);
    data.extend_from_slice(&totp_nonce);
    data.extend_from_slice(&totp_secret);

    new_mac.update(&data);

    let macc = new_mac.finalize().into_bytes().to_vec();

    Ok((
        salt,
        nonce.into(),
        enc,
        totp_nonce.to_vec(),
        totp_secret,
        macc,
    ))
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
        let mac = i.mac;

        let (salt_decoded, nonce_decoded, vault_decoded, totp_n_dec, totp_s_dec, mac) = (
            BASE64_STANDARD.decode(salt)?,
            BASE64_STANDARD.decode(nonce)?,
            BASE64_STANDARD.decode(vault)?,
            BASE64_STANDARD.decode(totp_n)?,
            BASE64_STANDARD.decode(totp_s)?,
            BASE64_STANDARD.decode(mac)?,
        );

        let mut out_master = Zeroizing::new([0u8; 32]);
        let totp_s = Zeroizing::new(totp_s_dec);

        #[cfg(feature = "dev")]
        {
            let argon2 = Argon2::default();
            argon2
                .hash_password_into(master_key.as_bytes(), &salt_decoded, &mut *out_master)
                .map_err(|e| anyhow!("Couldn't hash the master-key <{e}>"))?;
        }

        #[cfg(not(feature = "dev"))]
        {
            let param = Params::new(256 * 1024, 3, 4, Some(32)).map_err(|_| {
                anyhow!("[Couldn't set argon2 perm] please dont use it if you got this err!")
            })?;
            Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, param)
                .hash_password_into(master_key.as_bytes(), &salt_decoded, &mut *out_master)
                .map_err(|e| anyhow!("Couldn't hash the master-key <{e}>"))?;
        }

        let (enc_key, mac_key, totp_key, _) = derive_keys(&out_master, &salt_decoded)?;

        let key = Key::<Aes256Gcm>::from_slice(&*enc_key);
        let cip = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_decoded);
        let nonce_totp = Nonce::from_slice(&totp_n_dec);

        let key_totp = Key::<Aes256Gcm>::from_slice(&*totp_key);
        let cip_totp = Aes256Gcm::new(key_totp);

        if !mac.is_empty() {
            let mut data = Vec::new();
            data.extend_from_slice(&salt_decoded);
            data.extend_from_slice(&nonce_decoded);
            data.extend_from_slice(&vault_decoded);
            data.extend_from_slice(&totp_n_dec);
            data.extend_from_slice(&totp_s);

            let mut mac_new = <HamcSha256 as Mac>::new_from_slice(&*mac_key)?;
            mac_new.update(&data);

            mac_new.verify_slice(&mac).map_err(|_| {
                anyhow!("Integrity check failed! Vault may have been tampered with.")
            })?
        } else {
            return Err(anyhow!("MAC was not found!"));
        }

        let dec = cip.decrypt(nonce, &*vault_decoded).map_err(|_| {
            anyhow!("Couldn't dec data").context("try again with the correct master-key!")
        })?;

        let totp_s = cip_totp
            .decrypt(nonce_totp, totp_s.as_slice())
            .map_err(|_| {
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

    if code.len() < 6 {
        return Err(anyhow!("The TOTP must be 6 digits"));
    }

    if totp.check_current(&code)? {
        println!(">>{}", "verified!".bright_green().bold());
        Ok(())
    } else {
        Err(anyhow!("Invalid 2fa code!"))
    }
}

pub fn reshow_2fa_key(raw_s_totp: &[u8], id: &str) -> anyhow::Result<String> {
    let totp = TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        raw_s_totp.to_vec(),
        None,
        id.to_string(),
    )?;

    let code = totp.get_secret_base32();
    Ok(code)
}

type Keys = (
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
);

pub fn derive_keys(key: &[u8; 32], salt: &[u8]) -> anyhow::Result<Keys> {
    let hk = Hkdf::<Sha256>::new(Some(salt), key);

    let mut mac_key = Zeroizing::new([0u8; 32]);
    let mut id_key = Zeroizing::new([0u8; 32]);
    let mut totp_key = Zeroizing::new([0u8; 32]);
    let mut password_key = Zeroizing::new([0u8; 32]);

    hk.expand(b"diamond-mac-key", &mut *mac_key)
        .map_err(|_| anyhow!("Couldn't drive keys !"))?;

    hk.expand(b"diamond-id-key", &mut *id_key)
        .map_err(|_| anyhow!("Couldn't drive keys !"))?;

    hk.expand(b"diamond-totp-key", &mut *totp_key)
        .map_err(|_| anyhow!("Couldn't drive keys !"))?;

    hk.expand(b"diamond-password-key", &mut *password_key)
        .map_err(|_| anyhow!("Couldn't drive keys !"))?;

    Ok((mac_key, id_key, totp_key, password_key))
}
