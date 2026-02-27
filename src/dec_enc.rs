use std::{env::home_dir, fs, io::Read, path::PathBuf};

use anyhow::anyhow;
use base64::prelude::*;
use colored::Colorize;

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use argon2::Argon2;
use serde::{Deserialize, Serialize};

use crate::backend::safe::AnyHowErrHelper;

#[derive(Debug, Serialize, Deserialize)]
struct Felids {
    url_app: String,
    data: String,
}

pub fn home_dirr() -> anyhow::Result<PathBuf> {
    let home_dir = if let Some(h) = home_dir() {
        h
    } else {
        return Err(anyhow!("couldn't find home dir"));
    };

    Ok(home_dir)
}

pub fn _pre_() -> anyhow::Result<()> {
    let home_dir = home_dirr()?;
    fs::create_dir_all(home_dir.join("obsidian").to_string_lossy().to_string())?;
    Ok(())
}

pub fn pre_add(
    username_email: String,
    url_app: String,
    password: String,
    master_key: String,
) -> anyhow::Result<()> {
    let data = enc(&master_key, &username_email, &password)?;

    let data = BASE64_STANDARD.encode(data);

    let cont = Felids {
        url_app: url_app.clone(),
        data: data,
    };

    let vec = vec![cont];

    let yaml = serde_yaml::to_string(&vec)?;

    fs::write(home_dirr()?.join("obsidian/obs.yaml"), yaml)?;

    println!(
        ">>{}: added [{}] [{}] [{}]",
        "obsidian".bright_cyan().bold(),
        username_email.to_string().white().bold(),
        password.bright_white().bold(),
        url_app.bright_white().bold()
    );

    Ok(())
}

pub fn add(
    username_email: String,
    url_app: String,
    password: String,
    master_key: String,
) -> anyhow::Result<()> {
    let mut file = read_yaml().pe()?;
    let data = BASE64_STANDARD.encode(enc(&master_key, &username_email, &password)?);
    let cont = Felids {
        url_app: url_app.clone(),
        data: data,
    };

    file.push(cont);

    let yaml = serde_yaml::to_string(&file)?;
    fs::write(home_dirr()?.join("obsidian/obs.yaml"), yaml)?;

    println!(
        ">>{}: added [{}] [{}] [{}]",
        "obsidian".bright_cyan().bold(),
        username_email.to_string().white().bold(),
        password.bright_white().bold(),
        url_app.bright_white().bold()
    );

    Ok(())
}

pub fn get(url_app: String, master_key: String) -> anyhow::Result<()> {
    let dec = dec(&master_key, &url_app)?;
    let dec = String::from_utf8(dec)?;
    let decc: Vec<String> = dec.split('|').map(|s| s.to_string()).collect();

    println!(
        ">>{}: got [{}] [{}] [{}]",
        "obsidian".bright_cyan().bold(),
        url_app.to_string().white().bold(),
        decc[0].bright_white().bold(),
        decc[1].bright_white().bold()
    );
    Ok(())
}

fn read_yaml() -> anyhow::Result<Vec<Felids>> {
    let mut s = String::new();
    let mut o = fs::File::open(
        home_dirr()?
            .join("obsidian/obs.yaml")
            .to_string_lossy()
            .to_string(),
    )?;
    o.read_to_string(&mut s)?;

    if let Ok(vec) = serde_yaml::from_str::<Vec<Felids>>(&mut s) {
        return Ok(vec);
    } else {
        return Err(anyhow!("Couldn't read yaml file"));
    }
}

fn enc(master_key: &String, username_email: &String, password: &String) -> anyhow::Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let argon2 = Argon2::default();
    let mut out_master = [0u8; 32];

    argon2
        .hash_password_into(master_key.as_bytes(), &salt, &mut out_master)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&out_master);
    let cip = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let format = format!("{}|{}", username_email, password);

    let enc = cip
        .encrypt(&nonce, format.as_bytes())
        .map_err(|_| anyhow!("Couldn't enc data"))?;

    let mut finsh = Vec::new();
    finsh.extend_from_slice(&salt);
    finsh.extend_from_slice(&nonce);
    finsh.extend_from_slice(&enc);

    Ok(finsh)
}

fn dec(master_key: &String, url_app: &String) -> anyhow::Result<Vec<u8>> {
    let read_yaml = read_yaml()?;

    let data = if let Some(s) = read_yaml.iter().find(|s| s.url_app == *url_app) {
        s.data.trim()
    } else {
        return Err(anyhow!("Couldn't get data"));
    };

    let data = BASE64_STANDARD.decode(data)?;

    let (salt, rest) = data.split_at(16);
    let (nonce_bytes, restt) = rest.split_at(12);

    let argon2 = Argon2::default();
    let mut out_pass = [0u8; 32];

    argon2
        .hash_password_into(master_key.as_bytes(), salt, &mut out_pass)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&out_pass);
    let cip = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let dec = cip
        .decrypt(nonce, restt)
        .map_err(|_| anyhow!("Couldn't dec data"))?;

    Ok(dec)
}
