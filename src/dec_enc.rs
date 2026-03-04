use anyhow::anyhow;
use base64::prelude::*;
use colored::Colorize;
use std::{
    env::home_dir,
    fs,
    io::{Read, Write, stdin, stdout},
    ops::Deref,
    path::PathBuf,
};
use zeroize::Zeroizing;

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use argon2::Argon2;
use serde::{Deserialize, Serialize};

use crate::backend::safe::AnyHowErrHelper;

#[derive(Debug, Serialize, Deserialize)]
pub struct Felids {
    pub url_app: String,
    pub data: String,
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
    ef: Option<&String>,
) -> anyhow::Result<()> {
    let password = Zeroizing::new(password);
    let master_key = Zeroizing::new(master_key);

    let data = enc(&master_key, &username_email, &password)?;

    let data = BASE64_STANDARD.encode(data);

    let cont = Felids {
        url_app: url_app.clone(),
        data: data,
    };

    let vec = vec![cont];

    let yaml = serde_yaml::to_string(&vec)?;

    if let Some(o) = ef {
        fs::File::create(o)?;
        fs::write(home_dirr()?.join(o), yaml)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(o))?;
    } else {
        fs::write(home_dirr()?.join("obsidian/obs.yaml"), yaml)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join("obsidian/obs.yaml"))?;
    }

    println!(
        ">>{}: added [{}] [{}]",
        "obsidian".bright_cyan().bold(),
        username_email.to_string().white().bold(),
        url_app.bright_white().bold()
    );
    Ok(())
}

pub fn add(
    username_email: String,
    url_app: String,
    password: String,
    master_key: String,
    ef: Option<&String>,
) -> anyhow::Result<()> {
    let password = Zeroizing::new(password);
    let master_key = Zeroizing::new(master_key);

    let mut file = read_yaml(ef).pe()?;
    let data = BASE64_STANDARD.encode(enc(&master_key, &username_email, &password)?);
    let cont = Felids {
        url_app: url_app.clone(),
        data: data,
    };

    file.push(cont);

    let yaml = serde_yaml::to_string(&file)?;

    if let Some(o) = ef {
        fs::File::create(o)?;
        fs::write(home_dirr()?.join(o), yaml)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(o))?;
    } else {
        fs::write(home_dirr()?.join("obsidian/obs.yaml"), yaml)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join("obsidian/obs.yaml"))?;
    }

    println!(
        ">>{}: added [{}] [{}]",
        "obsidian".bright_cyan().bold(),
        username_email.to_string().white().bold(),
        url_app.bright_white().bold()
    );

    Ok(())
}

pub fn get(url_app: String, master_key: String, ef: Option<&String>) -> anyhow::Result<()> {
    let master_key = Zeroizing::new(master_key);

    let dec = dec(&master_key, &url_app, ef)?;
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

pub fn read_yaml(ef: Option<&String>) -> anyhow::Result<Vec<Felids>> {
    let mut s = String::new();

    let mut o = if let Some(ef) = ef {
        let o = fs::File::open(home_dirr()?.join(ef))?;
        o
    } else {
        let o = fs::File::open(
            home_dirr()?
                .join("obsidian/obs.yaml")
                .to_string_lossy()
                .to_string(),
        )?;
        o
    };

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
    let mut out_master = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(master_key.as_bytes(), &salt, &mut *out_master)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&*out_master);
    let cip = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let format = Zeroizing::new(format!("{}|{}", username_email, password.to_string()));

    let enc = cip
        .encrypt(&nonce, format.as_bytes())
        .map_err(|_| anyhow!("Couldn't enc data"))?;

    let mut finsh = Vec::new();
    finsh.extend_from_slice(&salt);
    finsh.extend_from_slice(&nonce);
    finsh.extend_from_slice(&enc);

    Ok(finsh)
}

fn dec(master_key: &String, url_app: &String, ef: Option<&String>) -> anyhow::Result<Vec<u8>> {
    let read_yaml = read_yaml(ef)?;

    let data = if let Some(s) = read_yaml.iter().find(|s| s.url_app == *url_app) {
        s.data.trim()
    } else {
        return Err(anyhow!("Couldn't get data"));
    };

    let data = BASE64_STANDARD.decode(data)?;

    let (salt, rest) = data.split_at(16);
    let (nonce_bytes, restt) = rest.split_at(12);

    let argon2 = Argon2::default();
    let mut out_pass = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(master_key.as_bytes(), salt, &mut *out_pass)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&*out_pass);
    let cip = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let dec = cip
        .decrypt(nonce, restt)
        .map_err(|_| anyhow!("Couldn't dec data"))?;

    Ok(dec)
}

pub fn list(ef: Option<&String>) -> anyhow::Result<()> {
    let read_yaml = read_yaml(ef)?;

    for i in read_yaml {
        println!(
            ">>{} url/app <{}> | data : <{}>",
            "obsidian".bright_cyan().bold(),
            i.url_app.to_string().bright_white().bold(),
            i.data.to_string().bright_white().bold()
        );
    }

    Ok(())
}

pub fn action_pass_maker(action_pass: &str) -> anyhow::Result<()> {
    fs::create_dir_all(home_dirr()?.join("obsidian/").to_string_lossy().to_string())?;

    fs::File::create(
        home_dirr()?
            .join("obsidian/obs_password.txt")
            .to_string_lossy()
            .to_string(),
    )?;
    set_perm_over_file_read_only(&home_dirr()?.join("obsidian/obs_password.txt"))?;

    let ac_pass = action_pass.trim();

    let argon2 = Argon2::default();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut out_ac_pass = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(ac_pass.as_bytes(), &salt, &mut *out_ac_pass)
        .map_err(|_| anyhow!("Couldn't hash the password in argon2"))?;

    let mut vec = Vec::new();
    vec.extend_from_slice(&salt);
    vec.extend_from_slice(&*out_ac_pass);

    let ac_pass = BASE64_STANDARD.encode(vec);

    fs::write(
        home_dirr()?
            .join("obsidian/obs_password.txt")
            .to_string_lossy()
            .to_string(),
        ac_pass,
    )?;
    Ok(())
}

pub fn action_pass_val(action_pass: &str) -> anyhow::Result<()> {
    let mut read = fs::File::open(
        home_dirr()?
            .join("obsidian/obs_password.txt")
            .to_string_lossy()
            .to_string(),
    )?;
    let mut s = String::new();
    read.read_to_string(&mut s)?;

    let s = s.trim();

    let dec_base64 = BASE64_STANDARD.decode(&s.trim())?;

    let (salt, _) = dec_base64.split_at(16);

    let mut out_pass_ac = Zeroizing::new([0u8; 32]);
    let argon2 = Argon2::default();

    argon2
        .hash_password_into(action_pass.as_bytes(), &salt, &mut *out_pass_ac)
        .map_err(|_| anyhow!("Couldn't hash the password using argon2"))?;

    let mut vec = Vec::new();
    vec.extend_from_slice(&salt);
    vec.extend_from_slice(&*out_pass_ac);

    let enc = BASE64_STANDARD.encode(vec);

    if enc == s {
        return Ok(());
    } else {
        return Err(anyhow!(
            "the add password didn't match try agian with diffrent one!"
        ));
    }
}

pub fn remove(url_app: &String, ef: Option<&String>) -> anyhow::Result<()> {
    let mut read_yaml = read_yaml(ef)?;

    println!(
        ">> are you sure you want to delete <{}>",
        url_app.bright_red().bold(),
    );
    print!(
        ">>[{}/{}]: ",
        "y".bright_cyan().bold(),
        "n".bright_red().bold()
    );
    stdout().flush()?;

    let mut str = String::new();
    stdin().read_line(&mut str)?;

    if str.trim() == "y" {
        if let Some(o) = read_yaml.iter().position(|s| s.url_app == *url_app) {
            read_yaml.remove(o);
        }

        let yaml = serde_yaml::to_string(&read_yaml)?;

        if let Some(ef) = ef {
            fs::write(home_dirr()?.join(ef), yaml)?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join(ef))?;
        } else {
            fs::write(home_dirr()?.join("obsidian/obs.yaml"), yaml)?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join("obsidian/obs.yaml"))?;

            println!(
                ">>{} removed [{}]",
                "obsidian".bright_cyan().bold(),
                url_app.bright_white().bold()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_perm_over_file(path: &PathBuf) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let file = fs::File::open(path)?;
    let mut perm = file.metadata()?.permissions();
    perm.set_mode(0o600);

    fs::set_permissions(&path, perm)?;
    Ok(())
}

fn set_perm_over_file_read_only(path: &PathBuf) -> anyhow::Result<()> {
    let file = fs::File::open(path)?;
    let mut perm = file.metadata()?.permissions();
    perm.set_readonly(true);

    fs::set_permissions(&path, perm)?;
    Ok(())
}

pub fn search(url_app: &String, ef: Option<&String>) -> anyhow::Result<()> {
    let read_yaml = read_yaml(ef)?;

    if let Some(ry) = read_yaml.iter().find(|u| u.url_app == *url_app) {
        println!(
            ">> {} [{}] [{}]",
            "found".bright_cyan().bold(),
            ry.url_app.to_string().bright_white().bold(),
            ry.data.to_string().bright_white().bold()
        );
    }
    Ok(())
}

pub fn change(
    url_app: &String,
    ef: Option<&String>,
    master_key: &String,
    password: &String,
    username_email: &String,
) -> anyhow::Result<()> {
    let password = Zeroizing::new(password.to_string());
    let master_key = Zeroizing::new(master_key.to_string());

    let mut read_yaml_i = read_yaml(ef)?;

    if let Some(o) = read_yaml_i
        .iter_mut()
        .find(|s| s.url_app == url_app.deref())
    {
        let enc = enc(&master_key, username_email, &password)?;
        let enc = BASE64_STANDARD.encode(enc);
        o.data = enc;
        let yaml = serde_yaml::to_string(&read_yaml_i)?;
        if let Some(ef) = ef {
            fs::write(home_dirr()?.join(ef), &yaml)?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join(ef))?;
        } else {
            fs::write(
                home_dirr()?
                    .join("obsidian/obs.yaml")
                    .to_string_lossy()
                    .to_string(),
                &yaml,
            )?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join("obsidian/obs.yaml"))?;
        }
    }
    Ok(())
}
