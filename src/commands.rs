use anyhow::anyhow;
use base64::prelude::*;
use colored::Colorize;
use qrcode::{
    QrCode,
    render::unicode::{self},
};
use rand::RngExt;
use std::{
    fs,
    io::{Read, Write, stdin, stdout},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

use crate::crypto::{_2fa_auth, Entry, Fields, dec, enc, read_json, reshow_2fa_key};
use crate::{
    backend::safe::AnyHowErrHelper,
    crypto::{self, dec_vault, enc_vault},
    toml::toml,
    vault::home_dirr,
};

#[cfg(unix)]
use crate::vault::set_perm_over_file;

pub fn add(
    username_email: &str,
    id: &str,
    password: &str,
    master_key: &str,
    note: Option<&str>,
    ef: Option<&str>,
    _2fa_raw_s: Vec<u8>,
) -> anyhow::Result<()> {
    let password = if password == "gp" {
        //we recommend the password to be 32 characters
        generate_password(Some("32".to_string()))?
    } else {
        password.to_string()
    };

    let password = Zeroizing::new(password.to_string());
    let master_key = Zeroizing::new(master_key.to_string());
    let _2fa_ = Zeroizing::new(_2fa_raw_s);
    let mut file = read_json(ef).pe()?;

    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    let enc = enc(&master_key, username_email, &password, &_2fa_, id)?;

    let (salt, nonce, username, password, _2fa_n, _2fa_s, mac) = (
        BASE64_STANDARD.encode(enc.0),
        BASE64_STANDARD.encode(enc.1),
        BASE64_STANDARD.encode(enc.2),
        BASE64_STANDARD.encode(enc.3),
        BASE64_STANDARD.encode(enc.4),
        BASE64_STANDARD.encode(enc.5),
        BASE64_STANDARD.encode(enc.6),
    );

    let date_of_adding = chrono::Local::now().to_string();
    let author = toml()?.customization.username;

    let content = Fields {
        entry: Entry {
            id: id.to_string(),
            author,
            salt,
            nonce,
            identifier: username,
            password,
            note: note.map(String::from),
            date: date_of_adding,
            _2fa_: crypto::_2fa_ {
                totp_secret: _2fa_s,
                totp_nonce: _2fa_n,
            },
            mac,
        },
    };

    file.push(content);

    let json = serde_json::to_string_pretty(&file)?;

    if let Some(o) = ef {
        let mut o = PathBuf::from(o);

        if let Some(s) = ef_validator(&o)? {
            o = s;
        }

        atomic_writer(&home_dirr()?.join(&o), &json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(o))?;
    } else {
        atomic_writer(&main_vault_path, &json)?;
        #[cfg(unix)]
        set_perm_over_file(&main_vault_path)?;
    }

    println!(
        ">>{}: added [{}] [{}]",
        "diamond".bright_cyan().bold(),
        username_email.to_string().bright_white().bold(),
        id.bright_white().bold()
    );

    Ok(())
}

#[derive(Debug)]
pub struct Flags {
    pub clip: Option<bool>,
    pub encodded: Option<bool>,
    pub qrcode: Option<bool>,
    pub totp: Option<bool>,
}

pub fn get(id: &str, master_key: &str, flags: Flags, ef: Option<&str>) -> anyhow::Result<()> {
    let master_key = Zeroizing::new(master_key.to_string());

    let dec = dec(&master_key, id, ef)
        .map_err(|_| anyhow!("invalid master key please try again later"))?;

    let username = String::from_utf8(dec.0)?;
    let password = String::from_utf8(dec.1)?;
    let totp_s = dec.2;

    _2fa_auth(&totp_s, id)?;

    if matches!(flags.clip, Some(false))
        && matches!(flags.encodded, Some(false))
        && matches!(flags.qrcode, Some(false))
        && matches!(flags.totp, Some(false))
    {
        println!(
            ">>{}: got [{}] [{}] [{}]",
            "diamond".bright_cyan().bold(),
            id.to_string().white().bold(),
            &username.bright_white().bold(),
            &password.bright_white().bold()
        )
    }

    if let Some(clipboard_or_without) = flags.clip
        && clipboard_or_without
    {
        terminal_clipboard::set_string(&password)
            .map_err(|_| anyhow!("Clouldn't copy to clipboard!"))?;

        println!(
            ">>{}: got [{}] [{}]",
            "diamond".bright_cyan().bold(),
            id.to_string().white().bold(),
            &username.bright_white().bold(),
        );
    }

    if let Some(qrcode) = flags.qrcode
        && qrcode
    {
        let qrcode = QrCode::new(format!("{}|{}", username, password).as_bytes())?;
        let string_qr = qrcode
            .render::<unicode::Dense1x2>()
            .max_dimensions(1, 1)
            .quiet_zone(false)
            .build();

        println!("{}", string_qr)
    }

    if let Some(with_hex) = flags.encodded
        && with_hex
    {
        let encoded = hex::encode(format!("{}|{}", username, password));
        println!(
            ">>{}: got [{}] [{}]",
            "diamond".bright_cyan().bold(),
            id.to_string().white().bold(),
            &encoded.bright_white().bold()
        );
    }

    if let Some(totp) = flags.totp
        && totp
    {
        let totp = reshow_2fa_key(&totp_s, id)?;
        println!(">>totp key [{}]", totp.bright_purple().bold());
    }
    Ok(())
}
pub fn list(ef: Option<&str>) -> anyhow::Result<()> {
    let read_json = read_json(ef)?;

    for i in read_json {
        if let Some(note) = i.entry.note {
            println!(
                ">>{} id <{}> | note : <{}> | date: <{}>",
                "diamond".bright_cyan().bold(),
                i.entry.id.to_string().bright_white().bold(),
                note.to_string().bright_white().bold(),
                i.entry.date.to_string().bright_white().bold(),
            );
        } else {
            println!(
                ">>{} id <{}> | date: <{}>",
                "diamond".bright_cyan().bold(),
                i.entry.id.to_string().bright_white().bold(),
                i.entry.date.to_string().bright_white().bold(),
            );
        }
    }

    Ok(())
}
pub fn remove(id: &str, ef: Option<&str>) -> anyhow::Result<()> {
    let mut read_json = read_json(ef)?;
    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    println!(
        ">> are you sure you want to delete <{}>",
        id.bright_red().bold(),
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
        if let Some(o) = read_json.iter().position(|s| s.entry.id == *id) {
            read_json.remove(o);
        }

        let json = serde_json::to_string_pretty(&read_json)?;

        if let Some(ef) = ef {
            atomic_writer(&home_dirr()?.join(ef), &json)?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join(ef))?;
        } else {
            atomic_writer(&main_vault_path, &json)?;
            #[cfg(unix)]
            set_perm_over_file(&main_vault_path)?;
        }
        println!(
            ">>{} removed [{}]",
            "diamond".bright_cyan().bold(),
            id.bright_white().bold()
        );
    }
    Ok(())
}
pub fn search(id: &str, ef: Option<&str>) -> anyhow::Result<()> {
    let read_json = read_json(ef)?;

    if let Some(ry) = read_json.iter().find(|u| u.entry.id == *id) {
        if let Some(note) = &ry.entry.note {
            println!(
                ">> {} [{}] [{}] [{}]",
                "found".bright_cyan().bold(),
                ry.entry.id.to_string().bright_white().bold(),
                ry.entry.date.to_string().bright_white().bold(),
                note.bright_white().bold()
            );
        } else {
            println!(
                ">> {} [{}] [{}]",
                "found".bright_cyan().bold(),
                ry.entry.id.to_string().bright_white().bold(),
                ry.entry.date.to_string().bright_white().bold(),
            );
        }
    }
    Ok(())
}
pub fn generate_password(len: Option<String>) -> anyhow::Result<String> {
    let len = if let Some(len) = len {
        len.trim().parse::<u32>()?
    } else {
        32
    };

    if len < 16 {
        return Err(anyhow!(
            "the password length cannot be lesser than 16 characters "
        ));
    }

    use rand::distr::Alphanumeric;
    let gen_pass: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len as usize)
        .map(char::from)
        .collect();

    println!(
        ">> {} <{}>",
        "generated password".bright_white().bold(),
        gen_pass.bright_yellow().bold()
    );
    Ok(gen_pass)
}

pub fn export(
    ef: Option<&str>,
    name_of_export: &str,
    master_key: &str,
    _2fa_raw_s: Vec<u8>,
) -> anyhow::Result<()> {
    let mut name_of_export: PathBuf = name_of_export.into();

    if let Some(s) = export_import_name_validotor(&name_of_export)? {
        name_of_export = s;
    }

    let mut vault = String::new();
    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();
    let master_key = Zeroizing::new(master_key.to_string());
    if let Some(ef) = ef {
        let mut ef = PathBuf::from(ef);

        if let Some(s) = ef_validator(&ef)? {
            ef = s;
        }

        fs::File::open(home_dirr()?.join(ef))?.read_to_string(&mut vault)?;
    } else {
        fs::File::open(main_vault_path)?.read_to_string(&mut vault)?;
    };

    let (salt, nonce, data, _2fa_n, _2fa_s, mac) = enc_vault(&master_key, vault, _2fa_raw_s)?;
    let (
        encoded_salt,
        encoded_nonce,
        encoded_vault,
        encoded_nonce_totp,
        encoded_secret_totp,
        encoded_mac,
    ) = (
        BASE64_STANDARD.encode(salt),
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(data),
        BASE64_STANDARD.encode(_2fa_n),
        BASE64_STANDARD.encode(_2fa_s),
        BASE64_STANDARD.encode(mac),
    );

    let date_of_adding = chrono::Local::now().to_string();

    let content = crypto::VaultExport {
        id: name_of_export.to_string_lossy().to_string(),
        author: toml()?.customization.username,
        salt: encoded_salt,
        nonce: encoded_nonce,
        _2fa_: crypto::_2fa_ {
            totp_secret: encoded_secret_totp,
            totp_nonce: encoded_nonce_totp,
        },
        vault: encoded_vault,
        mac: encoded_mac,
        date: date_of_adding,
    };
    let json = serde_json::to_string_pretty(&content)?;
    atomic_writer(&home_dirr()?.join(&name_of_export), &json)?;
    #[cfg(unix)]
    set_perm_over_file(&home_dirr()?.join(&name_of_export))?;

    println!(">>{}", "exporting is done!".bright_cyan().bold());
    Ok(())
}

pub fn import(master_key: &str, new_name: &str, path_of_vault: &str) -> anyhow::Result<()> {
    let mut new_name: PathBuf = new_name.into();

    if let Some(s) = export_import_name_validotor(&new_name)? {
        new_name = s;
    }

    let master_key = Zeroizing::new(master_key.to_string());
    let (dec, totp_s) = dec_vault(master_key.as_str(), path_of_vault)?;
    let dec: String = String::from_utf8(dec)?;
    _2fa_auth(&totp_s, path_of_vault)?;
    let json_args = serde_json::from_str::<Vec<Fields>>(dec.trim())?;
    let json = serde_json::to_string_pretty(&json_args)?;
    atomic_writer(&home_dirr()?.join(&new_name), &json)?;
    #[cfg(unix)]
    set_perm_over_file(&home_dirr()?.join(&new_name))?;
    Ok(())
}

pub fn atomic_writer(path: &PathBuf, content: &str) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, content)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn update(
    master_key: &str,
    ef: Option<&str>,
    id: &str,
    new_user_name: &str,
    new_password: &str,
) -> anyhow::Result<()> {
    let master_key = Zeroizing::new(master_key.to_string());
    let new_password = Zeroizing::new(new_password.to_string());

    let mut read_json = read_json(ef)?;

    let dec = dec(&master_key, id, ef)
        .map_err(|_| anyhow!("Incorrect master-key!"))
        .pe()?;

    let _2fa_ = dec.2;
    _2fa_auth(&_2fa_, id)?;

    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    if let Some(new) = read_json.iter_mut().find(|s| s.entry.id == id) {
        let enc = enc(&master_key, new_user_name, &new_password, &_2fa_, id)?;
        let (salt, nonce, username, password, totp_n, totp_s, mac) = (
            BASE64_STANDARD.encode(enc.0),
            BASE64_STANDARD.encode(enc.1),
            BASE64_STANDARD.encode(enc.2),
            BASE64_STANDARD.encode(enc.3),
            BASE64_STANDARD.encode(enc.4),
            BASE64_STANDARD.encode(enc.5),
            BASE64_STANDARD.encode(enc.6),
        );

        new.entry.identifier = username;
        new.entry.password = password;
        new.entry.salt = salt;
        new.entry.nonce = nonce;
        new.entry._2fa_.totp_nonce = totp_n;
        new.entry._2fa_.totp_secret = totp_s;
        new.entry.mac = mac;
    }

    let json = serde_json::to_string_pretty(&read_json)?;

    if let Some(ef) = ef {
        atomic_writer(&home_dirr()?.join(ef), &json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(ef))?;
    } else {
        atomic_writer(&main_vault_path, &json)?;
        #[cfg(unix)]
        set_perm_over_file(&main_vault_path)?;
    }

    println!(
        ">>{}",
        "update completed successfully!".bright_cyan().bold()
    );
    Ok(())
}

pub fn note(id: &str, note: &str, ef: Option<&str>) -> anyhow::Result<()> {
    let mut read_json = read_json(ef)?;
    let main_valut: PathBuf = toml()?.dependencies.main_vault_path.into();

    if let Some(notee) = read_json.iter_mut().find(|s| s.entry.id == id) {
        notee.entry.note = Some(note.to_string());
    } else {
        return Err(anyhow!("the id <{}> was not found", id));
    }

    let json = serde_json::to_string_pretty(&read_json)?;

    if let Some(ef) = ef {
        atomic_writer(&home_dirr()?.join(ef), &json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(ef))?;
    } else {
        atomic_writer(&main_valut, &json)?;
        #[cfg(unix)]
        set_perm_over_file(&main_valut)?;
    }
    println!(">>{}", "Note changed/added".bright_cyan().bold());
    Ok(())
}

pub fn fuzzy(keyword: &str, ef: Option<&str>) -> anyhow::Result<()> {
    let read_json = read_json(ef)?;

    for i in read_json {
        let note = if let Some(s) = i.entry.note {
            s.to_string()
        } else {
            String::new()
        };

        if i.entry.id.contains(keyword) {
            println!(
                ">>{} >{}: {} | {}: {} | {}: {}<",
                "Found".bright_blue().bold(),
                "id".bright_yellow().bold(),
                i.entry.id.bright_blue().bold(),
                "note".bright_yellow().bold(),
                note.bright_blue().bold(),
                "date".bright_yellow().bold(),
                i.entry.date.bright_blue().bold(),
            )
        }
    }
    Ok(())
}

pub fn switch_vault(valt_path: &str) -> anyhow::Result<()> {
    extern crate toml as tata;
    let mut toml = toml()?;

    toml.dependencies.main_vault_path = home_dirr()?.join(valt_path).to_string_lossy().to_string();
    let toml_to_string = tata::to_string(&toml)?;

    let vault = fs::File::open(toml.dependencies.main_vault_path)
        .map_err(|_| anyhow!(">>Vault Not Found!"))?;

    if vault.metadata()?.is_dir() {
        return Err(anyhow!(">>The vault can not be a directory!"));
    }

    if !valt_path.contains(".json") {
        return Err(anyhow!(">>The vault must be a json file only!"));
    }

    atomic_writer(&toml.dependencies.toml_path.into(), &toml_to_string)?;

    println!(
        ">>{} to >{}<",
        "switched".bright_blue().bold(),
        valt_path.bright_yellow().bold()
    );
    Ok(())
}

pub fn ef_validator(ef: &Path) -> anyhow::Result<Option<PathBuf>> {
    let ef_with_ex = if !ef.ends_with(".json") {
        ef.with_extension(".json")
    } else {
        return Err(anyhow!("the external file must end with (.json)"));
    };

    if ef
        .to_string_lossy()
        .to_string()
        .contains(home_dirr()?.to_string_lossy().to_string().trim())
    {
        return Err(anyhow!(
            "the external file must start with it's name or it's location in the home directory"
        ));
    }
    Ok(Some(ef_with_ex))
}

pub fn export_import_name_validotor(name: &Path) -> anyhow::Result<Option<PathBuf>> {
    let ef_with_ex = if !name.ends_with(".json") {
        name.with_extension(".json")
    } else {
        return Err(anyhow!("the name of the file must end with (.json)"));
    };

    if name
        .to_string_lossy()
        .to_string()
        .contains(home_dirr()?.to_string_lossy().to_string().trim())
    {
        return Err(anyhow!(
            "the file must start with it's name or it's location in the home directory"
        ));
    }

    Ok(Some(ef_with_ex))
}
