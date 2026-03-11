use anyhow::anyhow;
use base64::prelude::*;
use colored::Colorize;
use rand::RngExt;
use std::{
    fs,
    io::{Read, Write, stdin, stdout},
    path::PathBuf,
};
use zeroize::Zeroizing;

use crate::{
    backend::safe::AnyHowErrHelper,
    crypto::{self, enc_vault},
    toml,
    vault::home_dirr,
};
use crate::{
    crypto::{Entry, Fields, dec, enc, read_json},
    vault::set_perm_over_file,
};

pub fn pre_add(
    username_email: &str,
    id: &str,
    password: &str,
    master_key: &str,
    note: &str,
    ef: Option<&str>,
) -> anyhow::Result<()> {
    let password = Zeroizing::new(password.to_string());
    let master_key = Zeroizing::new(master_key.to_string());

    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    let enc = enc(&master_key, &username_email.to_string(), &password)?;

    let (salt, nonce, data) = (
        BASE64_STANDARD.encode(enc.0),
        BASE64_STANDARD.encode(enc.1),
        BASE64_STANDARD.encode(enc.2),
    );

    let date_of_adding = chrono::Local::now().to_string();

    let content = Fields {
        entry: Entry {
            id: id.to_string(),
            salt,
            nonce,
            data,
            note: Some(note.to_string()),
            date: date_of_adding,
        },
    };

    let vec = vec![content];

    let json = serde_json::to_string_pretty(&vec)?;

    if let Some(o) = ef {
        fs::write(&home_dirr()?.join(o), json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(o))?;
    } else {
        fs::write(main_vault_path.join("gem.json"), json)?;
        #[cfg(unix)]
        set_perm_over_file(&main_vault_path.join("gem.json"))?;
    }

    println!(
        ">>{}: added [{}] [{}]",
        "diamond".bright_cyan().bold(),
        username_email.to_string().bright_white().bold(),
        id.bright_white().bold()
    );
    Ok(())
}
pub fn add(
    username_email: &str,
    id: &str,
    password: &str,
    master_key: &str,
    note: &str,
    ef: Option<&str>,
) -> anyhow::Result<()> {
    let password = Zeroizing::new(password.to_string());
    let master_key = Zeroizing::new(master_key.to_string());
    let mut file = read_json(ef).pe()?;

    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    let enc = enc(&master_key, &username_email.to_string(), &password)?;
    let (salt, nonce, data) = (
        BASE64_STANDARD.encode(enc.0),
        BASE64_STANDARD.encode(enc.1),
        BASE64_STANDARD.encode(enc.2),
    );

    let date_of_adding = chrono::Local::now().to_string();

    let content = Fields {
        entry: Entry {
            id: id.to_string(),
            salt,
            nonce,
            data,
            note: Some(note.to_string()),
            date: date_of_adding,
        },
    };

    file.push(content);

    let json = serde_json::to_string_pretty(&file)?;

    if let Some(o) = ef {
        fs::write(&home_dirr()?.join(o), json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(o))?;
    } else {
        fs::write(&main_vault_path.join("gem.json"), json)?;
        #[cfg(unix)]
        set_perm_over_file(&main_vault_path.join("gem.json"))?;
    }

    println!(
        ">>{}: added [{}] [{}]",
        "diamond".bright_cyan().bold(),
        username_email.to_string().bright_white().bold(),
        id.bright_white().bold()
    );

    Ok(())
}

pub fn get(id: &str, master_key: &str, ef: Option<&str>) -> anyhow::Result<()> {
    let master_key = Zeroizing::new(master_key.to_string());

    let dec = dec(&master_key, &id.to_string(), ef)?;
    let dec = String::from_utf8(dec)?;
    let decc: Vec<String> = dec.split('|').map(|s| s.to_string()).collect();

    println!(
        ">>{}: got [{}] [{}] [{}]",
        "diamond".bright_cyan().bold(),
        id.to_string().white().bold(),
        &decc[0].bright_white().bold(),
        &decc[1].bright_white().bold()
    );

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
pub fn remove(id: &str, ef: Option<&str>, master_key: &str) -> anyhow::Result<()> {
    let mut read_json = read_json(ef)?;
    let master_key = Zeroizing::new(master_key.to_string());
    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    dec(&master_key, id, ef).map_err(|_| anyhow!("Incorrect master key for entry <{}>", id))?;

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
            fs::write(&home_dirr()?.join(ef), &json)?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join(ef))?;
        } else {
            fs::write(&main_vault_path.join("gem.json"), &json)?;
            #[cfg(unix)]
            set_perm_over_file(&main_vault_path.join("gem.json"))?;
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
                ">> {} [{}] [{}] [{}] [{}]",
                "found".bright_cyan().bold(),
                ry.entry.id.to_string().bright_white().bold(),
                ry.entry.data.to_string().bright_white().bold(),
                ry.entry.date.to_string().bright_white().bold(),
                note.bright_white().bold()
            );
        } else {
            println!(
                ">> {} [{}] [{}] [{}]",
                "found".bright_cyan().bold(),
                ry.entry.id.to_string().bright_white().bold(),
                ry.entry.data.to_string().bright_white().bold(),
                ry.entry.date.to_string().bright_white().bold(),
            );
        }
    }
    Ok(())
}
pub fn generate_password() -> anyhow::Result<String> {
    use rand::distr::Alphanumeric;
    let gen_pass: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    println!(
        ">> {} <{}>",
        "generated password".bright_white().bold(),
        gen_pass.bright_yellow().bold()
    );
    Ok(gen_pass)
}

pub fn export(ef: Option<&str>, name_of_export: &str, master_key: &str) -> anyhow::Result<()> {
    let mut vault = String::new();
    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    if let Some(ef) = ef {
        fs::File::open(home_dirr()?.join(ef))?.read_to_string(&mut vault)?;
    } else {
        fs::File::open(main_vault_path.join("gem.json"))?.read_to_string(&mut vault)?;
    };

    let (salt, nonce, data) = enc_vault(master_key, vault)?;
    let (encoded_salt, encoded_nonce, encoded_vault) = (
        BASE64_STANDARD.encode(salt),
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(data),
    );
    let content = crypto::VaultExport {
        salt: encoded_salt,
        nonce: encoded_nonce,
        vault: encoded_vault,
    };
    let json = serde_json::to_string_pretty(&content)?;
    fs::write(home_dirr()?.join(name_of_export), json)?;

    println!(">>{}" , "exporting is done!".bright_cyan().bold());
    Ok(())
}