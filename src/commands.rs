use anyhow::anyhow;
#[cfg(not(feature = "termux"))]
use arboard::Clipboard;
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
    path::PathBuf,
    thread::sleep,
    time::Duration,
};
use zeroize::Zeroizing;

use indicatif::{ProgressBar, ProgressStyle};

use crate::crypto::{Entry, Fields, dec, enc, read_json};
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
) -> anyhow::Result<()> {
    let password = if password.contains("gp") {
        generate_password()?
    } else {
        password.to_string()
    };

    let password = Zeroizing::new(password.to_string());
    let master_key = Zeroizing::new(master_key.to_string());
    let mut file = read_json(ef).pe()?;

    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    let enc = enc(&master_key, username_email, &password)?;

    let (salt, nonce, username, password) = (
        BASE64_STANDARD.encode(enc.0),
        BASE64_STANDARD.encode(enc.1),
        BASE64_STANDARD.encode(enc.2),
        BASE64_STANDARD.encode(enc.3),
    );

    let date_of_adding = chrono::Local::now().to_string();

    let content = Fields {
        entry: Entry {
            id: id.to_string(),
            salt,
            nonce,
            identifier: username,
            password,
            note: note.map(String::from),
            date: date_of_adding,
        },
    };

    file.push(content);

    let json = serde_json::to_string_pretty(&file)?;

    if let Some(o) = ef {
        atomic_writer(&home_dirr()?.join(o), &json)?;
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
}

pub fn get(id: &str, master_key: &str, flags: Flags, ef: Option<&str>) -> anyhow::Result<()> {
    let master_key = Zeroizing::new(master_key.to_string());

    let dec = dec(&master_key, id, ef)
        .map_err(|_| anyhow!("invalid master key please try again later"))?;

    let username = String::from_utf8(dec.0)?;
    let password = String::from_utf8(dec.1)?;

    if matches!(flags.clip, Some(false))
        && matches!(flags.encodded, Some(false))
        && matches!(flags.qrcode, Some(false))
    {
        println!(
            ">>{}: got [{}] [{}] [{}]",
            "diamond".bright_cyan().bold(),
            id.to_string().white().bold(),
            &username.bright_white().bold(),
            &password.bright_white().bold()
        )
    }

    if let Some(clipboard_or_without) = flags.clip {
        #[cfg(not(feature = "termux"))]
        {
            if clipboard_or_without {
                let mut c = Clipboard::new()?;
                c.set_text(&password)?;
                println!(
                    ">>{}, {}",
                    "wait for the password to be saved in the clipboard"
                        .bright_blue()
                        .bold(),
                    "it will take 5s..".bright_purple().bold()
                );

                let mut sec = 5;

                while sec > 0 {
                    let pb = ProgressBar::new(5);

                    for _ in 0..5 {
                        sleep(Duration::from_secs(1));
                        pb.clone()
                            .with_style(ProgressStyle::with_template(
                                "⏳ ~> [{bar:40.cyan/blue}] {pos}/{len}s",
                            )?)
                            .inc(1);
                    }
                    sec = 0
                }

                println!(
                    ">>{}: got [{}] [{}]",
                    "diamond".bright_cyan().bold(),
                    id.to_string().white().bold(),
                    &username.bright_white().bold(),
                );
            }
        }
        #[cfg(feature = "termux")]
        {
            if !clipboard_or_without {
                terminal_clipboard::set_string(&password)
                    .map_err(|_| anyhow!("Clouldn't copy to clipboard!"))?;
                println!(
                    ">>{}, {}",
                    "wait for the password to be saved in the clipboard"
                        .bright_blue()
                        .bold(),
                    "it will take 5s..".bright_purple().bold()
                );

                let mut sec = 5;

                while sec > 0 {
                    println!("~{}", sec.to_string().bright_cyan().bold());
                    thread::sleep(Duration::from_secs(1));
                    sec -= 1;
                }

                println!(
                    ">>{}: got [{}] [{}]",
                    "diamond".bright_cyan().bold(),
                    id.to_string().white().bold(),
                    &username.bright_white().bold(),
                );
            }
        }
    }

    if let Some(qrcode) = flags.qrcode {
        if qrcode {
            let qrcode = QrCode::new(format!("{}|{}", username, password).as_bytes())?;
            let string_qr = qrcode
                .render::<unicode::Dense1x2>()
                .max_dimensions(1, 1)
                .quiet_zone(false)
                .build();

            println!("{}", string_qr)
        }
    }

    if let Some(with_hex) = flags.encodded {
        if with_hex {
            let encoded = hex::encode(format!("{}|{}", username, password));
            println!(
                ">>{}: got [{}] [{}]",
                "diamond".bright_cyan().bold(),
                id.to_string().white().bold(),
                &encoded.bright_white().bold()
            );
        }
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
    let master_key = Zeroizing::new(master_key.to_string());

    if let Some(ef) = ef {
        fs::File::open(home_dirr()?.join(ef))?.read_to_string(&mut vault)?;
    } else {
        fs::File::open(main_vault_path)?.read_to_string(&mut vault)?;
    };

    let (salt, nonce, data) = enc_vault(&master_key, vault)?;
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
    atomic_writer(&home_dirr()?.join(name_of_export), &json)?;
    #[cfg(unix)]
    set_perm_over_file(&home_dirr()?.join(name_of_export))?;

    println!(">>{}", "exporting is done!".bright_cyan().bold());
    Ok(())
}

pub fn import(master_key: &str, new_name: &str, path_of_vault: &str) -> anyhow::Result<()> {
    let master_key = Zeroizing::new(master_key.to_string());
    let dec: String = String::from_utf8(dec_vault(master_key.as_str(), path_of_vault)?)?;
    let json_args = serde_json::from_str::<Vec<Fields>>(dec.trim())?;
    let json = serde_json::to_string_pretty(&json_args)?;
    atomic_writer(&home_dirr()?.join(new_name), &json)?;
    #[cfg(unix)]
    set_perm_over_file(&home_dirr()?.join(new_name))?;
    Ok(())
}

pub fn atomic_writer(path: &PathBuf, content: &str) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, content)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn rename(id: &str, new_id: &str, ef: Option<&str>) -> anyhow::Result<()> {
    let mut read_json = read_json(ef)?;

    let valut_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    if let Some(idd) = read_json.iter_mut().find(|s| s.entry.id == id) {
        idd.entry.id = new_id.to_string();
    }

    let json = serde_json::to_string_pretty(&read_json)?;

    if let Some(ef) = ef {
        atomic_writer(&home_dirr()?.join(ef), &json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(ef))?;
    } else {
        atomic_writer(&valut_path, &json)?;
        #[cfg(unix)]
        set_perm_over_file(&valut_path)?;
    }

    println!(">>{}", "renamed!".bright_cyan().bold());
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

    dec(&master_key, id, ef)
        .map_err(|_| anyhow!("Incorrect master-key!"))
        .pe()?;

    let main_vault_path: PathBuf = toml()?.dependencies.main_vault_path.into();

    if let Some(new) = read_json.iter_mut().find(|s| s.entry.id == id) {
        let enc = enc(&master_key, new_user_name, &new_password)?;
        let (salt, nonce, username, password) = (
            BASE64_STANDARD.encode(enc.0),
            BASE64_STANDARD.encode(enc.1),
            BASE64_STANDARD.encode(enc.2),
            BASE64_STANDARD.encode(enc.3),
        );

        new.entry.identifier = username;
        new.entry.password = password;
        new.entry.salt = salt;
        new.entry.nonce = nonce;
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
