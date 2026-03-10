use anyhow::anyhow;
use base64::prelude::*;
use colored::Colorize;
use rand::RngExt;
use std::{
    fs,
    io::{Write, stdin, stdout},
};
use zeroize::Zeroizing;

use crate::{backend::safe::AnyHowErrHelper};
use crate::{
    crypto::{Entry, Fields, dec, enc, read_json},
    vault::{home_dirr, set_perm_over_file},
};

pub fn pre_add(
    username_email: &str,
    id: &str,
    password: &str,
    master_key: &str,
    ef: Option<&str>,
) -> anyhow::Result<()> {
    let password = Zeroizing::new(password.to_string());
    let master_key = Zeroizing::new(master_key.to_string());

    let enc = enc(&master_key, &username_email.to_string(), &password)?;

    let (salt, nonce, data) = (
        BASE64_STANDARD.encode(enc.0),
        BASE64_STANDARD.encode(enc.1),
        BASE64_STANDARD.encode(enc.2),
    );

    let content = Fields {
        entry: Entry {
            id: id.to_string(),
            salt,
            nonce,
            data,
        },
    };

    let vec = vec![content];

    let json = serde_json::to_string(&vec)?;

    if let Some(o) = ef {
        fs::write(home_dirr()?.join(o), json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(o))?;
    } else {
        fs::write(home_dirr()?.join("diamond/gem.json"), json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join("diamond/gem.json"))?;
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
    ef: Option<&str>,
) -> anyhow::Result<()> {
    let password = Zeroizing::new(password.to_string());
    let master_key = Zeroizing::new(master_key.to_string());
    let mut file = read_json(ef).pe()?;

    let enc = enc(&master_key, &username_email.to_string(), &password)?;
    let (salt, nonce, data) = (
        BASE64_STANDARD.encode(enc.0),
        BASE64_STANDARD.encode(enc.1),
        BASE64_STANDARD.encode(enc.2),
    );

    let content = Fields {
        entry: Entry {
            id: id.to_string(),
            salt,
            nonce,
            data,
        },
    };

    file.push(content);

    let json = serde_json::to_string(&file)?;

    if let Some(o) = ef {
        fs::write(home_dirr()?.join(o), json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join(o))?;
    } else {
        fs::write(home_dirr()?.join("diamond/gem.json"), json)?;
        #[cfg(unix)]
        set_perm_over_file(&home_dirr()?.join("diamond/gem.json"))?;
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
        println!(
            ">>{} id <{}> | data : <{}>",
            "diamond".bright_cyan().bold(),
            i.entry.id.to_string().bright_white().bold(),
            i.entry.data.to_string().bright_white().bold()
        );
    }

    Ok(())
}
pub fn remove(id: &str, ef: Option<&str> , master_key: &str) -> anyhow::Result<()> {
    let mut read_json = read_json(ef)?;
    let master_key = Zeroizing::new(master_key.to_string());

    dec(&master_key, id, ef).map_err(|_| anyhow!("Incorrect master key for entry <{}>" , id))?;

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

        let json = serde_json::to_string(&read_json)?;

        if let Some(ef) = ef {
            fs::write(home_dirr()?.join(ef), &json)?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join(ef))?;
        } else {
            fs::write(home_dirr()?.join("diamond/gem.json"), &json)?;
            #[cfg(unix)]
            set_perm_over_file(&home_dirr()?.join("diamond/gem.json"))?;

            println!(
                ">>{} removed [{}]",
                "diamond".bright_cyan().bold(),
                id.bright_white().bold()
            );
        }
    }
    Ok(())
}
pub fn search(id: &str, ef: Option<&str>) -> anyhow::Result<()> {
    let read_json = read_json(ef)?;

    if let Some(ry) = read_json.iter().find(|u| u.entry.id == *id) {
        println!(
            ">> {} [{}] [{}]",
            "found".bright_cyan().bold(),
            ry.entry.id.to_string().bright_white().bold(),
            ry.entry.data.to_string().bright_white().bold()
        );
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
