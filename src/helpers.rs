use crate::{
    backend::{
        cleaner::extract_string_value_from_result,
        parser::Token,
        safe::{
            AnyHowErrHelper, Checkers, FileChecker, MasterKey, PasswordChecker, id_does_not_exsist,
        },
    }, commands::export, toml
};
use crate::{
    commands::{add, get, pre_add, remove, search},
    vault::home_dirr,
};
use anyhow::anyhow;
use std::{fs, path::PathBuf};

pub fn add_helper(
    ef: Option<&str>,
    mut index: usize,
    data: &Vec<String>,
    data_token: &Vec<String>,
) -> anyhow::Result<()> {
    let username_email = data
        .get_token(&index)
        .checker("username/email/etc..".to_string())
        .pe();

    index += 1;
    let password = data.get_token(&index).checker("password".to_string()).pe();
    index += 1;
    let id = data.get_token(&index).checker("id".to_string()).pe();
    index += 1;
    let master_key = data
        .get_token(&index)
        .checker("master-key".to_string())?
        .to_string()
        .master_key_checker()
        .pe();
    index += 1;
    let note = data_token.get_token(&index)?;

    let username_4_check_password_strengrh = extract_string_value_from_result(&username_email);
    let master_key =
        master_key.check_password_strength(&"master-key", &username_4_check_password_strengrh);

    let main_vault_path: PathBuf = toml::toml()?.dependencies.main_vault_path.into();

    if let (Ok(us), Ok(p), Ok(u), Ok(m)) = (username_email, password, &id, master_key) {
        if fs::File::open(
            &main_vault_path
                .join("gem.json")
                .to_string_lossy()
                .to_string(),
        )
        .is_err_and(|s| s.kind() == std::io::ErrorKind::NotFound)
        {
            pre_add(&us, &u, &p, &m, note, ef).pe()?;
            return Ok(());
        }
        if ef.is_some() {
            if let Some(ef) = ef {
                if fs::File::open(home_dirr()?.join(ef)).is_err() {
                    pre_add(&us.to_string(), &u, &p, &m, note, Some(ef)).pe()?;
                }
            }
        } else {
            let u = &u.to_string().check_existing_ids(u, ef).pe();
            if let Ok(u) = u {
                add(&us.to_string(), &u, &p, &m, note, ef).pe()?;
            }
        }
    }
    Ok(())
}

pub fn get_helper(
    ef: Option<&str>,
    mut index: usize,
    data: &Vec<String>,
    does_not_e_n: usize,
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe();
    index += 1;
    let master_key = data
        .get_token(&index)
        .checker("master-key".to_string())?
        .to_string()
        .master_key_checker()
        .pe();

    id_does_not_exsist(
        &id.as_ref()
            .map_err(|_| anyhow!("moving id error!"))?
            .to_string(),
        does_not_e_n,
        &data,
        ef,
    )
    .pe()?;

    if let (Ok(o), Ok(p)) = (id, master_key) {
        get(o, &p, ef).pe()?
    }
    Ok(())
}

pub fn remove_helper(
    ef: Option<&str>,
    mut index: usize,
    data: &Vec<String>,
    does_not_e_n: usize,
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe();
    index += 1;
    let master_key = data
        .get_token(&index)
        .checker("master-key".to_string())
        .pe()?
        .to_string()
        .master_key_checker()
        .pe()?;

    id_does_not_exsist(
        &id.as_ref()
            .map_err(|_| anyhow!("moving id error!"))?
            .to_string(),
        does_not_e_n,
        &data,
        ef,
    )
    .pe()?;

    if let Ok(o) = id {
        remove(o, ef, &master_key).pe()?;
    }

    Ok(())
}

pub fn search_helper(
    ef: Option<&str>,
    index: usize,
    data: &Vec<String>,
    does_not_e_n: usize,
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe();

    id_does_not_exsist(
        &id.as_ref()
            .map_err(|_| anyhow!("moving id error!"))?
            .to_string(),
        does_not_e_n,
        &data,
        ef,
    )
    .pe()?;

    if let Ok(o) = id {
        search(&o, ef).pe()?
    }

    Ok(())
}

pub fn export_helper (data: &Vec<String> , ef: Option<&str> , mut index: usize) -> anyhow::Result<()> {
    let name_of_export = data.get_token(&index).checker("name of export".to_string()).pe();
    index +=1;
    let master_key = data.get_token(&index).checker("master-key".to_string())?.to_string().master_key_checker().pe().check_password_strength("master-key", "").pe();

    if let (Ok(name) , Ok(master)) = (name_of_export , master_key) {
        export(ef, name, &master).pe()?;
    }
    Ok(())
} 

pub fn help_helper_1() -> anyhow::Result<()> {
    use colored::Colorize;

    println!(
        ">> [{}] --[{}]",
        "help".bright_purple().bold(),
        "add/get/remove/search/clear/exit/list"
            .bright_yellow()
            .bold()
    );
    println!(
        ">> <{}: used to add passwords and so on> / <{}: used to get data>",
        "add".bright_purple().bold(),
        "get".bright_purple().bold()
    );
    println!(
        ">> <{}: used to remove data from the file> / <{}: used to search for data by there id name>",
        "remove".bright_purple().bold(),
        "search".bright_purple().bold()
    );
    println!(
        ">> <{}: used to clear the term> / <{}: used to exit the program>",
        "clear".bright_purple().bold(),
        "exit".bright_purple().bold()
    );
    println!(
        ">> <{}: used to list all the data> / <{}: used to change data using there id name>",
        "list".bright_purple().bold(),
        "change".bright_purple().bold()
    );

    println!(
        ">> <{}: used to list all the data> / <{}: used to generate new password>",
        "list".bright_purple().bold(),
        "gp".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to export vaults> /",
        "export".bright_purple().bold(),
    );
    Ok(())
}