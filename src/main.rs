mod backend;
mod crypto;
use std::{collections::HashMap, thread::sleep, time::Duration};

use indicatif::{ProgressBar, ProgressStyle};

use anyhow::anyhow;
use colored::Colorize;
mod commands;
mod helpers;
mod test;
mod toml;
mod vault;
use rustyline::{DefaultEditor, error::ReadlineError};

use crate::{
    backend::{
        parser::{Token, parse_input, parse_input_by_token},
        safe::{AnyHowErrHelper, Checkers},
    },
    commands::{generate_password, list, switch_vault},
    helpers::{
        EF_INDEX, ID_INDEX, add_helper, export_helper, fuzzy_helper, get_helper, help_helper,
        import_helper, note_helper, remove_helper, rename_helper, search_helper, update_helper,
    },
    toml::{toma, toml},
    vault::{_init_, print_mini_logo},
};

fn main() -> anyhow::Result<()> {
    _init_()?;
    print_mini_logo();

    let mut atm: u8 = 0;

    loop {
        if interface(&mut atm).is_err() {
            continue;
        }
    }
}

pub enum Commands {
    Add,
    Get,
    List,
    Remove,
    Search,
    Export,
    Exit,
    Clear,
    Gp,
    Import,
    Help,
    Rename,
    Update,
    Note,
    Fuzzy,
    SwitchVault,
    Toma,
}

pub fn commandsmatch() -> HashMap<String, Commands> {
    let toml = toml()
        .ok()
        .and_then(|s| s.customization.allies)
        .unwrap_or_default();

    let mut hashmap = HashMap::new();
    hashmap.insert(toml.add.unwrap_or("add".to_string()), Commands::Add);
    hashmap.insert(toml.get.unwrap_or("get".to_string()), Commands::Get);
    hashmap.insert(toml.list.unwrap_or("list".to_string()), Commands::List);
    hashmap.insert(
        toml.remove.unwrap_or("remove".to_string()),
        Commands::Remove,
    );
    hashmap.insert(
        toml.search.unwrap_or("search".to_string()),
        Commands::Search,
    );
    hashmap.insert(
        toml.export.unwrap_or("export".to_string()),
        Commands::Export,
    );
    hashmap.insert(toml.exit.unwrap_or("exit".to_string()), Commands::Exit);
    hashmap.insert(toml.clear.unwrap_or("clear".to_string()), Commands::Clear);
    hashmap.insert(
        toml.import.unwrap_or("import".to_string()),
        Commands::Import,
    );
    hashmap.insert(toml.help.unwrap_or("help".to_string()), Commands::Help);
    hashmap.insert(
        toml.rename.unwrap_or("rename".to_string()),
        Commands::Rename,
    );
    hashmap.insert(
        toml.update.unwrap_or("update".to_string()),
        Commands::Update,
    );

    hashmap.insert(toml.note.unwrap_or("note".to_string()), Commands::Note);
    hashmap.insert(toml.fuzzy.unwrap_or("fuzzy".to_string()), Commands::Fuzzy);
    hashmap.insert(
        toml.switch_vault.unwrap_or("switch-vault".to_string()),
        Commands::SwitchVault,
    );
    hashmap.insert(toml.toma.unwrap_or("toma".to_string()), Commands::Toma);
    hashmap
}

fn interface(atm: &mut u8) -> anyhow::Result<()> {
    let mut rl = DefaultEditor::new()?;

    let username = toml().pe()?.customization.username;

    let format = format!("[diamond][{}]~>", username);

    let input = match rl.readline(&format) {
        Ok(o) => o,
        Err(e) => match e {
            ReadlineError::Eof | ReadlineError::Interrupted => std::process::exit(0),
            _ => Err(anyhow!("{e}"))?,
        },
    };

    let data = parse_input(input.trim().to_string())?;
    let data_token = parse_input_by_token(input.trim().to_string())?;

    match commandsmatch().get(data.get_token(&0)?) {
        Some(Commands::Add) => {
            add_helper(ID_INDEX, &data, &data_token)?;
        }
        Some(Commands::Get) => {
            let get = get_helper(ID_INDEX, &data, &data_token);

            let block_time = 30 * 60;

            if get.is_err_and(|s| s.to_string().contains("invalid master key")) {
                *atm += 1;
                println!(
                    ">>{} no.{} | 3 and you'll be blocked for 30min",
                    "attempt".bright_cyan().bold(),
                    atm.to_string().bright_red().bold()
                );
            }

            if *atm >= 3 {
                println!(
                    ">>{} , {}",
                    "you've passed the limit of attempts".bright_cyan().bold(),
                    "you have been blocked for 30min!".bright_red().bold()
                );
                let pb = ProgressBar::new(block_time);

                for _ in 0..block_time {
                    sleep(Duration::from_secs(1));
                    pb.clone()
                        .with_style(ProgressStyle::with_template(
                            "⏳ ~> [{bar:40.cyan/blue}] {pos}/{len}s",
                        )?)
                        .inc(1);
                }
            }
        }

        Some(Commands::Help) => help_helper(&data, 1).pe()?,

        Some(Commands::List) => {
            let ef = data_token.get(EF_INDEX).map(|s| s.as_str());
            list(ef).pe()?;
        }
        Some(Commands::Remove) => {
            remove_helper(ID_INDEX, &data, &data_token)?;
        }
        Some(Commands::Search) => {
            search_helper(ID_INDEX, &data, &data_token)?;
        }
        Some(Commands::Export) => {
            export_helper(&data, 1, &data_token).pe()?;
        }
        Some(Commands::Exit) => {
            std::process::exit(0);
        }
        Some(Commands::Clear) => {
            #[cfg(unix)]
            {
                std::process::Command::new("clear").status()?;
            }
            #[cfg(windows)]
            {
                std::process::Command::new("cmd")
                    .args(["/C", "cls"])
                    .status()?;
            }
        }
        Some(Commands::Gp) => {
            generate_password().pe()?;
        }
        Some(Commands::Import) => {
            import_helper(&data, 1).pe()?;
        }
        Some(Commands::Rename) => {
            rename_helper(&data, &data_token, ID_INDEX).pe()?;
        }
        Some(Commands::Update) => {
            update_helper(&data, &data_token, ID_INDEX).pe()?;
        }
        Some(Commands::Note) => {
            note_helper(&data, &data_token, 1).pe()?;
        }
        Some(Commands::Fuzzy) => {
            fuzzy_helper(&data, &data_token, 1).pe()?;
        }
        Some(Commands::SwitchVault) => {
            let new_vault_path = data.get_token(&1).checker("Vault-Path".to_string()).pe()?;
            switch_vault(new_vault_path).pe()?;
        }
        Some(Commands::Toma) => {
            toma(&data, 1).pe()?;
        }
        None => {
            if !data.get_token(&0)?.is_empty() {
                println!(
                    ">>The command [{}] you used is not vaild command please use [{} -l] to check all the available commands",
                    data.get_token(&0)?.bright_red().bold(),
                    "help".bright_yellow().bold()
                )
            }
        }
    }
    Ok(())
}
