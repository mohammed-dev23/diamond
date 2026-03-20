mod backend;
mod crypto;
use std::collections::HashMap;

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
        safe::AnyHowErrHelper,
    },
    commands::{generate_password, list},
    helpers::{
        add_helper, export_helper, fuzzy_helper, get_helper, help_helper, import_helper,
        note_helper, remove_helper, rename_helper, search_helper, update_helper,
    },
    toml::toml,
    vault::{_init_, print_mini_logo},
};

fn main() -> anyhow::Result<()> {
    _init_()?;
    print_mini_logo();
    loop {
        if interface().is_err() {
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
    hashmap
}

fn interface() -> anyhow::Result<()> {
    let mut rl = DefaultEditor::new()?;

    let username = toml().pe()?.customization.username;

    let format = format!("[diamond][{}]~>", username);

    let input = match rl.readline(&format) {
        Ok(o) => o,
        Err(e) => match e {
            ReadlineError::Eof => Err(anyhow!("Eof/ Ctrl+C"))?,
            _ => Err(anyhow!("{e}"))?,
        },
    };

    let data = parse_input(input.trim().to_string())?;
    let data_token = parse_input_by_token(input.trim().to_string())?;

    match commandsmatch().get(data.get_token(&0)?) {
        Some(Commands::Add) => {
            add_helper(1, &data, &data_token)?;
        }
        Some(Commands::Get) => {
            get_helper(1, &data, &data_token)?;
        }

        Some(Commands::Help) => help_helper(&data, 1).pe()?,

        Some(Commands::List) => {
            let ef = data_token.get(1).map(|s| s.as_str());
            list(ef).pe()?;
        }
        Some(Commands::Remove) => {
            remove_helper(1, &data, &data_token)?;
        }
        Some(Commands::Search) => {
            search_helper(1, &data, &data_token)?;
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
            rename_helper(&data, &data_token, 1).pe()?;
        }
        Some(Commands::Update) => {
            update_helper(&data, &data_token, 1).pe()?;
        }
        Some(Commands::Note) => {
            note_helper(&data, &data_token, 1).pe()?;
        }
        Some(Commands::Fuzzy) => {
            fuzzy_helper(&data, &data_token, 1).pe()?;
        }
        None => {
            if !data.get_token(&0)?.is_empty() {
                println!(
                    ">> The command [{}] you used is not vaild command please use [{} -l] to check all the available commands",
                    data.get_token(&0)?.bright_red().bold(),
                    "help".bright_yellow().bold()
                )
            }
        }
    }
    Ok(())
}
