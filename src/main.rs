mod backend;
mod crypto;
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
        add_helper, export_helper, get_helper, help_helper, import_helper, remove_helper,
        search_helper,
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

    match data.get_token(&0)?.trim() {
        "add" => {
            add_helper(1, &data, &data_token)?;
        }
        "get" => {
            get_helper(1, &data, &data_token)?;
        }

        "help" => help_helper(&data, 1).pe()?,

        "list" => list(None).pe()?,
        "remove" => {
            remove_helper(1, &data, &data_token)?;
        }
        "search" => {
            search_helper(1, &data, &data_token)?;
        }
        "export" => {
            export_helper(&data, 1, &data_token).pe()?;
        }
        "exit" => {
            std::process::exit(0);
        }
        "clear" => {
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
        "gp" => {
            generate_password().pe()?;
        }
        "import" => {
            import_helper(&data, 1).pe()?;
        }
        _ => {
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
