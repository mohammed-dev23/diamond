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
        safe::{AnyHowErrHelper, Checkers},
    },
    commands::{generate_password, list},
    helpers::{add_helper, export_helper, get_helper, help_helper_1, remove_helper, search_helper},
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
            add_helper(None, 1, &data, &data_token)?;
        }
        "get" => {
            get_helper(None, 1, &data, 1)?;
        }

        "help" => match data.get_token(&1)?.trim() {
            "--add" => {
                println!(
                    ">>{}: [{}] [{}] [{}] [{}] [{}] [{}] [<{}>]",
                    "Usage".bright_green().bold(),
                    "diamond".bright_blue().bold(),
                    "add".bright_yellow().bold(),
                    "username/email".bright_yellow().bold(),
                    "password".bright_yellow().bold(),
                    "id".bright_yellow().bold(),
                    "master-key".bright_yellow().bold(),
                    "Option: note".bright_yellow().bold(),
                );
            }
            "--get" => {
                println!(
                    ">>{}: [{}] [{}] [{}] [{}]",
                    "Usage".bright_green().bold(),
                    "diamond".bright_blue().bold(),
                    "get".bright_yellow().bold(),
                    "id".bright_yellow().bold(),
                    "master-key".bright_yellow().bold()
                );
            }
            "--remove" => {
                println!(
                    ">>{}: [{}] [{}] [{}] [{}]",
                    "Usage".bright_green().bold(),
                    "diamond".bright_blue().bold(),
                    "remove".bright_yellow().bold(),
                    "id".bright_yellow().bold(),
                    "master-key".bright_yellow().bold(),
                );
            }
            "--list" => {
                println!(
                    ">>{}: [{}] [{}]",
                    "Usage".bright_green().bold(),
                    "diamond".bright_blue().bold(),
                    "list".bright_yellow().bold(),
                );
            }
            "--search" => {
                println!(
                    ">>{}: [{}] [{}] [{}]",
                    "Usage".bright_green().bold(),
                    "diamond".bright_blue().bold(),
                    "search".bright_yellow().bold(),
                    "id".bright_yellow().bold(),
                );
            }
            "--clear" => {
                println!(
                    ">>{}: [{}] [{}]",
                    "Usage".bright_green().bold(),
                    "diamond".bright_blue().bold(),
                    "clear".bright_yellow().bold(),
                );
            }
            "--exit" => {
                println!(
                    ">>{}: [{}] [{}]",
                    "Usage".bright_green().bold(),
                    "diamond".bright_blue().bold(),
                    "exit".bright_yellow().bold(),
                );
            }
            "--export" => {
                println!(
                    ">>{}: [{}] [{}] [{}] [{}]",
                    "Usage".bright_green().bold(),
                    "diamond".bright_blue().bold(),
                    "export".bright_yellow().bold(),
                    "(name of expoert).json".bright_yellow().bold(),
                    "master-key".bright_yellow().bold()
                );
            }
            "-l" => {
                help_helper_1()?;
            }
            _ => {
                if !data.get_token(&1)?.is_empty() {
                    println!(
                        ">> The flag [{}] you used is not vaild flag please use [{} -l] to check all the available flags",
                        data.get_token(&1)?.bright_red().bold(),
                        "help".bright_yellow().bold()
                    )
                }
            }
        },
        "list" => list(None).pe()?,
        "remove" => {
            remove_helper(None, 1, &data, 1)?;
        }
        "search" => {
            search_helper(None, 1, &data, 1)?;
        }
        "export" => {
            export_helper(&data, None, 1)?;
        }
        "external" => match data.get_token(&2)?.trim() {
            "add" => {
                let ef = data
                    .get_token(&1)
                    .checker("external file/path".to_string())
                    .pe();

                if let Ok(ef) = ef {
                    add_helper(Some(&ef.to_string()), 3, &data, &data_token).pe()?;
                }
            }
            "get" => {
                let ef = data
                    .get_token(&1)
                    .checker("external file/path".to_string())
                    .pe();

                if let Ok(ef) = ef {
                    get_helper(Some(&ef.to_string()), 3, &data, 2)?;
                }
            }
            "list" => {
                let ef = data
                    .get_token(&1)
                    .checker("external file/path".to_string())
                    .pe();

                if let Ok(ef) = ef {
                    list(Some(ef)).pe()?
                }
            }
            "remove" => {
                let ef = data
                    .get_token(&1)
                    .checker("external file/path".to_string())
                    .pe();

                if let Ok(ef) = ef {
                    remove_helper(Some(&ef.to_string()), 3, &data, 2)?;
                }
            }
            "search" => {
                let ef = data
                    .get_token(&1)
                    .checker("external file/path".to_string())
                    .pe();

                if let Ok(ef) = ef {
                    search_helper(Some(&ef.to_string()), 3, &data, 2)?;
                }
            }
            "export" => {
                let ef = data
                    .get_token(&1)
                    .checker("external file/path".to_string())
                    .pe();

                if let Ok(ef) = ef {
                    export_helper(&data, Some(ef), 3)?;
                } 
            }
            "help" => match data.get_token(&3)?.trim() {
                "--add" => {
                    println!(
                        ">>{}: [{}] [{}] [{}] [{}] [{}] [{}] [{}] [{}] [<{}>]",
                        "Usage".bright_green().bold(),
                        "diamond".bright_blue().bold(),
                        "external".bright_yellow().bold(),
                        "path/name".bright_yellow().bold(),
                        "add".bright_yellow().bold(),
                        "username/email".bright_yellow().bold(),
                        "password".bright_yellow().bold(),
                        "id".bright_yellow().bold(),
                        "master-key".bright_yellow().bold(),
                        "Option: note".bright_yellow().bold(),
                    );
                }
                "--get" => {
                    println!(
                        ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
                        "Usage".bright_green().bold(),
                        "diamond".bright_blue().bold(),
                        "external".bright_yellow().bold(),
                        "path/name".bright_yellow().bold(),
                        "get".bright_yellow().bold(),
                        "id".bright_yellow().bold(),
                        "master-key".bright_yellow().bold(),
                    );
                }
                "--remove" => {
                    println!(
                        ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
                        "Usage".bright_green().bold(),
                        "diamond".bright_blue().bold(),
                        "external".bright_yellow().bold(),
                        "path/name".bright_yellow().bold(),
                        "remove".bright_yellow().bold(),
                        "id".bright_yellow().bold(),
                        "master-key".bright_yellow().bold(),
                    );
                }
                "--list" => {
                    println!(
                        ">>{}: [{}] [{}] [{}] [{}]",
                        "Usage".bright_green().bold(),
                        "diamond".bright_blue().bold(),
                        "external".bright_yellow().bold(),
                        "path/name".bright_yellow().bold(),
                        "list".bright_yellow().bold(),
                    );
                }
                "--search" => {
                    println!(
                        ">>{}: [{}] [{}] [{}] [{}] [{}]",
                        "Usage".bright_green().bold(),
                        "diamond".bright_blue().bold(),
                        "external".bright_yellow().bold(),
                        "path/name".bright_yellow().bold(),
                        "search".bright_yellow().bold(),
                        "id".bright_yellow().bold(),
                    );
                }
                "--export" => {
                    println!(
                        ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
                        "Usage".bright_green().bold(),
                        "diamond".bright_blue().bold(),
                        "external".bright_yellow().bold(),
                        "path/name".bright_yellow().bold(),
                        "export".bright_yellow().bold(),
                        "(name of expoert).json".bright_yellow().bold(),
                        "master-key".bright_yellow().bold(),
                    )
                }
                "-l" => {
                    help_helper_1()?;
                }
                _ => {
                    if !data.get_token(&2)?.is_empty() {
                        println!(
                            ">> The flag [{}] you used is not vaild flag please use [{} -l] to check all the available flags",
                            data.get_token(&2)?.bright_red().bold(),
                            "help".bright_yellow().bold()
                        )
                    }
                }
            },
            _ => {
                if !data.get_token(&1)?.is_empty() {
                    println!(
                        ">> The command [{}] you used is not vaild command please use [{}] to check all the available commands",
                        data.get_token(&1)?.bright_red().bold(),
                        "help".bright_yellow().bold()
                    )
                }
            }
        },
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
