mod backend;
mod dec_enc;
use anyhow::anyhow;
use colored::Colorize;
use std::{
    fs,
    io::{Write, stdout},
};
mod test;
use rustyline::{DefaultEditor, error::ReadlineError};

use crate::{
    backend::{
        parser::{Token, parse_input},
        safe::{
            AnyHowErrHelper, Checkers, FileChecker, MasterKeyV, PasswordChecker, action_password,
            does_not_e,
        },
    },
    dec_enc::{add, change, get, list, remove, search},
};
use dec_enc::{_pre_, home_dirr, pre_add};

fn main() -> anyhow::Result<()> {
    loop {
        if interface().is_err() {
            continue;
        }
    }
}

fn interface() -> anyhow::Result<()> {
    let mut rl = DefaultEditor::new()?;

    loop {
        let data = match rl.readline("[obsidian]~>") {
            Ok(o) => o,
            Err(e) => match e {
                ReadlineError::Eof => break Err(anyhow!("Eof/ Ctrl+C")),
                _ => break Err(anyhow!("{e}")),
            },
        };

        let data = parse_input(data)?;

        match data.get_token(0)?.trim() {
            "add" => {
                let username = data.get_token(1).checker("username".to_string()).pe();
                let password = data.get_token(2).checker("password".to_string()).pe();
                let url_app = data.get_token(3).checker("url/app".to_string()).pe();
                let master_key = data
                    .get_token(4)
                    .checker("master-key".to_string())?
                    .master_key_checker()
                    .pe2()?
                    .check_password_(&"master-key".to_string())
                    .pe2();

                let ac_password = data
                    .get_token(5)
                    .checker("action-password".to_string())?
                    .check_password_(&"action-password".to_string())
                    .pe();

                let res = if ac_password.is_ok() {
                    action_password(&ac_password?).pe()
                } else {
                    return Err(anyhow!("missing action-password"));
                };

                if res.is_ok() {
                    if let (Ok(us), Ok(p), Ok(u), Ok(m)) = (username, password, url_app, master_key)
                    {
                        if fs::File::open(
                            home_dirr()?
                                .join("obsidian/obs.yaml")
                                .to_string_lossy()
                                .to_string(),
                        )
                        .is_err_and(|s| s.kind() == std::io::ErrorKind::NotFound)
                        {
                            _pre_()?;
                            pre_add(us, u, p, m, None).pe()?;
                        } else {
                            let u = u.check_existing_url_apps(&data.get_token(3)?, None).pe();
                            if let Ok(u) = u {
                                add(us, u, p, m, None).pe()?;
                            }
                        }
                    }
                }
            }
            "get" => {
                let url_app = data.get_token(1).checker("app/url".to_string()).pe();
                let master_key = data
                    .get_token(2)
                    .checker("master-key".to_string())?
                    .master_key_checker()
                    .pe();

                let action_pass = data
                    .get_token(3)
                    .checker("action-password".to_string())
                    .pe();

                let res = if action_pass.is_ok() {
                    action_password(&action_pass?).pe()
                } else {
                    return Err(anyhow!("missing action-password"));
                };

                does_not_e(
                    &url_app
                        .as_ref()
                        .map_err(|_| anyhow!("moving url/app error!"))?
                        .to_string(),
                    1,
                    &data,
                    None,
                )
                .pe()?;

                if res.is_ok() {
                    if let (Ok(o), Ok(p)) = (url_app, master_key) {
                        get(o, p, None).pe()?
                    }
                }
            }

            "help" => {
                match data.get_token(1)?.trim() {
                    "--add" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "add".bright_yellow().bold(),
                            "username/email".bright_yellow().bold(),
                            "obsidian".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "master-key".bright_yellow().bold(),
                            "add-password".bright_yellow().bold(),
                        );
                    }
                    "--get" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "get".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "master-key".bright_yellow().bold()
                        );
                    }
                    "--remove" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "remove".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "action-password".bright_yellow().bold()
                        );
                    }
                    "--list" => {
                        println!(
                            ">>{}: [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "list".bright_yellow().bold(),
                            "action-password".bright_yellow().bold()
                        );
                    }
                    "--search" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "search".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                        );
                    }
                    "--change" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "change".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "username/email".bright_yellow().bold(),
                            "password".bright_yellow().bold(),
                            "master-key".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                        );
                    }
                    "--clear" => {
                        println!(
                            ">>{}: [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "clear".bright_yellow().bold(),
                        );
                    }
                    "--exit" => {
                        println!(
                            ">>{}: [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "exit".bright_yellow().bold(),
                        );
                    }
                    "-l" => {
                        println!(
                            ">>[{}] --[{}]",
                            "help".bright_purple().bold(),
                            "add/get/remove/search/clear/exit/list/change"
                                .bright_yellow()
                                .bold()
                        );

                        println!(
                            ">> <{}: used to add passwords and so on> / <{}: used to get data>",
                            "add".bright_purple().bold(),
                            "get".bright_purple().bold()
                        );
                        println!(
                            ">> <{}: used to remove data from the file> / <{}: used to search for data by there url/app name>",
                            "remove".bright_purple().bold(),
                            "search".bright_purple().bold()
                        );
                        println!(
                            ">> <{}: used to clear the term> / <{}: used to exit the program>",
                            "clear".bright_purple().bold(),
                            "exit".bright_purple().bold()
                        );
                        println!(
                            ">> <{}: used to list all the data> / <{}: used to change data using there url/app name>",
                            "list".bright_purple().bold(),
                            "change".bright_purple().bold()
                        );
                    }
                    _ => {
                        if !data.get_token(1)?.is_empty() {
                            println!(
                                ">> The flag [{}] you used is not vaild flag please use [{} -l] to check all the available flags",
                                data.get_token(1)?.bright_red().bold(),
                                "help".bright_yellow().bold()
                            )
                        }
                        continue;
                    }
                }
                continue;
            }
            "list" => {
                let ac_pass = data
                    .get_token(1)
                    .checker("action-password".to_string())
                    .pe();

                let res = if ac_pass.is_ok() {
                    action_password(&ac_pass?).pe()
                } else {
                    return Err(anyhow!("missing action-password"));
                };

                if res.is_ok() {
                    list(None).pe()?;
                }
            }
            "remove" => {
                let url_app = data.get_token(1).checker("url/app".to_string()).pe();
                let ac_password = data
                    .get_token(2)
                    .checker("action password".to_string())
                    .pe();

                let res = if ac_password.is_ok() {
                    action_password(&ac_password?).pe()
                } else {
                    return Err(anyhow!("missing action-password"));
                };

                does_not_e(
                    &url_app
                        .as_ref()
                        .map_err(|_| anyhow!("moving url/app error!"))?
                        .to_string(),
                    1,
                    &data,
                    None,
                )
                .pe()?;

                if res.is_ok() {
                    if let Ok(o) = url_app {
                        remove(&o, None)?;
                    }
                }
            }
            "search" => {
                let url_app = data.get_token(1).checker("url/app".to_string()).pe();
                let ac_password = data
                    .get_token(2)
                    .checker("action password".to_string())
                    .pe();

                let res = if ac_password.is_ok() {
                    action_password(&ac_password?).pe()
                } else {
                    return Err(anyhow!("missing action-password"));
                };

                does_not_e(
                    &url_app
                        .as_ref()
                        .map_err(|_| anyhow!("moving url/app error!"))?
                        .to_string(),
                    1,
                    &data,
                    None,
                )
                .pe()?;

                if res.is_ok() {
                    if let Ok(o) = url_app {
                        search(&o, None).pe()?
                    }
                }
            }
            "change" => {
                let url_app = data.get_token(1).checker("url/app".to_string()).pe();
                let username_email = data.get_token(2).checker("username/email".to_string()).pe();
                let passwoed = data.get_token(3).checker("password".to_string()).pe();
                let master_key = data
                    .get_token(4)
                    .checker("master-key".to_string())
                    .pe2()?
                    .master_key_checker()
                    .pe2()?
                    .check_password_(&"master-key".to_string());
                let ac_password = data
                    .get_token(5)
                    .checker("action-password".to_string())
                    .pe();

                let res = if ac_password.is_ok() {
                    action_password(&ac_password?)
                } else {
                    return Err(anyhow!("missing action-password"));
                };

                does_not_e(
                    &url_app
                        .as_ref()
                        .map_err(|_| anyhow!("moving url/app error!"))?
                        .to_string(),
                    1,
                    &data,
                    None,
                )
                .pe()?;

                if res.is_ok() {
                    if let (Ok(ue), Ok(pw), Ok(mk)) = (username_email, passwoed, master_key) {
                        change(
                            &data.get_token(1).checker("url/app".to_string())?,
                            None,
                            &mk,
                            &pw,
                            &ue,
                        )
                        .pe()?
                    }
                }
            }
            "external" => match data.get_token(1)?.trim() {
                "add" => {
                    let username = data.get_token(2).checker("username".to_string()).pe();
                    let password = data.get_token(3).checker("password".to_string()).pe();
                    let url_app = data.get_token(4).checker("url/app".to_string()).pe();
                    let master_key = data
                        .get_token(5)
                        .checker("master-key".to_string())?
                        .master_key_checker()
                        .pe2()?
                        .check_password_(&"master-key".to_string())
                        .pe2();

                    let ac_password = data
                        .get_token(6)
                        .checker("add-password".to_string())?
                        .check_password_(&"action-password".to_string())
                        .pe();

                    let external_file = data
                        .get_token(7)
                        .checker("external file/path/name".to_string())
                        .pe();

                    let res = if ac_password.is_ok() {
                        action_password(&ac_password?).pe()
                    } else {
                        return Err(anyhow!("missing action-password"));
                    };

                    if res.is_ok() {
                        if let (Ok(us), Ok(p), Ok(u), Ok(m), Ok(ef)) =
                            (username, password, url_app, master_key, external_file)
                        {
                            if fs::File::open(home_dirr()?.join(&ef).to_string_lossy().to_string())
                                .is_err_and(|s| s.kind() == std::io::ErrorKind::NotFound)
                            {
                                _pre_()?;
                                pre_add(us, u, p, m, Some(&ef)).pe()?;
                            } else {
                                let u = u
                                    .check_existing_url_apps(&data.get_token(4)?, Some(&ef))
                                    .pe();
                                if let Ok(u) = u {
                                    add(us, u, p, m, Some(&ef)).pe()?;
                                }
                            }
                        }
                    }
                }
                "get" => {
                    let url_app = data.get_token(2).checker("app/url".to_string()).pe();
                    let master_key = data
                        .get_token(3)
                        .checker("master-key".to_string())?
                        .master_key_checker()
                        .pe();

                    let ac_password = data
                        .get_token(4)
                        .checker("action-password".to_string())
                        .pe();

                    let ef = data
                        .get_token(5)
                        .checker("external file/path/name".to_string())
                        .pe();

                    let res = if ac_password.is_ok() {
                        action_password(&ac_password?).pe()
                    } else {
                        return Err(anyhow!("missing action-password"));
                    };

                    does_not_e(
                        &url_app
                            .as_ref()
                            .map_err(|_| anyhow!("moving url/app error!"))?
                            .to_string(),
                        1,
                        &data,
                        None,
                    )
                    .pe()?;

                    if res.is_ok() {
                        if let (Ok(o), Ok(p), Ok(ef)) = (url_app, master_key, ef) {
                            get(o, p, Some(&ef)).pe()?
                        }
                    }
                }
                "list" => {
                    let ac_pass = data
                        .get_token(2)
                        .checker("action-password".to_string())
                        .pe();

                    let ef = data
                        .get_token(3)
                        .checker("external file/path/name".to_string())
                        .pe();

                    let res = if ac_pass.is_ok() {
                        action_password(&ac_pass?).pe()
                    } else {
                        return Err(anyhow!("missing action-password"));
                    };

                    if res.is_ok() {
                        if let Ok(o) = ef {
                            list(Some(&o)).pe()?;
                        }
                    }
                }
                "remove" => {
                    let url_app = data.get_token(2).checker("url/app".to_string()).pe();
                    let ac_pass = data
                        .get_token(3)
                        .checker("action-password".to_string())
                        .pe();

                    let ef = data
                        .get_token(3)
                        .checker("external file/path/name".to_string())
                        .pe();

                    let res = if ac_pass.is_ok() {
                        action_password(&ac_pass?).pe()
                    } else {
                        return Err(anyhow!("missing action-password"));
                    };

                    does_not_e(
                        &url_app
                            .as_ref()
                            .map_err(|_| anyhow!("moving url/app error!"))?
                            .to_string(),
                        1,
                        &data,
                        None,
                    )
                    .pe()?;

                    if res.is_ok() {
                        if let (Ok(o), Ok(ef)) = (url_app, ef) {
                            remove(&o, Some(&ef))?;
                        }
                    }
                }
                "search" => {
                    let url_app = data.get_token(2).checker("url/app".to_string()).pe();
                    let ac_password = data
                        .get_token(3)
                        .checker("action password".to_string())
                        .pe();

                    let ef = data
                        .get_token(4)
                        .checker("external file/path/name".to_string())
                        .pe();

                    let res = if ac_password.is_ok() {
                        action_password(&ac_password?).pe()
                    } else {
                        return Err(anyhow!("missing action-password"));
                    };

                    does_not_e(
                        &url_app
                            .as_ref()
                            .map_err(|_| anyhow!("moving url/app error!"))?
                            .to_string(),
                        1,
                        &data,
                        None,
                    )
                    .pe()?;

                    if res.is_ok() {
                        if let (Ok(o), Ok(ef)) = (url_app, ef) {
                            search(&o, Some(&ef)).pe()?
                        }
                    }
                }
                "change" => {
                    let url_app = data.get_token(2).checker("url/app".to_string()).pe();
                    let username_email =
                        data.get_token(3).checker("username/email".to_string()).pe();
                    let passwoed = data.get_token(4).checker("password".to_string()).pe();
                    let master_key = data
                        .get_token(5)
                        .checker("master-key".to_string())
                        .pe2()?
                        .master_key_checker()
                        .pe2()?
                        .check_password_(&"master-key".to_string());
                    let ac_password = data
                        .get_token(6)
                        .checker("action-password".to_string())
                        .pe();

                    let res = if ac_password.is_ok() {
                        action_password(&ac_password?)
                    } else {
                        return Err(anyhow!("missing action-password"));
                    };

                    does_not_e(
                        &url_app
                            .as_ref()
                            .map_err(|_| anyhow!("moving url/app error!"))?
                            .to_string(),
                        1,
                        &data,
                        None,
                    )
                    .pe()?;

                    let ef = data
                        .get_token(7)
                        .checker("external file/path/name".to_string())
                        .pe();

                    if res.is_ok() {
                        if let (Ok(ue), Ok(pw), Ok(mk), Ok(ef)) =
                            (username_email, passwoed, master_key, ef)
                        {
                            change(
                                &data.get_token(2).checker("url/app".to_string())?,
                                Some(&ef),
                                &mk,
                                &pw,
                                &ue,
                            )
                            .pe()?
                        }
                    }
                }
                "help" => match data.get_token(2)?.trim() {
                    "--add" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "add".bright_yellow().bold(),
                            "username/email".bright_yellow().bold(),
                            "obsidian".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "master-key".bright_yellow().bold(),
                            "add-password".bright_yellow().bold(),
                            "path/name".bright_yellow().bold(),
                        );
                    }
                    "--get" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "get".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "master-key".bright_yellow().bold(),
                            "path/name".bright_yellow().bold(),
                        );
                    }
                    "--remove" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "remove".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                            "path/name".bright_yellow().bold(),
                        );
                    }
                    "--list" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "list".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                            "path/name".bright_yellow().bold()
                        );
                    }
                    "--search" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "search".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                            "path/name".bright_yellow().bold()
                        );
                    }
                    "--change" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usage".bright_green().bold(),
                            "obsidian".bright_blue().bold(),
                            "external".bright_yellow().bold(),
                            "change".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "username/email".bright_yellow().bold(),
                            "password".bright_yellow().bold(),
                            "master-key".bright_yellow().bold(),
                            "action-password".bright_yellow().bold(),
                            "path/name".bright_yellow().bold(),
                        );
                    }
                    "-l" => {
                        println!(
                            ">>[{}] --[{}]",
                            "help".bright_purple().bold(),
                            "add/get/remove/search/clear/exit/list/change"
                                .bright_yellow()
                                .bold()
                        );
                        println!(
                            ">> <{}: used to add passwords and so on> / <{}: used to get data>",
                            "add".bright_purple().bold(),
                            "get".bright_purple().bold()
                        );
                        println!(
                            ">> <{}: used to remove data from the file> / <{}: used to search for data by there url/app name>",
                            "remove".bright_purple().bold(),
                            "search".bright_purple().bold()
                        );
                        println!(
                            ">> <{}: used to clear the term> / <{}: used to exit the program>",
                            "clear".bright_purple().bold(),
                            "exit".bright_purple().bold()
                        );
                        println!(
                            ">> <{}: used to list all the data> / <{}: used to change data using there url/app name>",
                            "list".bright_purple().bold(),
                            "change".bright_purple().bold()
                        );
                    }
                    _ => {
                        if !data.get_token(2)?.is_empty() {
                            println!(
                                ">> The flag [{}] you used is not vaild flag please use [{} -l] to check all the available flags",
                                data.get_token(2)?.bright_red().bold(),
                                "help".bright_yellow().bold()
                            )
                        }
                        continue;
                    }
                },
                _ => {
                    if !data.get_token(1)?.is_empty() {
                        println!(
                            ">> The command [{}] you used is not vaild command please use [{}] to check all the available commands",
                            data.get_token(1)?.bright_red().bold(),
                            "help".bright_yellow().bold()
                        )
                    }
                }
            },
            "exit" => {
                std::process::exit(0);
            }
            "clear" => {
                print!("\x1B[2J\x1B[1;1H");
                stdout().flush()?;
                continue;
            }
            _ => {
                if !data.get_token(0)?.is_empty() {
                    println!(
                        ">> The command [{}] you used is not vaild command please use [{} -l] to check all the available commands",
                        data.get_token(0)?.bright_red().bold(),
                        "help".bright_yellow().bold()
                    )
                }
            }
        }
        return Ok(());
    }
}
