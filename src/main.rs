mod backend;
mod dec_enc;
use colored::Colorize;
use std::{
    fs,
    io::{Write, stdout},
};
mod test;
use crate::{
    backend::{
        parser::{Token, parse_input},
        safe::{AnyHowErrHelper, ArgsChecker},
    },
    dec_enc::{add, get},
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
    loop {
        print!("[obsidian]~>");
        stdout().flush()?;

        let data = parse_input()?;

        match data.get_token(0)?.trim() {
            "add" => {
                let username = data.get_token(1).checker("username".to_string()).pe();
                let password = data.get_token(2).checker("password".to_string()).pe();
                let url_app = data.get_token(3).checker("url/app".to_string()).pe();
                let master_key = data.get_token(4).checker("master-key".to_string()).pe();

                if let (Ok(us), Ok(p), Ok(u), Ok(m)) = (username, password, url_app, master_key) {
                    if fs::File::open(
                        home_dirr()?
                            .join("obsidian/obs.yaml")
                            .to_string_lossy()
                            .to_string(),
                    )
                    .is_err_and(|s| s.kind() == std::io::ErrorKind::NotFound)
                    {
                        _pre_()?;
                        pre_add(us, u, p, m)?;
                    } else {
                        add(us, u, p, m)?;
                    }
                }
            }
            "get" => {
                let url_app = data.get_token(1).checker("app/url".to_string()).pe();
                let master_key = data.get_token(2).checker("master-key".to_string()).pe();

                if let (Ok(o), Ok(p)) = (url_app, master_key) {
                    get(o, p).pe()?
                }
            }

            "help" => {
                match data.get_token(1)?.trim() {
                    "--add" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
                            "Usge".bright_green().bold(),
                            "obsidan".bright_blue().bold(),
                            "add".bright_yellow().bold(),
                            "username/email".bright_yellow().bold(),
                            "passwored".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "master-key".bright_yellow().bold()
                        );
                    }
                    "--get" => {
                        println!(
                            ">>{}: [{}] [{}] [{}] [{}]",
                            "Usge".bright_green().bold(),
                            "obsidan".bright_blue().bold(),
                            "get".bright_yellow().bold(),
                            "url/app".bright_yellow().bold(),
                            "master-key".bright_yellow().bold()
                        );
                    }
                    _ => {
                        continue;
                    }
                }
                continue;
            }
            "exit" => {
                std::process::exit(1);
            }
            "clear" => {
                print!("\x1B[2J\x1B[1;1H");
                stdout().flush()?;
                continue;
            }
            _ => {
                continue;
            }
        }
        return Ok(());
    }
}
