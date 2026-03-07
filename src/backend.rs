pub mod safe {
    use core::fmt;
    use std::{fs, ops::Deref};

    use anyhow::anyhow;
    use colored::Colorize;
    use zxcvbn::Score;

    use crate::{
        backend::parser::Token,
        dec_enc::{action_pass_maker, action_pass_val, home_dirr, read_json},
    };

    pub trait Checkers {
        type Out;

        fn checker(self, res: String) -> Self::Out;
    }

    pub trait MasterKeyV {
        type Out;

        fn master_key_checker(self) -> Self::Out;
    }

    pub trait FileChecker {
        type Out;

        fn check_existing_ids(self, id: &str, ef: Option<&String>) -> Self::Out;
    }

    pub trait AnyHowErrHelper {
        fn pe(self) -> Self;
    }

    impl<T> Checkers for anyhow::Result<T> {
        type Out = anyhow::Result<T>;
        fn checker(self, res: String) -> Self::Out {
            match self {
                Ok(o) => return Ok(o),
                Err(_) => {
                    return Err(anyhow!("missing value [{}]", res));
                }
            }
        }
    }

    impl MasterKeyV for String {
        type Out = anyhow::Result<String>;

        fn master_key_checker(self) -> Self::Out {
            if self.len() >= 16 {
                return Ok(self);
            } else {
                return Err(anyhow!("The master key must be 16 characters at least "));
            }
        }
    }

    impl FileChecker for String {
        type Out = anyhow::Result<String>;

        fn check_existing_ids(self, id: &str, ef: Option<&String>) -> Self::Out {
            let read_json = read_json(ef)?;

            if let Some(o) = read_json.iter().find(|s| s.id == id) {
                return Err(anyhow!(
                    "the url/app does already exist try another one or add special symbols beside it ! <{}>",
                    o.id.to_string().bright_yellow().bold()
                ));
            } else {
                return Ok(self);
            }
        }
    }

    impl<T> AnyHowErrHelper for anyhow::Result<T> {
        fn pe(self) -> Self {
            if let Err(e) = &self {
                eprintln!(
                    ">>{}: due to [{}]",
                    "Error".bright_red(),
                    e.to_string().bright_red().bold()
                );
            }
            self
        }
    }

    pub fn action_password(ac_pass: &str) -> anyhow::Result<()> {
        let res = if fs::File::open(
            home_dirr()?
                .join("obsidian/obs_password.txt")
                .to_string_lossy()
                .to_string(),
        )
        .is_err()
        {
            action_pass_maker(ac_pass)
        } else {
            action_pass_val(ac_pass)
        };

        res
    }

    #[derive(PartialEq, Debug)]
    pub enum PasswordCheckerT<'s> {
        VeryWeak(&'s String),
        Weak(&'s String),
        Fair(&'s String),
        Good(&'s String),
        Strong(&'s String),
    }

    impl fmt::Display for PasswordCheckerT<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                PasswordCheckerT::VeryWeak(pwd) => {
                    write!(
                        f,
                        "the password <{}> is [{}]",
                        pwd.bright_yellow().bold(),
                        "very Weak".bright_red().bold()
                    )
                }
                PasswordCheckerT::Weak(pwd) => {
                    write!(
                        f,
                        "the password <{}> is [{}]",
                        pwd.bright_yellow().bold(),
                        "Weak".bright_red().bold()
                    )
                }
                PasswordCheckerT::Fair(pwd) => {
                    write!(
                        f,
                        "the password <{}> is [{}]",
                        pwd.bright_yellow().bold(),
                        "fair".bright_yellow().bold()
                    )
                }
                PasswordCheckerT::Good(pwd) => {
                    write!(
                        f,
                        "the password <{}> is [{}]",
                        pwd.bright_yellow().bold(),
                        "good".bright_cyan().bold()
                    )
                }
                PasswordCheckerT::Strong(pwd) => {
                    write!(
                        f,
                        "the password <{}> is [{}]",
                        pwd.bright_yellow().bold(),
                        "strong".bright_green().bold()
                    )
                }
            }
        }
    }

    pub trait PasswordChecker {
        type Out;

        fn check_password_(
            &self,
            pwd: &String,
            context: anyhow::Result<&String, &anyhow::Error>,
        ) -> Self::Out;
    }

    impl PasswordChecker for String {
        type Out = anyhow::Result<String>;

        fn check_password_(
            &self,
            pwd: &String,
            context: anyhow::Result<&String, &anyhow::Error>,
        ) -> Self::Out {
            let score = zxcvbn::zxcvbn(
                &self,
                &[context
                    .map_err(|_| anyhow!("missing username/email"))?
                    .as_str()],
            )
            .score();

            let sc = match score {
                Score::Zero => PasswordCheckerT::VeryWeak(pwd),
                Score::One => PasswordCheckerT::Weak(pwd),
                Score::Two => PasswordCheckerT::Fair(pwd),
                Score::Three => PasswordCheckerT::Good(pwd),
                Score::Four => PasswordCheckerT::Strong(pwd),
                _ => unreachable!(),
            };

            if sc == PasswordCheckerT::VeryWeak(pwd) || sc == PasswordCheckerT::Weak(pwd) {
                return Err(anyhow!("{}", sc));
            }
            println!(">>{}", sc);
            return Ok(self.to_string());
        }
    }

    pub fn does_not_e(
        id: &String,
        token: usize,
        data: &Vec<String>,
        ef: Option<&String>,
    ) -> anyhow::Result<()> {
        if id
            .deref()
            .to_string()
            .check_existing_ids(&*data.get_token(&token)?, ef)
            .is_ok()
        {
            return Err(anyhow!("The url/app does not exist!"));
        }
        Ok(())
    }
}

pub mod parser {
    use anyhow::{Ok, anyhow};

    pub fn parse_input(data: String) -> anyhow::Result<Vec<String>> {
        let data: Vec<String> = data.split_whitespace().map(|s| s.to_string()).collect();
        return Ok(data);
    }

    pub trait Token {
        fn get_token(&self, index: &usize) -> anyhow::Result<String>;
    }

    impl Token for Vec<String> {
        fn get_token(&self, index: &usize) -> anyhow::Result<String> {
            if self.is_empty() && *index == 0 {
                return Ok(String::new());
            }

            if let Some(d) = self.get(*index) {
                return Ok(d.to_string());
            } else {
                return Err(anyhow!("Couldn't get data from the parser!"));
            }
        }
    }
}
