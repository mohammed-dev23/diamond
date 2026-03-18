pub mod safe {
    use core::fmt;

    use anyhow::anyhow;
    use colored::Colorize;
    use zxcvbn::Score;

    use crate::{backend::parser::Token, crypto::read_json};

    pub trait Checkers {
        type Out;

        fn checker(self, res: String) -> Self::Out;
    }

    pub trait MasterKey {
        type Out;

        fn master_key_checker(self) -> Self::Out;
    }

    pub trait FileChecker {
        type Out;

        fn check_existing_ids(self, id: &str, ef: Option<&str>) -> Self::Out;
    }

    pub trait AnyHowErrHelper {
        fn pe(self) -> Self;
    }

    impl<T> Checkers for anyhow::Result<T> {
        type Out = anyhow::Result<T>;
        fn checker(self, res: String) -> Self::Out {
            match self {
                Ok(o) => Ok(o),
                Err(_) => Err(anyhow!("missing value [{}]", res)),
            }
        }
    }

    impl<T> Checkers for Option<T> {
        type Out = anyhow::Result<T>;
        fn checker(self, res: String) -> Self::Out {
            match self {
                Some(s) => Ok(s),
                None => Err(anyhow!("missing value [{}]", res)),
            }
        }
    }

    impl MasterKey for String {
        type Out = anyhow::Result<String>;

        fn master_key_checker(self) -> Self::Out {
            if self.len() >= 16 {
                Ok(self)
            } else {
                Err(anyhow!("The master key must be 16 characters at least "))
            }
        }
    }

    impl FileChecker for String {
        type Out = anyhow::Result<String>;

        fn check_existing_ids(self, id: &str, ef: Option<&str>) -> Self::Out {
            let read_json = read_json(ef)?;

            if let Some(o) = read_json.iter().find(|s| s.entry.id == id) {
                Err(anyhow!(
                    "the id does already exist try another one or add special symbols beside it ! <{}>",
                    o.entry.id.to_string().bright_yellow().bold()
                ))
            } else {
                Ok(self)
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
    #[derive(PartialEq, Debug)]
    pub enum PasswordCheckerT<'s> {
        VeryWeak(&'s str),
        Weak(&'s str),
        Fair(&'s str),
        Good(&'s str),
        Strong(&'s str),
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

        fn check_password_strength(self, pwd: &str, context: &str) -> Self::Out;
    }

    impl PasswordChecker for anyhow::Result<String> {
        type Out = anyhow::Result<String>;

        fn check_password_strength(self, pwd: &str, context: &str) -> Self::Out {
            let sself = self?;

            let score = zxcvbn::zxcvbn(&sself, &[context]).score();

            let sc = match score {
                Score::Zero => PasswordCheckerT::VeryWeak(pwd),
                Score::One => PasswordCheckerT::Weak(pwd),
                Score::Two => PasswordCheckerT::Fair(pwd),
                Score::Three => PasswordCheckerT::Good(pwd),
                Score::Four => PasswordCheckerT::Strong(pwd),
                _ => unreachable!(),
            };

            if sc == PasswordCheckerT::VeryWeak(pwd)
                || sc == PasswordCheckerT::Weak(pwd)
                || sc == PasswordCheckerT::Fair(pwd)
            {
                return Err(anyhow!("{}", sc));
            }
            println!(">>{}", sc);
            Ok(sself)
        }
    }

    pub fn id_does_not_existe(
        id: &str,
        token: usize,
        data: &Vec<String>,
        ef: Option<&str>,
    ) -> anyhow::Result<()> {
        if id
            .to_string()
            .check_existing_ids(data.get_token(&token)?, ef)
            .is_ok()
        {
            return Err(anyhow!("The id does not exist!"));
        }
        Ok(())
    }
}

pub mod parser {
    use anyhow::{Ok, anyhow};

    pub fn parse_input(data: String) -> anyhow::Result<Vec<String>> {
        let data: Vec<String> = data.split_whitespace().map(|s| s.to_string()).collect();
        Ok(data)
    }

    pub fn parse_input_by_token(data: String) -> anyhow::Result<Vec<String>> {
        let mut content_in = String::new();
        let mut _in_ = false;
        let mut vec = Vec::new();

        for i in data.chars() {
            match i {
                '<' => {
                    if !content_in.trim().is_empty() {
                        vec.push(content_in.trim().to_string());
                    }
                    _in_ = true;
                    content_in.clear();
                }
                '>' => {
                    if _in_ {
                        vec.push(content_in.trim().to_string());
                        content_in.clear();
                        _in_ = false;
                    }
                }
                _ => {
                    if _in_ {
                        content_in.push(i);
                    } else if i.is_whitespace() {
                        if !content_in.trim().is_empty() {
                            vec.push(content_in.trim().to_string());
                            content_in.clear();
                        }
                    } else {
                        content_in.push(i);
                    }
                }
            }
        }
        Ok(vec)
    }

    pub trait Token {
        fn get_token(&self, index: &usize) -> anyhow::Result<&str>;
    }

    impl Token for Vec<String> {
        fn get_token(&self, index: &usize) -> anyhow::Result<&str> {
            if self.is_empty() && *index == 0 {
                return Ok("");
            }

            if let Some(d) = self.get(*index) {
                Ok(d.as_str())
            } else {
                Err(anyhow!("Couldn't get data from the parser!"))
            }
        }
    }
}

pub mod cleaner {
    pub fn extract_string_value_from_result(value: &anyhow::Result<&str>) -> String {
        if let Ok(o) = value {
            o.to_string()
        } else {
            String::new()
        }
    }
}
