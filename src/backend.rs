pub mod safe {
    use anyhow::anyhow;
    use colored::Colorize;

    pub trait ArgsChecker {
        type Out;

        fn checker(self, res: String) -> Self::Out;
    }

    pub trait AnyHowErrHelper {
        fn pe(self) -> Self;
    }

    impl<T> ArgsChecker for anyhow::Result<T> {
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
}

pub mod parser {
    use anyhow::{Ok, anyhow};

    pub fn parse_input() -> anyhow::Result<Vec<String>> {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let data: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
        return Ok(data);
    }

    pub trait Token {
        fn get_token(&self, index: usize) -> anyhow::Result<String>;
    }

    impl Token for Vec<String> {
        fn get_token(&self, index: usize) -> anyhow::Result<String> {
            if self.is_empty() && index == 0 {
                return Ok(String::new());
            }

            if let Some(d) = self.get(index) {
                return Ok(d.to_string());
            } else {
                return Err(anyhow!("Couldn't get data from the parser!"));
            }
        }
    }
}
