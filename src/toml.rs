use std::{fs, io::Read};

use serde::{Deserialize, Serialize};

use crate::vault::home_dirr;

#[derive(Serialize, Deserialize)]
pub struct Toml {
    pub customization: Customization,
    pub dependencies: Dependencies,
}

#[derive(Serialize, Deserialize)]
pub struct Customization {
    pub username: String,
}
#[derive(Serialize, Deserialize)]
pub struct Dependencies {}

pub fn toml() -> anyhow::Result<Toml> {
    let mut readed_toml = String::new();
    let read_toml =
        fs::File::open(home_dirr()?.join("diamond/gem.toml"))?.read_to_string(&mut readed_toml);

    if read_toml.is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        toml_init()?;
    }

    let get_data: Toml = toml::from_str(&readed_toml)?;
    Ok(get_data)
}

pub fn toml_init() -> anyhow::Result<()> {
    let username = "def".to_string();

    let def_toml = Toml {
        customization: Customization { username: username },
        dependencies: Dependencies {},
    };

    let make_data = toml::to_string(&def_toml)?;
    fs::write(home_dirr()?.join("diamond/gem.toml"), make_data)?;
    Ok(())
}
