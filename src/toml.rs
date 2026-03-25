use std::{fs, io::Read, path::PathBuf};

use anyhow::anyhow;
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::{
    backend::{
        parser::Token,
        safe::{AnyHowErrHelper, Checkers},
    },
    commands::atomic_writer,
    vault::home_dirr,
};

#[derive(Serialize, Deserialize, Default)]
pub struct Toml {
    pub customization: Customization,
    pub dependencies: Dependencies,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Customization {
    pub username: String,
    pub allies: Option<Allies>,
}
#[derive(Serialize, Deserialize, Default)]
pub struct Dependencies {
    pub main_vault_path: String,
    pub toml_path: String,
}
#[derive(Serialize, Deserialize, Default)]
pub struct Allies {
    pub add: Option<String>,
    pub get: Option<String>,
    pub list: Option<String>,
    pub remove: Option<String>,
    pub search: Option<String>,
    pub export: Option<String>,
    pub exit: Option<String>,
    pub clear: Option<String>,
    pub gp: Option<String>,
    pub import: Option<String>,
    pub help: Option<String>,
    pub rename: Option<String>,
    pub update: Option<String>,
    pub note: Option<String>,
    pub fuzzy: Option<String>,
    pub switch_vault: Option<String>,
    pub toma: Option<String>,
}

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

    let main_vault_path = home_dirr()?
        .join("diamond/gem.json")
        .to_string_lossy()
        .to_string();
    let toml_path = home_dirr()?
        .join("diamond/gem.toml")
        .to_string_lossy()
        .to_string();

    let def_toml = Toml {
        customization: Customization {
            username,
            allies: None,
        },
        dependencies: Dependencies {
            main_vault_path,
            toml_path,
        },
    };

    let make_data = toml::to_string(&def_toml)?;
    fs::write(home_dirr()?.join("diamond/gem.toml"), make_data)?;
    Ok(())
}

pub fn toma(data: &Vec<String>, mut index: usize) -> anyhow::Result<()> {
    let mut toml_file = toml()?;
    let change = data
        .get_token(&index)
        .checker("what to change".to_string())
        .pe()?;
    index += 1;

    let changer = |checker_mas: &str, indexx: &usize| {
        data.get_token(indexx)
            .checker(checker_mas.to_string())
            .pe()
    };

    match change.trim() {
        "main-vault-path" => {
            let new_path = changer("path.json", &index)?;
            toml_file.dependencies.main_vault_path =
                home_dirr()?.join(new_path).to_string_lossy().to_string();
        }
        "toml-file-path" => {
            let new_path = changer("path.json", &index)?;
            toml_file.dependencies.toml_path =
                home_dirr()?.join(new_path).to_string_lossy().to_string();
        }
        "username" => {
            let new_user = changer("new-username", &index)?;
            toml_file.customization.username = new_user.to_string();
        }
        "allies" => {
            let ali_to_change = changer("allie to change", &index)?;
            index += 1;
            let new_allies = changer("new-allies", &index)?;

            match ali_to_change.trim() {
                "add" => {
                    toml_file.customization.allies.get_or_insert_default().add =
                        Some(new_allies.to_string());
                }
                "get" => {
                    toml_file.customization.allies.get_or_insert_default().get =
                        Some(new_allies.to_string());
                }
                "remove" => {
                    toml_file
                        .customization
                        .allies
                        .get_or_insert_default()
                        .remove = Some(new_allies.to_string());
                }
                "list" => {
                    toml_file.customization.allies.get_or_insert_default().list =
                        Some(new_allies.to_string());
                }
                "rename" => {
                    toml_file
                        .customization
                        .allies
                        .get_or_insert_default()
                        .rename = Some(new_allies.to_string());
                }
                "clear" => {
                    toml_file.customization.allies.get_or_insert_default().clear =
                        Some(new_allies.to_string());
                }
                "exit" => {
                    toml_file.customization.allies.get_or_insert_default().exit =
                        Some(new_allies.to_string());
                }
                "export" => {
                    toml_file
                        .customization
                        .allies
                        .get_or_insert_default()
                        .export = Some(new_allies.to_string());
                }
                "import" => {
                    toml_file
                        .customization
                        .allies
                        .get_or_insert_default()
                        .import = Some(new_allies.to_string());
                }
                "search" => {
                    toml_file
                        .customization
                        .allies
                        .get_or_insert_default()
                        .search = Some(new_allies.to_string());
                }
                "fuzzy" => {
                    toml_file.customization.allies.get_or_insert_default().fuzzy =
                        Some(new_allies.to_string());
                }
                "switch-vault" => {
                    toml_file
                        .customization
                        .allies
                        .get_or_insert_default()
                        .switch_vault = Some(new_allies.to_string());
                }
                "update" => {
                    toml_file
                        .customization
                        .allies
                        .get_or_insert_default()
                        .update = Some(new_allies.to_string());
                }
                "note" => {
                    toml_file.customization.allies.get_or_insert_default().note =
                        Some(new_allies.to_string());
                }
                "toma" => {
                    toml_file.customization.allies.get_or_insert_default().toma =
                        Some(new_allies.to_string());
                }
                _ => {}
            }
        }
        _ => return Err(anyhow!(">>Unkown flag [{}]", change)),
    }
    let json = toml::to_string(&toml_file)?;
    atomic_writer(&PathBuf::from(toml_file.dependencies.toml_path), &json)?;
    println!(">>{}!", "toma is done".bright_cyan().bold());
    Ok(())
}
