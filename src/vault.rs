use crate::crypto::Fields;
use crate::toml;
use anyhow::anyhow;
use std::{env::home_dir, fs, path::PathBuf};

#[cfg(unix)]
pub fn set_perm_over_file(path: &PathBuf) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let file = fs::File::open(path)?;
    let mut perm = file.metadata()?.permissions();
    perm.set_mode(0o600);

    fs::set_permissions(path, perm)?;
    Ok(())
}

pub fn _init_() -> anyhow::Result<()> {
    let home_dir = home_dirr()?;
    fs::create_dir_all(home_dir.join("diamond"))?;

    if fs::File::open(home_dirr()?.join("diamond/gem.toml"))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        toml::toml_init()?;
    }

    if fs::File::open(home_dirr()?.join("diamond/gem.json"))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        let json_init = serde_json::to_string_pretty::<Vec<Fields>>(&vec![])?;
        let main_vault: PathBuf = toml()?.dependencies.main_vault_path.into();

        fs::write(main_vault, json_init)?;
    }
    Ok(())
}

pub fn home_dirr() -> anyhow::Result<PathBuf> {
    let home_dir = if let Some(h) = home_dir() {
        h
    } else {
        return Err(anyhow!("couldn't find home dir"));
    };

    Ok(home_dir)
}

pub fn print_mini_logo() {
    use colored::Colorize;
    println!(
        "{}",
        r#"      __________________
    .-'  \ _.-''-._ /  '-.
  .-/\   .'.      .'.   /\-.
 _'/  \.'   '.  .'   './  \'_
:======:======::======:======:
 '. '.  \     ''     /  .' .'
   '. .  \   :  :   /  . .'
     '.'  \  '  '  /  '.'
       ':  \:    :/  :'
         '. \    / .'
           '.\  /.'    @Safe Place For Your Information To Be In
             '\/'"#
            .bright_cyan()
            .bold()
    );
}
