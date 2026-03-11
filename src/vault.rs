use crate::toml;
use anyhow::anyhow;
use std::{env::home_dir, fs, path::PathBuf};

#[cfg(unix)]
pub fn set_perm_over_file(path: &PathBuf) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let file = fs::File::open(path)?;
    let mut perm = file.metadata()?.permissions();
    perm.set_mode(0o600);

    fs::set_permissions(&path, perm)?;
    Ok(())
}

pub fn _init_() -> anyhow::Result<()> {
    let home_dir = home_dirr()?;
    fs::create_dir_all(home_dir.join("diamond").to_string_lossy().to_string())?;

    if fs::File::open(home_dirr()?.join("diamond/gem.toml"))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        toml::toml_init()?;
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
        r#"
       ╱╲
      ╱  ╲    D I A M O N D
     ╱ ╱╲ ╲   
    ╱ ╱  ╲ ╲  Secure Vault
    ╲ ╲  ╱ ╱
     ╲ ╲╱ ╱
      ╲  ╱
       ╲╱
    "#
        .bright_cyan()
    );
}
