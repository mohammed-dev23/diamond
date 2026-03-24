use crate::commands::{Flags, add, fuzzy, get, note, remove, rename, search, update};
use crate::{
    backend::{
        parser::Token,
        safe::{
            AnyHowErrHelper, Checkers, FileChecker, MasterKey, PasswordChecker, id_does_not_existe,
        },
    },
    commands::{export, import},
};
use anyhow::anyhow;
use colored::Colorize;

pub const ID_INDEX: usize = 1;
pub const EF_INDEX: usize = 1;

pub fn add_helper(
    mut index: usize,
    data: &Vec<String>,
    data_token: &[String],
) -> anyhow::Result<()> {
    let username_email = data
        .get_token(&index)
        .checker("identifier".to_string())
        .pe()?;

    index += 1;
    let password = data
        .get_token(&index)
        .checker("password".to_string())
        .pe()?;
    index += 1;
    let id = data.get_token(&index).checker("id".to_string()).pe()?;

    index += 1;
    let note = data_token.get(index).map(|s| s.as_str());

    let note = if let Some(note) = note {
        if note.contains(".json") {
            index -= 1;
            None
        } else {
            Some(note)
        }
    } else {
        None
    };

    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    let master_key = helper_master_key()
        .checker("Master-key".to_string())?
        .to_string()
        .master_key_checker()
        .pe();

    let master_key = master_key
        .check_password_strength("Master-key", username_email)
        .pe()?;

    let id = &id.to_string().check_existing_ids(id, ef).pe()?;

    add(username_email, id, password, &master_key, note, ef).pe()?;
    Ok(())
}

pub fn get_helper(
    mut index: usize,
    data: &Vec<String>,
    data_token: &[String],
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe()?;

    index += 1;
    let flags = Flags {
        clip: Some(
            data.get_token(&index)
                .map(|s| s == "--with-clipboard")
                .unwrap_or(false),
        ),
        encodded: Some(
            data.get_token(&index)
                .map(|s| s == "--with-hex-fromat")
                .unwrap_or(false),
        ),
        qrcode: Some(
            data.get_token(&index)
                .map(|s| s == "--as-qrcode")
                .unwrap_or(false),
        ),
    };

    if !flags.clip.unwrap_or(true)
        || !flags.encodded.unwrap_or(true)
        || !flags.qrcode.unwrap_or(true)
    {
        index -= 1;
    }

    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    if ef.is_some_and(|s| s.contains("--")) {
        return Err(anyhow!("You can use flags in the place of <external file>"));
    }

    id_does_not_existe(id, ID_INDEX, data, ef).pe()?;

    let master_key = helper_master_key()
        .checker("Master-Key".to_string())?
        .to_string()
        .master_key_checker()
        .pe()?;

    get(id, &master_key, flags, ef).pe()?;
    Ok(())
}

pub fn remove_helper(
    mut index: usize,
    data: &Vec<String>,
    data_token: &[String],
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe()?;

    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    id_does_not_existe(id, ID_INDEX, data, ef).pe()?;

    let master_key = helper_master_key()
        .checker("Master-Key".to_string())?
        .to_string()
        .master_key_checker()
        .pe()?;

    remove(id, ef, &master_key).pe()?;
    Ok(())
}

pub fn search_helper(
    mut index: usize,
    data: &Vec<String>,
    data_token: &[String],
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe()?;
    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    id_does_not_existe(id, ID_INDEX, data, ef).pe()?;

    search(id, ef).pe()?;
    Ok(())
}

pub fn export_helper(
    data: &Vec<String>,
    mut index: usize,
    data_token: &[String],
) -> anyhow::Result<()> {
    let name_of_export = data
        .get_token(&index)
        .checker("name of export".to_string())
        .pe()?;

    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    let master_key = helper_master_key()
        .checker("Master-Key".to_string())?
        .to_string()
        .master_key_checker()
        .pe()
        .check_password_strength("Master-Key", "")
        .pe()?;

    export(ef, name_of_export, &master_key).pe()?;
    Ok(())
}

pub fn import_helper(data: &Vec<String>, mut index: usize) -> anyhow::Result<()> {
    let path_of_exported_vault = data
        .get_token(&index)
        .checker("the name of the vault".to_string())
        .pe()?;

    index += 1;
    let new_name = data
        .get_token(&index)
        .checker("the path of the vault".to_string())
        .pe()?;

    let master_key = helper_master_key()
        .checker("Master-Key".to_string())?
        .to_string()
        .master_key_checker()
        .pe()?;

    import(&master_key, new_name, path_of_exported_vault).pe()?;

    println!(">>{}", "import is done!".bright_cyan().bold());
    Ok(())
}

pub fn help_helper_() -> anyhow::Result<()> {
    use colored::Colorize;

    println!(
        ">> [{}] --[{}]",
        "help".bright_purple().bold(),
        "add/get/remove/search/clear/exit/list/update/rename/note/fuzzy/switch-vault/toma"
            .bright_yellow()
            .bold()
    );
    println!(
        ">> <{}: used to add passwords and so on>",
        "add".bright_purple().bold(),
    );
    println!(">> <{}: used to get data>", "get".bright_purple().bold());
    println!(
        ">> <{}: used to remove data from the file>",
        "remove".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to search for data by there id name>",
        "search".bright_purple().bold()
    );
    println!(
        ">> <{}: used to clear the term>",
        "clear".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to exit the program>",
        "exit".bright_purple().bold()
    );
    println!(
        ">> <{}: used to list all the data>",
        "list".bright_purple().bold(),
    );

    println!(
        ">> <{}: used to generate new password>",
        "gp".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to export vaults>",
        "export".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to import vaults using the master-key>",
        "import".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to change the password and the identifier by there id and using the master-key>",
        "update".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to rename ids>",
        "rename".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to change a note or add it>",
        "note".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to make fuzzy search to grap any match using a keyword>",
        "fuzzy".bright_purple().bold(),
    );
    println!(
        ">> <{}: as the name represents it's used to switch vaults using there files>",
        "switch-vault".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to change things in the config file like [{}/{}/{}/{}]>",
        "toma".bright_purple().bold(),
        "username".bright_yellow().bold(),
        "main-vault-path".bright_yellow().bold(),
        "toml-file-path".bright_yellow().bold(),
        "allies".bright_yellow().bold(),
    );
    Ok(())
}

pub fn help_helper(data: &Vec<String>, index: usize) -> anyhow::Result<()> {
    use colored::Colorize;

    match data.get_token(&index).unwrap_or_default() {
        "--add" => {
            println!(
                ">>{}: [{}] [{}] [{}] [{}] [{}] [<{}>] [<{}>]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "add".bright_yellow().bold(),
                "identifier".bright_yellow().bold(),
                "password".bright_yellow().bold(),
                "id".bright_yellow().bold(),
                "Option: note".bright_yellow().bold(),
                "Option: external path".bright_yellow().bold(),
            );
        }
        "--get" => {
            println!(
                ">>{}: [{}] [{}] [{}] --[{}] [<{}>]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "get".bright_yellow().bold(),
                "id".bright_yellow().bold(),
                "flag [--with-clipboard/--as-qrcode/--with-hex-format]"
                    .bright_yellow()
                    .bold(),
                "Option: external path".bright_yellow().bold(),
            );
        }
        "--remove" => {
            println!(
                ">>{}: [{}] [{}] [{}] [<{}>]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "remove".bright_yellow().bold(),
                "id".bright_yellow().bold(),
                "Option: external path".bright_yellow().bold()
            );
        }
        "--list" => {
            println!(
                ">>{}: [{}] [{}] [<{}>]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "list".bright_yellow().bold(),
                "Option: external path".bright_yellow().bold(),
            );
        }
        "--search" => {
            println!(
                ">>{}: [{}] [{}] [{}] [<{}>]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "search".bright_yellow().bold(),
                "id".bright_yellow().bold(),
                "Option: external path".bright_yellow().bold(),
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
                "Option: external path".bright_yellow().bold(),
            );
        }
        "--import" => {
            println!(
                ">>{}: [{}] [{}] [{}] [{}]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "import".bright_yellow().bold(),
                "(import file).json".bright_yellow().bold(),
                "new name for the imported vault".bright_yellow().bold(),
            );
        }
        "--rename" => {
            println!(
                ">>{}: [{}] [{}] [{}] [{}] [<{}>]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "rename".bright_yellow().bold(),
                "old-id".bright_yellow().bold(),
                "new-id".bright_yellow().bold(),
                "Option: external path".bright_yellow().bold(),
            );
        }
        "--update" => {
            println!(
                ">>{}: [{}] [{}] [{}] [{}] [{}] [<{}>]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "update".bright_yellow().bold(),
                "id".bright_yellow().bold(),
                "new-identifier".bright_yellow().bold(),
                "new-password".bright_yellow().bold(),
                "Option: external path".bright_yellow().bold(),
            );
        }
        "--note" => {
            println!(
                ">>{}: [{}] [{}] [{}] [<{}>] [<{}>]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "note".bright_yellow().bold(),
                "id".bright_yellow().bold(),
                "note".bright_yellow().bold(),
                "Option: external path".bright_yellow().bold(),
            );
        }
        "--fuzzy" => {
            println!(
                ">>{}: [{}] [{}] [{}] [<{}>]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "fuzzy".bright_yellow().bold(),
                "keyword".bright_yellow().bold(),
                "Option: external path".bright_yellow().bold(),
            )
        }
        "--switch-vault" => {
            println!(
                ">>{}: [{}] [{}] [{}]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "switch-vault".bright_yellow().bold(),
                "path of vault(.json)".bright_yellow().bold(),
            )
        }
        "--toma" => {
            println!(
                ">>{}: [{}] [{}] [{}] [{}]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "toma".bright_yellow().bold(),
                "[username/main-vault-path/toml-file-path/allies]"
                    .bright_yellow()
                    .bold(),
                "new-value".bright_yellow().bold(),
            )
        }
        "-l" => {
            help_helper_()?;
        }
        _ => {
            if !data.get_token(&index).unwrap_or_default().is_empty() {
                println!(
                    ">> The flag [{}] you used is not vaild flag please use [{} -l] to check all the available flags",
                    data.get_token(&index)?.bright_red().bold(),
                    "help".bright_yellow().bold()
                )
            } else {
                help_helper_()?;
            }
        }
    }
    Ok(())
}

fn helper_master_key() -> anyhow::Result<String> {
    let format = format!(
        ">>{} Your {}{}{} :",
        "Enter".bright_cyan().bold(),
        "<".bright_cyan().bold(),
        "Master-Key".bright_magenta().bold(),
        ">".bright_cyan().bold()
    );
    let master_key_input = rpassword::prompt_password(format)?;

    if master_key_input.is_empty() {
        return Err(anyhow!("You Entered nothing!"));
    }

    Ok(master_key_input)
}

pub fn rename_helper(
    data: &Vec<String>,
    data_token: &[String],
    mut index: usize,
) -> anyhow::Result<()> {
    let old_id = data.get_token(&index).checker("old id".to_string()).pe()?;
    index += 1;
    let new_id = data.get_token(&index).checker("new id".to_string()).pe()?;
    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    id_does_not_existe(old_id, ID_INDEX, data, ef).pe()?;

    rename(old_id, new_id, ef)?;
    Ok(())
}

pub fn update_helper(
    data: &Vec<String>,
    data_token: &[String],
    mut index: usize,
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe()?;
    index += 1;
    let new_username = data
        .get_token(&index)
        .checker("identifier".to_string())
        .pe()?;
    index += 1;
    let new_password = data
        .get_token(&index)
        .checker("password".to_string())
        .pe()?;
    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    id_does_not_existe(id, ID_INDEX, data, ef).pe()?;
    let master_key = helper_master_key()
        .checker("master-key".to_string())?
        .to_string()
        .master_key_checker()
        .pe()?;

    update(&master_key, ef, id, new_username, new_password)?;

    Ok(())
}

pub fn note_helper(
    data: &Vec<String>,
    data_token: &[String],
    mut index: usize,
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe()?;
    index += 1;
    let notee = data_token
        .get(index)
        .map(|s| s.to_string())
        .checker("note".to_string())
        .pe()?;
    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    id_does_not_existe(id, ID_INDEX, data, ef).pe()?;
    note(id, &notee, ef)?;
    Ok(())
}

pub fn fuzzy_helper(
    data: &Vec<String>,
    data_token: &[String],
    mut index: usize,
) -> anyhow::Result<()> {
    let key_word = data.get_token(&index).checker("keyword".to_string()).pe()?;
    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    fuzzy(key_word, ef)?;
    Ok(())
}
