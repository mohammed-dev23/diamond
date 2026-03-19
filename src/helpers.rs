use crate::commands::{add, fuzzy, get, note, remove, rename, search, update};
use crate::{
    backend::{
        cleaner::extract_string_value_from_result,
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

pub fn add_helper(
    mut index: usize,
    data: &Vec<String>,
    data_token: &[String],
) -> anyhow::Result<()> {
    let username_email = data
        .get_token(&index)
        .checker("username/email/etc..".to_string())
        .pe();

    index += 1;
    let password = data.get_token(&index).checker("password".to_string()).pe();
    index += 1;
    let id = data.get_token(&index).checker("id".to_string()).pe();

    index += 1;
    let note = data_token.get(index).map(|s| s.as_str());
    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    let username_4_check_password_strengrh = extract_string_value_from_result(&username_email);

    if let (Ok(us), Ok(p), Ok(u)) = (username_email, password, &id) {
        let master_key = helper_master_key()
            .checker("Master-key".to_string())?
            .to_string()
            .master_key_checker()
            .pe();

        let master_key =
            master_key.check_password_strength("Master-key", &username_4_check_password_strengrh);
        if let Ok(m) = master_key {
            let u = &u.to_string().check_existing_ids(u, ef).pe();
            if let Ok(u) = u {
                add(us, u, p, &m, note, ef).pe()?;
            }
        }
    }
    Ok(())
}

pub fn get_helper(
    mut index: usize,
    data: &Vec<String>,
    data_token: &[String],
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe();

    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    id_does_not_existe(
        id.as_ref().map_err(|_| anyhow!("moving id error!"))?,
        ID_INDEX,
        data,
        ef,
    )
    .pe()?;

    if let Ok(o) = id {
        let master_key = helper_master_key()
            .checker("Master-Key".to_string())?
            .to_string()
            .master_key_checker()
            .pe();

        if let Ok(p) = master_key {
            get(o, &p, ef).pe()?
        }
    }
    Ok(())
}

pub fn remove_helper(
    mut index: usize,
    data: &Vec<String>,
    data_token: &[String],
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe();

    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    id_does_not_existe(
        id.as_ref().map_err(|_| anyhow!("moving id error!"))?,
        ID_INDEX,
        data,
        ef,
    )
    .pe()?;

    if let Ok(o) = id {
        let master_key = helper_master_key()
            .checker("Master-Key".to_string())?
            .to_string()
            .master_key_checker()
            .pe();

        if let Ok(master) = master_key {
            remove(o, ef, &master).pe()?;
        }
    }

    Ok(())
}

pub fn search_helper(
    mut index: usize,
    data: &Vec<String>,
    data_token: &[String],
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe();
    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    id_does_not_existe(
        id.as_ref().map_err(|_| anyhow!("moving id error!"))?,
        ID_INDEX,
        data,
        ef,
    )
    .pe()?;

    if let Ok(o) = id {
        search(o, ef).pe()?
    }

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
        .pe();

    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    if let Ok(name) = name_of_export {
        let master_key = helper_master_key()
            .checker("Master-Key".to_string())?
            .to_string()
            .master_key_checker()
            .pe()
            .check_password_strength("Master-Key", "");

        if let Ok(master) = master_key {
            export(ef, name, &master).pe()?;
        }
    }
    Ok(())
}

pub fn import_helper(data: &Vec<String>, mut index: usize) -> anyhow::Result<()> {
    let path_of_exported_vault = data
        .get_token(&index)
        .checker("the name of the vault".to_string())
        .pe();

    index += 1;
    let new_name = data
        .get_token(&index)
        .checker("the path of the vault".to_string())
        .pe();

    if let (Ok(name), Ok(pov)) = (new_name, path_of_exported_vault) {
        let master_key = helper_master_key()
            .checker("Master-Key".to_string())?
            .to_string()
            .master_key_checker()
            .pe()
            .check_password_strength("Master-key", "")
            .pe();

        if let Ok(mk) = master_key {
            import(&mk, name, pov).pe()?;
        }
    }

    println!(">>{}", "import is done!".bright_cyan().bold());
    Ok(())
}

pub fn help_helper_() -> anyhow::Result<()> {
    use colored::Colorize;

    println!(
        ">> [{}] --[{}]",
        "help".bright_purple().bold(),
        "add/get/remove/search/clear/exit/list/update/rename/note"
            .bright_yellow()
            .bold()
    );
    println!(
        ">> <{}: used to add passwords and so on> / <{}: used to get data>",
        "add".bright_purple().bold(),
        "get".bright_purple().bold()
    );
    println!(
        ">> <{}: used to remove data from the file> / <{}: used to search for data by there id name>",
        "remove".bright_purple().bold(),
        "search".bright_purple().bold()
    );
    println!(
        ">> <{}: used to clear the term> / <{}: used to exit the program>",
        "clear".bright_purple().bold(),
        "exit".bright_purple().bold()
    );
    println!(
        ">> <{}: used to list all the data>",
        "list".bright_purple().bold(),
    );

    println!(
        ">> <{}: used to list all the data> / <{}: used to generate new password>",
        "list".bright_purple().bold(),
        "gp".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to export vaults> / <{}: used to import vaults using the master-key>",
        "export".bright_purple().bold(),
        "import".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to change the password and the identifier by there id and using the master-key> / <{}: used to rename ids>",
        "update".bright_purple().bold(),
        "rename".bright_purple().bold(),
    );
    println!(
        ">> <{}: used to change a note or add it>",
        "note".bright_purple().bold(),
    );
    Ok(())
}

pub fn help_helper(data: &Vec<String>, index: usize) -> anyhow::Result<()> {
    use colored::Colorize;
    match data.get_token(&index)?.trim() {
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
                ">>{}: [{}] [{}] [{}] [<{}>]",
                "Usage".bright_green().bold(),
                "diamond".bright_blue().bold(),
                "get".bright_yellow().bold(),
                "id".bright_yellow().bold(),
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
        "-l" => {
            help_helper_()?;
        }
        _ => {
            if !data.get_token(&1)?.is_empty() {
                println!(
                    ">> The flag [{}] you used is not vaild flag please use [{} -l] to check all the available flags",
                    data.get_token(&1)?.bright_red().bold(),
                    "help".bright_yellow().bold()
                )
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
    let old_id = data.get_token(&index).checker("old id".to_string()).pe();
    index += 1;
    let new_id = data.get_token(&index).checker("new id".to_string()).pe();
    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    if let (Ok(old_idd), Ok(new_idd)) = (old_id, new_id) {
        id_does_not_existe(old_idd, ID_INDEX, data, ef).pe()?;
        rename(old_idd, new_idd, ef)?;
    }
    Ok(())
}

pub fn update_helper(
    data: &Vec<String>,
    data_token: &[String],
    mut index: usize,
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe();
    index += 1;
    let new_username = data
        .get_token(&index)
        .checker("identifier".to_string())
        .pe();
    index += 1;
    let new_password = data.get_token(&index).checker("password".to_string()).pe();
    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    if let (Ok(id), Ok(username), Ok(password)) = (id, new_username, new_password) {
        id_does_not_existe(id, ID_INDEX, data, ef).pe()?;
        let master_key = helper_master_key()
            .checker("master-key".to_string())?
            .to_string()
            .master_key_checker()
            .pe();

        if let Ok(master_key) = master_key {
            update(&master_key, ef, id, username, password)?;
        }
    }
    Ok(())
}

pub fn note_helper(
    data: &Vec<String>,
    data_token: &[String],
    mut index: usize,
) -> anyhow::Result<()> {
    let id = data.get_token(&index).checker("id".to_string()).pe();
    index += 1;
    let notee = data_token
        .get(index)
        .map(|s| s.to_string())
        .checker("note".to_string())
        .pe();
    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    if let (Ok(id), Ok(notee)) = (id, notee) {
        id_does_not_existe(id, ID_INDEX, data, ef).pe()?;
        note(id, &notee, ef)?;
    }
    Ok(())
}

pub fn fuzzy_helper(
    data: &Vec<String>,
    data_token: &[String],
    mut index: usize,
) -> anyhow::Result<()> {
    let key_word = data.get_token(&index).checker("keyword".to_string()).pe();
    index += 1;
    let ef = data_token.get(index).map(|s| s.as_str());

    if let Ok(key) = key_word {
        fuzzy(key, ef)?;
    }
    Ok(())
}
