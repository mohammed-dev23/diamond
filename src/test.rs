#[cfg(test)]
pub mod test {
    use crate::{
        backend::safe::{MasterKey, PasswordChecker},
        commands::fuzzy,
    };

    #[test]
    pub fn test_weak_password() {
        let res = "password12345678"
            .to_string()
            .master_key_checker()
            .check_password_strength("master-key-test", "mohammedamarneh@gmail.com");
        match res {
            Ok(o) => eprintln!("ok {o}"),
            Err(e) => eprintln!("err {e}"),
        }
    }
    #[test]
    pub fn test_fuzzy() {
        fuzzy("test", None).unwrap();
    }
}
