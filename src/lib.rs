use orion::aead;
#[allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::io::prelude::*;
use zeroize::Zeroize;

const DEFAULT_PASSWORD_LENGTH: u32 = 30;

const ENCRYPTION_SALT: [u8; 64] = [
    0xe3, 0x1a, 0x0c, 0x9b, 0x6b, 0x01, 0xbe, 0x19, 0xc5, 0x44, 0x7f, 0xb9, 0x2f, 0x79, 0x94, 0x91,
    0xcf, 0xae, 0xb6, 0xda, 0x09, 0x0c, 0x24, 0xf3, 0x0f, 0xab, 0x2b, 0xf2, 0x4a, 0x1c, 0x39, 0xf7,
    0xc1, 0xfc, 0xdc, 0x61, 0xc3, 0xf3, 0x15, 0xcf, 0x64, 0x76, 0x96, 0x25, 0xf9, 0xe6, 0xb1, 0x18,
    0x62, 0xbd, 0x03, 0x6a, 0x67, 0x2d, 0xbb, 0x42, 0x1c, 0xbb, 0xb3, 0x24, 0x83, 0x5f, 0x7e, 0x53,
];

const MASTER_PASS_SALT: [u8; 64] = [
    0xa1, 0x48, 0x48, 0x5a, 0x76, 0x31, 0xe5, 0x45, 0x65, 0xf4, 0xde, 0xb0, 0xbb, 0x3a, 0x8f, 0xcc,
    0xaa, 0x35, 0xff, 0x87, 0x7c, 0xd5, 0xcd, 0x4c, 0x4a, 0xbb, 0xbe, 0x21, 0x56, 0x5b, 0xe2, 0x7e,
    0x60, 0x70, 0xd6, 0x5c, 0x0e, 0x3a, 0xa6, 0x02, 0xf9, 0xa1, 0xc9, 0x37, 0x88, 0x2a, 0xe0, 0xdc,
    0x06, 0xcc, 0x25, 0xa6, 0x05, 0x8d, 0x75, 0x91, 0xc5, 0xdb, 0x0d, 0x90, 0xdb, 0xf3, 0x05, 0x8f,
];

type Result<T> = std::result::Result<T, Box<std::error::Error>>;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Ranpaman {
    master_password: Vec<u8>,
    encryption_key: Vec<u8>,
    file_path: Option<String>,
    data: Vec<Service>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Service {
    name: String,
    accounts: Vec<Account>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Account {
    login: String,
    include_special_characters: bool,
    revision: u32,
    custom_length: Option<u32>,
}

impl Drop for Ranpaman {
    fn drop(&mut self) {
        self.master_password.zeroize();
        self.encryption_key.zeroize();
    }
}

impl Ranpaman {
    pub fn new(mut master_password: String, file_path: Option<String>) -> Ranpaman {
        let config = argon2::Config::default();
        let pw = argon2::hash_raw(&master_password.as_bytes(), &MASTER_PASS_SALT, &config).unwrap();
        let key = argon2::hash_raw(&master_password.as_bytes(), &ENCRYPTION_SALT, &config).unwrap();
        master_password.zeroize();
        Ranpaman {
            master_password: pw,
            encryption_key: key,
            file_path,
            data: Vec::new(),
        }
    }

    pub fn add_account(
        &mut self,
        service_name: String,
        login: String,
        include_special_characters: bool,
        custom_length: Option<u32>,
    ) -> Result<()> {
        if service_name.is_empty() || login.is_empty() {
            //TODO: Return an error here
        }
        if let Some(length) = custom_length {
            if length < 1 {
                //TODO: Return an error here
            }
        }

        let account = Account {
            login,
            include_special_characters,
            revision: 0,
            custom_length,
        };
        match self
            .data
            .binary_search_by_key(&&service_name, |service| &service.name)
        {
            Ok(index) => {
                let service = &mut self.data.get_mut(index).unwrap();
                match service
                    .accounts
                    .binary_search_by_key(&&account.login, |account| &account.login)
                {
                    Ok(_) =>
                        /*Return an error here*/
                        {}
                    Err(index) => service.accounts.insert(index, account),
                }
            }
            Err(index) => self.data.insert(
                index,
                Service {
                    name: service_name,
                    accounts: vec![account],
                },
            ),
        };
        Ok(())
    }

    pub fn get_password(&self, service_name: &String, login: &String) -> Result<Vec<u8>>{
        if let Ok(accounts) = self
            .data
            .binary_search_by_key(&service_name, |service| &service.name)
            .map(|index| self.data[index].accounts){
                if let Ok(account) = accounts.binary_search_by_key(&login, |account| &account.login).map(|index| accounts[index]){

                }
            }
        Ok(Vec::new())
    }

    pub fn change_file_path(&mut self, new_path: Option<String>) -> Result<()> {
        match new_path {
            None => {
                if let Some(old_path) = &self.file_path {
                    std::fs::remove_file(old_path)?;
                    self.file_path = None;
                }
            }
            Some(new_path) => {
                let mut new_file = std::fs::File::create(&new_path)?;
                if let Some(old_path) = &self.file_path {
                    std::fs::remove_file(old_path)?;
                }
                self.file_path = Some(new_path);
                let encoded_self = bincode::serialize(&self).unwrap();
                let encrypted_self = aead::seal(
                    &aead::SecretKey::from_slice(&self.encryption_key).unwrap(),
                    &encoded_self,
                )
                .unwrap();
                new_file.write(&encrypted_self)?;
            }
        }

        Ok(())
    }

    pub fn write_to_file(&self) -> Result<()> {
        let encoded_self = bincode::serialize(&self).unwrap();
        let encrypted_self = aead::seal(
            &aead::SecretKey::from_slice(&self.encryption_key).unwrap(),
            &encoded_self,
        )
        .unwrap();
        std::fs::write(
            self.file_path.as_ref().ok_or("No file path specified")?,
            encrypted_self,
        )?;
        Ok(())
    }

    pub fn read_from_file(mut master_password: String, path: &str) -> Result<Ranpaman> {
        let read = std::fs::read(path)?;
        let config = argon2::Config::default();
        let key = argon2::hash_raw(&master_password.as_bytes(), &ENCRYPTION_SALT, &config).unwrap();
        master_password.zeroize();
        let decrypted = aead::open(&aead::SecretKey::from_slice(&key).unwrap(), &read).unwrap();
        Ok(bincode::deserialize(&decrypted)?)
    }

    pub fn get_file_path(&self) -> Option<&String> {
        self.file_path.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn master_password_generation() {
        let ranpaman = Ranpaman::new("masterpass".to_string(), Some("test_file".to_string()));
        assert_eq!(
            ranpaman.master_password,
            [
                223, 108, 222, 141, 127, 89, 120, 143, 166, 127, 41, 255, 155, 5, 5, 195, 198, 186,
                182, 18, 209, 221, 182, 64, 164, 34, 27, 230, 196, 48, 187, 237
            ]
        );
    }
    #[test]
    fn encryption_key_generation() {
        let ranpaman = Ranpaman::new("masterpass".to_string(), Some("test_file".to_string()));
        assert_eq!(
            ranpaman.encryption_key,
            [
                110, 249, 117, 224, 82, 86, 66, 21, 42, 235, 243, 204, 137, 226, 46, 12, 116, 161,
                243, 48, 201, 170, 187, 179, 80, 147, 37, 111, 124, 108, 191, 182
            ]
        );
    }

    #[test]
    fn read_write() {
        let path = "test_file";
        let ranpaman = Ranpaman::new("masterpass".to_string(), Some(path.to_string()));
        ranpaman.write_to_file().unwrap();
        let decoded = Ranpaman::read_from_file("masterpass".to_string(), path).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(ranpaman, decoded);
    }

    #[test]
    fn change_file_path() {
        let path = "test_file";
        let ranpaman = Ranpaman::new("masterpass".to_string(), Some(path.to_string()));
        ranpaman.write_to_file().unwrap();
        let mut decoded = Ranpaman::read_from_file("masterpass".to_string(), path).unwrap();
        let new_path = "other_test_file";
        decoded
            .change_file_path(Some(new_path.to_string()))
            .unwrap();
        let mut decoded = Ranpaman::read_from_file("masterpass".to_string(), new_path).unwrap();
        decoded.change_file_path(Some(path.to_string())).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(ranpaman, decoded);
    }

    #[test]
    fn get_file_path() {
        let path = "test_file1";
        let ranpaman = Ranpaman::new("masterpass".to_string(), Some(path.to_string()));
        assert_eq!(ranpaman.get_file_path(), Some(&path.to_string()));
    }
}
