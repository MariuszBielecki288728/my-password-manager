extern crate clap;
extern crate passwords;
extern crate rpassword;
extern crate serde_json;

use clap::{load_yaml, App};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::pwhash::Salt;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::Nonce;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::str;

#[derive(Serialize, Deserialize, Debug)]
struct Records {
    records: Vec<Record>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Record {
    name: String,
    password: String,
}

fn main() {
    let yaml = load_yaml!("cli.yaml");
    let app_m = App::from(yaml).get_matches();
    let pass = rpassword::read_password_from_tty(Some("Enter your master password: ")).unwrap();
    let data: Records = load_data(&pass);

    match app_m.subcommand() {
        ("add", Some(sub_m)) => {
            process_add(sub_m, data, &pass);
        }
        ("update", Some(sub_m)) => {
            process_update(sub_m, data, &pass);
        }
        ("remove", Some(sub_m)) => {
            process_remove(sub_m, data, &pass);
        }
        ("show", Some(sub_m)) => {
            process_copy(sub_m, data);
        }
        ("list", Some(sub_m)) => {
            process_list(sub_m, data);
        }
        _ => {} // Either no subcommand or one not tested for...
    }
}

fn process_add(sub_m: &clap::ArgMatches<'_>, mut data: Records, password: &str) {
    let key = sub_m.value_of("KEY").unwrap();
    if is_present(&data, &key) {
        panic!("Unable to add record with given key, because it already exists")
    }
    let passwd;
    if sub_m.is_present("auto-generate") {
        passwd = generate_password();
    } else {
        passwd = rpassword::read_password_from_tty(Some("Enter password to store: "))
            .expect("Unable to read password");
    }
    data.records.push(Record {
        name: key.to_owned(),
        password: passwd.to_owned(),
    });
    save_data(&data, password);
}

fn process_update(sub_m: &clap::ArgMatches<'_>, mut data: Records, password: &str) {
    let key = sub_m.value_of("KEY").unwrap();
    if !is_present(&data, &key) {
        panic!("Unable to find record with given key")
    }
    let passwd;
    if sub_m.is_present("auto-generate") {
        passwd = generate_password();
    } else {
        passwd = rpassword::read_password_from_tty(Some("Enter password to store: "))
            .expect("Unable to read password");
    }
    data.records.retain(|record| record.name != key);
    data.records.push(Record {
        name: key.to_owned(),
        password: passwd.to_owned(),
    });
    save_data(&data, password);
}

fn process_remove(sub_m: &clap::ArgMatches<'_>, mut data: Records, password: &str) {
    let key = sub_m.value_of("KEY").unwrap();

    data.records.retain(|record| record.name != key);
    save_data(&data, password);
}

fn process_copy(sub_m: &clap::ArgMatches<'_>, data: Records) {
    let key = sub_m.value_of("KEY").unwrap();
    let record: &Record = find_record(&data, key.to_owned());
    println!("{}", record.password);
}

fn process_list(_sub_m: &clap::ArgMatches<'_>, data: Records) {
    for record in data.records {
        println!("{}", record.name);
    }
}

fn load_data(password: &str) -> Records {
    if !Path::new("db.dat").exists() {
        create_data_file(password);
    }

    let f = open_reader("db.dat");
    let encrypted_data: Vec<u8> = serde_json::from_reader(f).expect("Unable to read from db.dat");
    let decrypted_data = decrypt_(password, encrypted_data);
    serde_json::from_str(&decrypted_data).expect("Unable to read json data")
}

fn create_data_file(password: &str) {
    let f = open_writer("db.dat", true);
    let records = Records { records: vec![] };
    let json = serde_json::to_string(&records).expect("Unable to convert records to json");
    let encrypted_json = encrypt_(password, &json);
    serde_json::to_writer(f, &encrypted_json).expect("Unable to write initial data to file");
}

fn save_data(data: &Records, password: &str) {
    let f = open_writer("db.dat", true);

    let json = serde_json::to_string(data).expect("Unable to convert records to json");
    let encrypted_json = encrypt_(password, &json);
    serde_json::to_writer(f, &encrypted_json).expect("Unable data to file");
}

fn open_writer(filename: &str, truncate: bool) -> BufWriter<File> {
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(truncate)
        .open(filename)
        .expect("Unable to open file");
    BufWriter::new(f)
}

fn open_reader(filename: &str) -> BufReader<File> {
    let f = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("Unable to open file");
    BufReader::new(f)
}

fn generate_password() -> String {
    let pg = passwords::PasswordGenerator {
        length: 8,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        strict: true,
    };
    pg.generate_one().expect("Unable to generate password")
}

fn find_record(data: &Records, key: String) -> &Record {
    data.records
        .iter()
        .find(|record| record.name == key)
        .expect("Unable to find record")
}

fn is_present(data: &Records, key: &str) -> bool {
    data.records.iter().any(|record| record.name == key)
}

fn encrypt_(key: &str, plain_text: &str) -> Vec<u8> {
    let passwd = key.as_bytes();
    let salt = pwhash::gen_salt();
    let mut k = secretbox::Key([0; secretbox::KEYBYTES]);
    let secretbox::Key(ref mut kb) = k;
    pwhash::derive_key(
        kb,
        passwd,
        &salt,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    )
    .unwrap();
    let nonce = secretbox::gen_nonce();
    let plaintext = plain_text.as_bytes();
    let ciphertext = secretbox::seal(plaintext, &nonce, &secretbox::Key(*kb));
    save_metadata(nonce, salt);
    ciphertext
    // let their_plaintext = secretbox::open(&ciphertext, &nonce, &key).unwrap();
}

fn decrypt_(key: &str, encrypted_text: Vec<u8>) -> String {
    let (nonce, salt) = load_metadata();
    let passwd = key.as_bytes();
    let mut k = secretbox::Key([0; secretbox::KEYBYTES]);
    let secretbox::Key(ref mut kb) = k;
    pwhash::derive_key(
        kb,
        passwd,
        &salt,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    )
    .unwrap();
    str::from_utf8(
        &secretbox::open(&encrypted_text, &nonce, &secretbox::Key(*kb))
            .expect("Unable to decrypt data")[..],
    )
    .unwrap()
    .to_owned()
}

fn save_metadata(nonce: Nonce, salt: Salt) {
    let f = open_writer("nonce.dat", true);
    serde_json::to_writer(f, &nonce).expect("Unable to write nonce to file");
    let f = open_writer("salt.dat", true);
    serde_json::to_writer(f, &salt).expect("Unable to write data to file");
}

fn load_metadata() -> (Nonce, Salt) {
    let f_nonce = open_reader("nonce.dat");
    let f_salt = open_reader("salt.dat");
    (
        serde_json::from_reader(f_nonce).expect("Unable to read from nonce.dat"),
        serde_json::from_reader(f_salt).expect("Unable to read from salt.dat"),
    )
}

#[cfg(test)]
mod tests;
