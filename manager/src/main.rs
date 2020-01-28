extern crate clap;
extern crate rpassword;
extern crate serde_json;
extern crate wayland_client;

use clap::{load_yaml, App};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::path::Path;

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
    //let pass = rpassword::read_password_from_tty(Some("Enter your password: ")).unwrap();
    let data: Records = load_data();
    let yaml = load_yaml!("cli.yaml");
    let app_m = App::from(yaml).get_matches();

    match app_m.subcommand() {
        ("add", Some(sub_m)) => {
            process_add(sub_m, data);
        }
        ("remove", Some(sub_m)) => {
            process_remove(sub_m, data);
        }
        ("copy", Some(sub_m)) => {
            process_copy(sub_m, data);
        }
        ("list", Some(sub_m)) => {
            process_list(sub_m, data);
        }
        _ => {} // Either no subcommand or one not tested for...
    }
}
fn process_add(sub_m: &clap::ArgMatches<'_>, mut data: Records) {
    let key = sub_m.value_of("KEY").unwrap();
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
    save_data(&data);
}

fn process_remove(sub_m: &clap::ArgMatches<'_>, mut data: Records) {
    let key = sub_m.value_of("KEY").unwrap();

    data.records.retain(|record| record.name != key);
    save_data(&data);
}

fn process_copy(sub_m: &clap::ArgMatches<'_>, data: Records) {
    let key = sub_m.value_of("KEY").unwrap();
    let record: &Record = find_record(&data, key.to_owned());
    let (display, _) = wayland_client::Display::connect_to_env().expect("Failed to connect to the wayland server.");
    let mut clipboard = smithay_clipboard::WaylandClipboard::new(&display);
    println!("{}", record.password);
    clipboard.store(None, record.password.to_owned());
}

fn process_list(_sub_m: &clap::ArgMatches<'_>, data: Records) {
    for record in data.records {
        println!("{}", record.name);
    }
}

fn load_data() -> Records {
    if !Path::new("db.dat").exists() {
        let f = open_writer();
        let records = Records { records: vec![] };
        serde_json::to_writer(f, &records).expect("Unable to write initial data to file");
    }

    let f = open_reader();
    serde_json::from_reader(f).expect("db.dat has invalid structure")
}
fn save_data(data: &Records) {
    let f = open_writer();
    serde_json::to_writer(f, data).expect("Unable to write data to file");
}

fn open_writer() -> BufWriter<File> {
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .open("db.dat")
        .expect("Unable to open file");
    BufWriter::new(f)
}

fn open_reader() -> BufReader<File> {
    let f = OpenOptions::new()
        .read(true)
        .open("db.dat")
        .expect("Unable to open file");
    BufReader::new(f)
}

fn generate_password() -> String {
    "".to_owned()
}

fn find_record(data: &Records, key: String) -> &Record {
    data.records
        .iter()
        .find(|record| record.name == key)
        .expect("Unable to find record")
}

#[cfg(test)]
mod tests;
