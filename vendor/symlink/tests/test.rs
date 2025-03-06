use std::env::temp_dir;
use std::fs::{self, File};
use std::io;
use std::io::prelude::*;
use std::path::Path;

extern crate symlink;
use symlink::{symlink_auto, symlink_file, symlink_dir, remove_symlink_file, remove_symlink_dir};

const TEST_FILE_CONTENTS: &'static [u8] =
    b"This file was created for the purpose of testing the symlink crate.";

#[test]
fn test_symlink_file() {
    let temp = temp_dir();
    let file_path = temp.join("symlink-crate-test-file");
    let symlink_path = temp.join("symlink-crate-test-file-symlink");
    test_file_symlink(&file_path, &symlink_path, |src, dst| symlink_file(src, dst));
}

#[test]
fn test_symlink_auto_file() {
    let temp = temp_dir();
    let file_path = temp.join("symlink-crate-test-auto-file");
    let symlink_path = temp.join("symlink-crate-test-auto-file-symlink");
    test_file_symlink(&file_path, &symlink_path, |src, dst| symlink_auto(src, dst));
}

#[test]
fn test_symlink_dir() {
    let temp = temp_dir();
    let dir_path = temp.join("symlink-crate-test-dir");
    let symlink_path = temp.join("symlink-crate-test-dir-symlink");
    test_dir_symlink(&dir_path, &symlink_path, |src, dst| symlink_dir(src, dst));
}

#[test]
fn test_symlink_auto_dir() {
    let temp = temp_dir();
    let dir_path = temp.join("symlink-crate-test-auto-dir");
    let symlink_path = temp.join("symlink-crate-test-auto-dir-symlink");
    test_dir_symlink(&dir_path, &symlink_path, |src, dst| symlink_auto(src, dst));
}

fn test_file_symlink<F>(file_path: &Path, symlink_path: &Path, create_symlink: F)
where F: for<'a> FnOnce(&'a Path, &'a Path) -> io::Result<()> {
    let mut file = File::create(file_path).unwrap();
    file.write_all(TEST_FILE_CONTENTS).unwrap();
    // Ensure it’s all written to disk properly.
    drop(file);

    // Note: the destination is *deliberately* a relative path. TODO: this would probably be a bad
    // idea. On Windows, the paths are relative to the working directory (including treating X:foo
    // as foo in the X: working directory); on Linux, I don’t know? If it’s anything like ln, it’s
    // a path relative to the symlink.
    //create_symlink("symlink-crate-test-file", symlink_path).unwrap();
    create_symlink(file_path, symlink_path).unwrap();

    assert!(symlink_path.symlink_metadata().unwrap().file_type().is_symlink());

    file = File::open(symlink_path).unwrap();
    let mut contents = vec![];
    file.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, TEST_FILE_CONTENTS);
    drop(file);

    // TODO: use some kind of temp file wrapper which makes sure that the files gets deleted if
    // they get created.
    remove_symlink_file(symlink_path).unwrap();
    fs::remove_file(file_path).unwrap();

    assert!(!symlink_path.exists());
    assert!(!file_path.exists());
}

fn test_dir_symlink<F>(dir_path: &Path, symlink_path: &Path, create_symlink: F)
where F: for<'a> FnOnce(&'a Path, &'a Path) -> io::Result<()> {
    fs::create_dir(dir_path).unwrap();

    let file_path = dir_path.join("test-file");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(TEST_FILE_CONTENTS).unwrap();
    drop(file);

    create_symlink(dir_path, symlink_path).unwrap();

    assert!(symlink_path.symlink_metadata().unwrap().file_type().is_symlink());

    file = File::open(symlink_path.join("test-file")).unwrap();
    let mut contents = vec![];
    file.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, TEST_FILE_CONTENTS);
    drop(file);

    // TODO: use some kind of temp file wrapper which makes sure that the files gets deleted if
    // they get created.
    remove_symlink_dir(symlink_path).unwrap();
    fs::remove_file(&file_path).unwrap();
    fs::remove_dir(dir_path).unwrap();

    assert!(!symlink_path.exists());
    assert!(!file_path.exists());
    assert!(!dir_path.exists());
}
