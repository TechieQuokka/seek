use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::{tempdir, NamedTempFile};
use std::io::Write;

#[test]
fn test_scan_single_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "This is a test file").unwrap();

    let mut cmd = Command::cargo_bin("seek").unwrap();
    cmd.args(["scan", "--file", temp_file.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn test_scan_eicar_test_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    // EICAR test string - safe test pattern recognized by antivirus software
    writeln!(temp_file, "X5O!P%@AP[4\\PZX54(P^)7CC)7}}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();

    let mut cmd = Command::cargo_bin("seek").unwrap();
    cmd.args(["scan", "--file", temp_file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("EICAR").or(predicate::str::contains("threat")));
}

#[test]
fn test_scan_directory() {
    let temp_dir = tempdir().unwrap();

    // Create test files
    let test_file1 = temp_dir.path().join("test1.txt");
    std::fs::write(&test_file1, "Clean test file 1").unwrap();

    let test_file2 = temp_dir.path().join("test2.txt");
    std::fs::write(&test_file2, "Clean test file 2").unwrap();

    let mut cmd = Command::cargo_bin("seek").unwrap();
    cmd.args(["scan", temp_dir.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn test_scan_nonexistent_file() {
    let mut cmd = Command::cargo_bin("seek").unwrap();
    cmd.args(["scan", "--file", "/nonexistent/file.txt"])
        .assert()
        .failure();
}

#[test]
fn test_scan_with_output_format() {
    let temp_dir = tempdir().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    std::fs::write(&test_file, "Test file content").unwrap();

    let mut cmd = Command::cargo_bin("seek").unwrap();
    cmd.args([
        "scan",
        "--format", "json",
        temp_dir.path().to_str().unwrap()
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("{"));
}