use assert_cmd::Command;
use predicates::prelude::*;
use std::process::Command as StdCommand;

#[test]
fn test_cli_help_command() {
    let mut cmd = Command::cargo_bin("seek").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Seek - Rust antivirus CLI"));
}

#[test]
fn test_cli_version_command() {
    let mut cmd = Command::cargo_bin("seek").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("seek"));
}

#[test]
fn test_scan_command_help() {
    let mut cmd = Command::cargo_bin("seek").unwrap();
    cmd.args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Scan"));
}

#[cfg(feature = "integration-tests")]
#[test]
fn test_scan_current_directory() {
    let mut cmd = Command::cargo_bin("seek").unwrap();
    cmd.args(["scan", "--quick"])
        .assert()
        .success();
}

#[test]
fn test_invalid_command() {
    let mut cmd = Command::cargo_bin("seek").unwrap();
    cmd.arg("invalid-command")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}