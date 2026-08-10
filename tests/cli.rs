use std::process::Command;

use tempfile::tempdir;

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_astdiff"))
}

#[test]
fn malformed_javascript_fails_with_a_diagnostic() {
    let directory = tempdir().unwrap();
    let old = directory.path().join("old.js");
    let new = directory.path().join("new.js");
    std::fs::write(&old, "function broken( {").unwrap();
    std::fs::write(&new, "function valid() {}").unwrap();

    let output = command().arg(old).arg(new).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("syntax error"));
}

#[test]
fn removed_no_op_flags_are_not_advertised() {
    let output = command().arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(!help.contains("--map1"));
    assert!(!help.contains("--map2"));
    assert!(!help.contains("--report-path"));
}

#[test]
fn rename_export_is_written_in_old_to_new_direction() {
    let directory = tempdir().unwrap();
    let old = directory.path().join("old.js");
    let new = directory.path().join("new.js");
    let mappings = directory.path().join("renames.yaml");
    std::fs::write(&old, "function oldName(){return 1}").unwrap();
    std::fs::write(&new, "function newName(){return 1}").unwrap();

    let output = command()
        .arg(&old)
        .arg(&new)
        .arg("--compact")
        .arg("--export-mappings")
        .arg(&mappings)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: std::collections::HashMap<String, String> =
        serde_yaml::from_str(&std::fs::read_to_string(mappings).unwrap()).unwrap();
    assert_eq!(parsed.get("oldName").map(String::as_str), Some("newName"));
}

#[test]
fn dump_cli_round_trip_preserves_unchanged_matches() {
    let directory = tempdir().unwrap();
    let old = directory.path().join("old.js");
    let new = directory.path().join("new.js");
    let dump = directory.path().join("analysis.astdump");
    std::fs::write(&old, "function oldName(){return 1}").unwrap();
    std::fs::write(&new, "function newName(){return 1}").unwrap();

    let create = command()
        .arg(&old)
        .arg(&new)
        .arg("--compact")
        .arg("--dump")
        .arg(&dump)
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );

    let load = command().arg("load").arg(&dump).output().unwrap();
    assert!(
        load.status.success(),
        "{}",
        String::from_utf8_lossy(&load.stderr)
    );
    assert!(String::from_utf8_lossy(&load.stdout).contains("Total matches: 1"));

    let query = command()
        .arg("query")
        .arg(&dump)
        .arg("match")
        .arg("oldName")
        .output()
        .unwrap();
    assert!(
        query.status.success(),
        "{}",
        String::from_utf8_lossy(&query.stderr)
    );
    assert!(String::from_utf8_lossy(&query.stdout).contains("-> newName"));
}

#[test]
fn dump_with_an_empty_side_loads_and_queries_without_panicking() {
    let directory = tempdir().unwrap();
    let old = directory.path().join("old.js");
    let new = directory.path().join("new.js");
    let dump = directory.path().join("analysis.astdump");
    std::fs::write(&old, "function removed(){return 1}").unwrap();
    std::fs::write(&new, "").unwrap();

    assert!(command()
        .arg(&old)
        .arg(&new)
        .arg("--compact")
        .arg("--dump")
        .arg(&dump)
        .status()
        .unwrap()
        .success());
    let query = command()
        .arg("query")
        .arg(&dump)
        .arg("find")
        .arg("removed")
        .output()
        .unwrap();
    assert!(
        query.status.success(),
        "{}",
        String::from_utf8_lossy(&query.stderr)
    );
    assert!(String::from_utf8_lossy(&query.stdout).contains("old.js"));
}
