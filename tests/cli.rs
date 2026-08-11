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

#[test]
fn analysis_cli_writes_and_queries_positioned_artifact() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("input.js");
    let artifact = directory.path().join("input.astir");
    std::fs::write(
        &source,
        "function greet(name) { return name; } greet('world');",
    )
    .unwrap();

    let create = command()
        .arg("analyze")
        .arg(&source)
        .arg("--output")
        .arg(&artifact)
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    assert!(artifact.exists());

    let summary = command()
        .arg("analysis")
        .arg(&artifact)
        .arg("summary")
        .output()
        .unwrap();
    assert!(
        summary.status.success(),
        "{}",
        String::from_utf8_lossy(&summary.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&summary.stdout).unwrap();
    assert_eq!(summary["profile"], "astdiff.analysis.v1");
    assert_eq!(summary["symbols"], 2);
    assert_eq!(summary["references"], 2);
    assert_eq!(summary["def_uses"], 2);
    assert_eq!(summary["calls"], 1);

    let symbol = command()
        .arg("analysis")
        .arg(&artifact)
        .arg("symbol")
        .arg("0")
        .output()
        .unwrap();
    assert!(
        symbol.status.success(),
        "{}",
        String::from_utf8_lossy(&symbol.stderr)
    );
    let symbol: serde_json::Value = serde_json::from_slice(&symbol.stdout).unwrap();
    assert_eq!(symbol["name"], "greet");
    assert_eq!(symbol["kind"], "function");

    for query in ["reference", "def-use", "call"] {
        let output = command()
            .arg("analysis")
            .arg(&artifact)
            .arg(query)
            .arg("0")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{query}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["index"], 0);
    }
}

#[test]
fn lineage_and_semantic_names_work_end_to_end_without_leaking_default_names() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("source.js");
    let target = directory.path().join("target.js");
    let lineage = directory.path().join("lineage.json");
    let names = directory.path().join("names.json");
    let propagated = directory.path().join("propagated.json");
    let propagated_js = directory.path().join("propagated.js");
    std::fs::write(
        &source,
        "function sentinelGeneratedName(value) { return value + 1; }",
    )
    .unwrap();
    std::fs::write(&target, "function a(b) { return b + 1; }").unwrap();

    let first = command()
        .arg("lineage")
        .arg(&source)
        .arg(&target)
        .arg("--output")
        .arg(&lineage)
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_bytes = std::fs::read(&lineage).unwrap();
    let summary: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert!(summary["accepted"].as_u64().unwrap() >= 1);
    assert!(!String::from_utf8_lossy(&first.stdout).contains("sentinelGeneratedName"));
    assert!(!String::from_utf8_lossy(&first.stdout).contains(source.to_str().unwrap()));

    let second = command()
        .arg("lineage")
        .arg(&source)
        .arg(&target)
        .arg("--output")
        .arg(&lineage)
        .output()
        .unwrap();
    assert!(second.status.success());
    assert_eq!(first_bytes, std::fs::read(&lineage).unwrap());

    let export = command()
        .arg("names")
        .arg("export")
        .arg(&source)
        .arg("--output")
        .arg(&names)
        .output()
        .unwrap();
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&names).unwrap()).unwrap();
    assert_eq!(document["redacted"], true);
    assert!(!document.to_string().contains("sentinelGeneratedName"));
    let symbol_id = document["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["kind"] == "function")
        .unwrap()["symbol_id"]
        .as_str()
        .unwrap()
        .to_string();

    let set = command()
        .arg("names")
        .arg("set")
        .arg(&names)
        .arg(&symbol_id)
        .arg("increment_value")
        .arg("--expected-revision")
        .arg("0")
        .arg("--origin")
        .arg("agent")
        .output()
        .unwrap();
    assert!(
        set.status.success(),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );
    let stale = command()
        .arg("names")
        .arg("clear")
        .arg(&names)
        .arg(&symbol_id)
        .arg("--expected-revision")
        .arg("0")
        .output()
        .unwrap();
    assert!(!stale.status.success());
    let approve = command()
        .arg("names")
        .arg("approve")
        .arg(&names)
        .arg(&symbol_id)
        .arg("--expected-revision")
        .arg("1")
        .output()
        .unwrap();
    assert!(
        approve.status.success(),
        "{}",
        String::from_utf8_lossy(&approve.stderr)
    );

    let propagate = command()
        .arg("names")
        .arg("propagate")
        .arg(&names)
        .arg(&lineage)
        .arg(&source)
        .arg(&target)
        .arg("--output")
        .arg(&propagated)
        .arg("--render-output")
        .arg(&propagated_js)
        .output()
        .unwrap();
    assert!(
        propagate.status.success(),
        "{}",
        String::from_utf8_lossy(&propagate.stderr)
    );
    let propagated: serde_json::Value =
        serde_json::from_slice(&std::fs::read(propagated).unwrap()).unwrap();
    assert_eq!(propagated["redacted"], true);
    assert!(propagated["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["semantic_name"] == "increment_value" && entry["state"] == "approved"));
    assert_eq!(propagated["events"].as_array().unwrap().len(), 1);
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "function a(b) { return b + 1; }"
    );
    assert_eq!(
        std::fs::read_to_string(propagated_js).unwrap(),
        "function increment_value(b) {\n  return b + 1;\n}\n"
    );
}

#[test]
fn names_render_recreates_a_minified_target_with_variable_names() {
    let directory = tempdir().unwrap();
    let target = directory.path().join("target.js");
    let names = directory.path().join("target.names.json");
    let rendered = directory.path().join("target-readable.js");
    let original = "function a(b){const c=b+1;return c}";
    std::fs::write(&target, original).unwrap();

    let export = command()
        .arg("names")
        .arg("export")
        .arg(&target)
        .arg("--output")
        .arg(&names)
        .arg("--include-generated-names")
        .output()
        .unwrap();
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&names).unwrap()).unwrap();
    let names_by_generated = document["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["generated_name"].as_str().unwrap().to_string(),
                entry["symbol_id"].as_str().unwrap().to_string(),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();

    let mut revision = 0;
    for (generated, semantic) in [("a", "calculate_total"), ("b", "items"), ("c", "total")] {
        let symbol_id = names_by_generated.get(generated).unwrap();
        let set = command()
            .arg("names")
            .arg("set")
            .arg(&names)
            .arg(symbol_id)
            .arg(semantic)
            .arg("--expected-revision")
            .arg(revision.to_string())
            .arg("--origin")
            .arg("test")
            .output()
            .unwrap();
        assert!(
            set.status.success(),
            "{}",
            String::from_utf8_lossy(&set.stderr)
        );
        revision += 1;
        let approve = command()
            .arg("names")
            .arg("approve")
            .arg(&names)
            .arg(symbol_id)
            .arg("--expected-revision")
            .arg(revision.to_string())
            .arg("--origin")
            .arg("test")
            .output()
            .unwrap();
        assert!(
            approve.status.success(),
            "{}",
            String::from_utf8_lossy(&approve.stderr)
        );
        revision += 1;
    }

    let render = command()
        .arg("names")
        .arg("render")
        .arg(&names)
        .arg(&target)
        .arg("--output")
        .arg(&rendered)
        .output()
        .unwrap();
    assert!(
        render.status.success(),
        "{}",
        String::from_utf8_lossy(&render.stderr)
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
    assert_eq!(
        std::fs::read_to_string(rendered).unwrap(),
        "function calculate_total(items) {\n  const total = items + 1;\n  return total\n}\n"
    );
    let overwrite = command()
        .arg("names")
        .arg("render")
        .arg(&names)
        .arg(&target)
        .arg("--output")
        .arg(&target)
        .output()
        .unwrap();
    assert!(!overwrite.status.success());
    assert_eq!(std::fs::read_to_string(target).unwrap(), original);
}

#[test]
fn semantic_name_propagation_rejects_a_forged_lineage_binding() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("source.js");
    let target = directory.path().join("target.js");
    let lineage = directory.path().join("lineage.json");
    let names = directory.path().join("names.json");
    let output = directory.path().join("output.json");
    std::fs::write(&source, "function sourceName(x) { return x; }").unwrap();
    std::fs::write(&target, "function a(y) { return y; }").unwrap();
    assert!(command()
        .arg("lineage")
        .arg(&source)
        .arg(&target)
        .arg("-o")
        .arg(&lineage)
        .output()
        .unwrap()
        .status
        .success());
    assert!(command()
        .arg("names")
        .arg("export")
        .arg(&source)
        .arg("-o")
        .arg(&names)
        .output()
        .unwrap()
        .status
        .success());

    let mut forged: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&lineage).unwrap()).unwrap();
    forged["matches"][0]["source_symbol_id"] = serde_json::Value::String("00".repeat(32));
    std::fs::write(&lineage, serde_json::to_vec_pretty(&forged).unwrap()).unwrap();
    let result = command()
        .arg("names")
        .arg("propagate")
        .arg(&names)
        .arg(&lineage)
        .arg(&source)
        .arg(&target)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
}

#[test]
fn source_map_cli_validates_and_looks_up_with_redacted_defaults() {
    let directory = tempdir().unwrap();
    let map = directory.path().join("synthetic.map");
    std::fs::write(
        &map,
        r#"{"version":3,"sources":["synthetic-source.js"],"sourcesContent":["const privateSentinel = 1;"],"names":["semanticSentinel"],"mappings":"AAAAA"}"#,
    )
    .unwrap();

    let rejected = command()
        .arg("map")
        .arg("validate")
        .arg(&map)
        .output()
        .unwrap();
    assert!(!rejected.status.success());

    let valid = command()
        .arg("map")
        .arg("validate")
        .arg(&map)
        .arg("--allow-sources-content")
        .output()
        .unwrap();
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    let valid: serde_json::Value = serde_json::from_slice(&valid.stdout).unwrap();
    assert_eq!(valid["valid"], true);
    assert_eq!(valid["segments"], 1);

    let lookup = command()
        .arg("map")
        .arg("lookup")
        .arg(&map)
        .arg("--line")
        .arg("0")
        .arg("--column")
        .arg("0")
        .arg("--allow-sources-content")
        .output()
        .unwrap();
    assert!(lookup.status.success());
    let text = String::from_utf8(lookup.stdout).unwrap();
    assert!(!text.contains("synthetic-source"));
    assert!(!text.contains("semanticSentinel"));
    assert!(!text.contains("privateSentinel"));
    let lookup: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(lookup["mapping"], "mapped");
    assert_eq!(lookup["coordinate_basis"], "zero_based_utf16");
    assert_eq!(lookup["original_line"], 0);

    let explicit = command()
        .arg("map")
        .arg("lookup")
        .arg(&map)
        .arg("--line")
        .arg("0")
        .arg("--column")
        .arg("0")
        .arg("--allow-sources-content")
        .arg("--include-source-names")
        .output()
        .unwrap();
    assert!(explicit.status.success());
    let explicit = String::from_utf8(explicit.stdout).unwrap();
    assert!(explicit.contains("synthetic-source.js"));
    assert!(explicit.contains("semanticSentinel"));
    assert!(!explicit.contains("privateSentinel"));
}

#[test]
fn source_map_cli_preserves_ambiguity_and_positioned_cache_binding() {
    let directory = tempdir().unwrap();
    let map = directory.path().join("synthetic.map");
    let generated = directory.path().join("bundle.js");
    let cache = directory.path().join("bundle.astsm");
    std::fs::write(
        &map,
        r#"{"version":3,"sources":["first.js","second.js"],"names":[],"mappings":"AAAA,ACAA;;"}"#,
    )
    .unwrap();
    std::fs::write(&generated, "const value = 1;\n").unwrap();

    let ambiguous = command()
        .arg("map")
        .arg("lookup")
        .arg(&map)
        .arg("--line")
        .arg("2")
        .arg("--column")
        .arg("10")
        .output()
        .unwrap();
    assert!(ambiguous.status.success());
    let ambiguous: serde_json::Value = serde_json::from_slice(&ambiguous.stdout).unwrap();
    assert_eq!(ambiguous["mapping"], "ambiguous");
    assert_eq!(ambiguous["count"], 2);
    assert_eq!(ambiguous["positions"][0]["source_index"], 0);
    assert_eq!(ambiguous["positions"][1]["source_index"], 1);
    assert!(!ambiguous.to_string().contains("first.js"));

    let create = command()
        .arg("map")
        .arg("cache")
        .arg(&map)
        .arg(&generated)
        .arg("--output")
        .arg(&cache)
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    assert!(cache.exists());

    let validate = command()
        .arg("map")
        .arg("cache-validate")
        .arg(&cache)
        .arg(&generated)
        .output()
        .unwrap();
    assert!(validate.status.success());
    let validate: serde_json::Value = serde_json::from_slice(&validate.stdout).unwrap();
    assert_eq!(validate["valid"], true);
    assert_eq!(validate["segments"], 2);

    let cached = command()
        .arg("map")
        .arg("cache-lookup")
        .arg(&cache)
        .arg(&generated)
        .arg("--line")
        .arg("2")
        .arg("--column")
        .arg("10")
        .output()
        .unwrap();
    assert!(cached.status.success());
    let cached: serde_json::Value = serde_json::from_slice(&cached.stdout).unwrap();
    assert_eq!(cached, ambiguous);

    std::fs::write(&generated, "different generated bytes\n").unwrap();
    let stale = command()
        .arg("map")
        .arg("cache-validate")
        .arg(&cache)
        .arg(&generated)
        .output()
        .unwrap();
    assert!(!stale.status.success());
}

#[test]
fn map_bound_lineage_requires_the_same_maps_during_name_propagation() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("source.js");
    let target = directory.path().join("target.js");
    let source_map = directory.path().join("source.map");
    let target_map = directory.path().join("target.map");
    let lineage = directory.path().join("lineage.json");
    let names = directory.path().join("names.json");
    let propagated = directory.path().join("propagated.json");
    std::fs::write(&source, "function descriptive(value) { return value + 1; }").unwrap();
    std::fs::write(&target, "function a(b) { return b + 1; }").unwrap();
    let map_bytes = r#"{"version":3,"sources":["original.js"],"names":[],"mappings":"AAAA"}"#;
    std::fs::write(&source_map, map_bytes).unwrap();
    std::fs::write(&target_map, map_bytes).unwrap();

    let matched = command()
        .arg("lineage")
        .arg(&source)
        .arg(&target)
        .arg("--source-map-source")
        .arg(&source_map)
        .arg("--source-map-target")
        .arg(&target_map)
        .arg("--output")
        .arg(&lineage)
        .output()
        .unwrap();
    assert!(
        matched.status.success(),
        "{}",
        String::from_utf8_lossy(&matched.stderr)
    );
    assert!(command()
        .arg("names")
        .arg("export")
        .arg(&source)
        .arg("--output")
        .arg(&names)
        .output()
        .unwrap()
        .status
        .success());

    let missing_maps = command()
        .arg("names")
        .arg("propagate")
        .arg(&names)
        .arg(&lineage)
        .arg(&source)
        .arg(&target)
        .arg("--output")
        .arg(&propagated)
        .output()
        .unwrap();
    assert!(!missing_maps.status.success());
    assert!(!propagated.exists());

    let propagated_result = command()
        .arg("names")
        .arg("propagate")
        .arg(&names)
        .arg(&lineage)
        .arg(&source)
        .arg(&target)
        .arg("--source-map-source")
        .arg(&source_map)
        .arg("--source-map-target")
        .arg(&target_map)
        .arg("--output")
        .arg(&propagated)
        .output()
        .unwrap();
    assert!(
        propagated_result.status.success(),
        "{}",
        String::from_utf8_lossy(&propagated_result.stderr)
    );
    assert!(propagated.exists());
}
