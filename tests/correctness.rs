use astdiff::diff::{ChangeType, DiffClassification, DiffResult, StructuralDiff};
use astdiff::parser::JsParser;

fn compare(old: &str, new: &str) -> DiffResult {
    let mut parser1 = JsParser::new().unwrap();
    let mut parser2 = JsParser::new().unwrap();
    let tree1 = parser1.parse(old).unwrap();
    let tree2 = parser2.parse(new).unwrap();
    let diff = StructuralDiff::new();
    let left = diff.extract_declarations(&tree1, old).unwrap();
    let right = diff.extract_declarations(&tree2, new).unwrap();
    diff.compare_declarations(&left, &right, old, new).unwrap()
}

#[test]
fn one_line_bundle_uses_declaration_byte_ranges() {
    let result = compare(
        include_str!("../fixtures/regressions/one-line-old.js"),
        include_str!("../fixtures/regressions/one-line-new.js"),
    );

    assert_eq!(result.changes.len(), 1);
    let change = &result.changes[0];
    assert_eq!(change.structural_path, "global.b");
    assert_eq!(change.classification, Some(DiffClassification::Structural));
}

#[test]
fn keyword_literals_are_not_normalized_as_identifiers() {
    let result = compare(
        include_str!("../fixtures/regressions/keyword-old.js"),
        include_str!("../fixtures/regressions/keyword-new.js"),
    );

    assert!(!result.identical);
    assert_eq!(result.changes.len(), 1);
    assert_eq!(
        result.changes[0].classification,
        Some(DiffClassification::Structural)
    );
}

#[test]
fn bundled_module_table_change_is_not_lost() {
    let result = compare(
        include_str!("../fixtures/regressions/bundle-old.js"),
        include_str!("../fixtures/regressions/bundle-new.js"),
    );

    assert!(!result.identical);
    assert_eq!(result.matched_declarations, 1);
    assert_eq!(result.changes.len(), 1);
    assert_eq!(result.changes[0].structural_path, "global.modules");
}

#[test]
fn stable_name_bypasses_structural_size_window() {
    let result = compare(
        "function stable(){return 1}",
        "function stable(){let total=0;for(let i=0;i<20;i++){total+=i*i;}if(total>10){total+=Math.max(total,5);}return total+100}",
    );

    assert_eq!(result.matched_declarations, 1);
    assert!(result.changes.iter().all(|change| !matches!(
        change.change_type,
        ChangeType::Addition | ChangeType::Deletion
    )));
}

#[test]
fn location_snippets_are_bounded_on_minified_lines() {
    let padding = "x".repeat(600);
    let old = format!("function a(){{return '{padding}'}}");
    let new = format!("function a(){{return '{padding}y'}}");
    let result = compare(&old, &new);
    let location = result.changes[0].location1.as_ref().unwrap();

    assert!(location.code_snippet.chars().count() <= 201);
    assert!(location.code_snippet.ends_with('…'));
}

#[test]
fn disabling_fingerprints_skips_extraction() {
    let source = "function a(){return 'a distinctive string'}";
    let mut parser = JsParser::new().unwrap();
    let tree = parser.parse(source).unwrap();
    let mut diff = StructuralDiff::new();
    diff.set_use_fingerprints(false);

    let declarations = diff.extract_declarations(&tree, source).unwrap();
    assert_eq!(declarations.len(), 1);
    assert!(declarations[0].fingerprint.is_none());
}

#[test]
fn local_renames_and_line_wrapping_preserve_comparison() {
    for (old, new) in [
        (
            "function f(x){return function g(y){return y+x;};}",
            "function a(b){\nreturn function c(d){return d+b;};\n}",
        ),
        (
            "function f(x){return function g(y){return y;};}",
            "function a(b){return function c(b){return b;};}",
        ),
        (
            "function f(x){return `received ${x} items`;}",
            "function a(b){return `received ${b} items`;}",
        ),
    ] {
        let result = compare(old, new);
        assert!(result.identical, "{old} versus {new}: {result:?}");
        assert_eq!(result.matched_declarations, 1);
    }
}

#[test]
fn string_contents_are_not_whitespace_normalized() {
    for (old, new) in [
        (
            "function f(){return 'a  b';}",
            "function f(){return 'a b';}",
        ),
        ("function f(){return '';}", "function f(){return 'new';}"),
        (
            "function f(x){return `before ${x} after`;}",
            "function f(x){return `${x}`;}",
        ),
    ] {
        let result = compare(old, new);
        assert!(!result.identical);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(
            result.changes[0].classification,
            Some(DiffClassification::StringOnly)
        );
    }
}

#[test]
fn external_names_and_binding_targets_remain_observable() {
    for (old, new) in [
        (
            "function f(x){return fetch(x);}",
            "function f(x){return erase(x);}",
        ),
        ("function f(x,y){return x;}", "function f(x,y){return y;}"),
        (
            "import {readFile as f} from 'fs';",
            "import {writeFile as f} from 'fs';",
        ),
        (
            "function f(x){return x.push(1);}",
            "function f(x){return x.shift(1);}",
        ),
        ("let x=1;", "const x=1;"),
        ("function f(){return\nx;}", "function f(){return x;}"),
    ] {
        let result = compare(old, new);
        assert!(!result.identical, "{old} versus {new}");
        assert!(result
            .changes
            .iter()
            .all(|change| change.classification != Some(DiffClassification::Unchanged)));
    }
}

#[test]
fn template_hashes_and_fingerprints_ignore_bound_spelling() {
    let old = "function f(x){return `received ${x} items`;}";
    let new = "function a(b){return `received ${b} items`;}";
    let mut parser = JsParser::new().unwrap();
    let mut diff = StructuralDiff::new();
    diff.set_use_fingerprints(true);
    let left = diff
        .extract_declarations(&parser.parse(old).unwrap(), old)
        .unwrap();
    let right = diff
        .extract_declarations(&parser.parse(new).unwrap(), new)
        .unwrap();
    assert_eq!(left[0].structural_hashes, right[0].structural_hashes);
    assert_eq!(left[0].minhash_signature, right[0].minhash_signature);
    assert_eq!(
        serde_json::to_value(&left[0].fingerprint).unwrap(),
        serde_json::to_value(&right[0].fingerprint).unwrap()
    );
    assert!(
        diff.compare_declarations(&left, &right, old, new)
            .unwrap()
            .identical
    );
}

#[test]
fn display_context_uses_target_names() {
    let result = compare(
        "function oldName(x) {\n  const count = x + 1;\n  return count + 3;\n}",
        "function newName(y) {\n  const total = y + 1;\n  return total + 4;\n}",
    );
    assert_eq!(result.changes.len(), 1);
    let display = &result.changes[0].display_diff;
    assert!(display.contains(" function newName(y) {"), "{display}");
    assert!(display.contains("   const total = y + 1;"), "{display}");
    assert!(display.contains("-  return count + 3;"), "{display}");
    assert!(display.contains("+  return total + 4;"), "{display}");
}

#[test]
fn stale_declaration_ranges_are_rejected() {
    let source = "function f(){return 1;}";
    let tree = JsParser::new().unwrap().parse(source).unwrap();
    let diff = StructuralDiff::new();
    let declarations = diff.extract_declarations(&tree, source).unwrap();
    assert!(diff
        .compare_declarations(&declarations, &declarations, "", source)
        .is_err());
}

#[test]
fn legal_redeclarations_share_their_normalized_binding() {
    let result = compare(
        "function f(x){var x; var y=1; var y=2; return x+y;}",
        "function g(a){var a; var b=1; var b=2; return a+b;}",
    );
    assert!(result.identical, "{result:?}");
}

#[test]
fn multiline_template_diff_points_at_the_changed_line() {
    let result = compare(
        "function f(x){return `first ${x}\nold text\nlast`;}",
        "function f(x){return `first ${x}\nnew text\nlast`;}",
    );
    assert_eq!(result.changes.len(), 1);
    let change = &result.changes[0];
    assert_eq!(change.classification, Some(DiffClassification::StringOnly));
    assert!(
        change.display_diff.contains("-old text\n+new text"),
        "{}",
        change.display_diff
    );
}
