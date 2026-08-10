use std::path::Path;

use astdiff::diff::{ChangeType, DiffClassification, DiffResult, StructuralDiff};
use astdiff::parser::JsParser;

fn compare(old: &str, new: &str) -> DiffResult {
    let mut parser1 = JsParser::new().unwrap();
    let mut parser2 = JsParser::new().unwrap();
    let tree1 = parser1.parse(old).unwrap();
    let tree2 = parser2.parse(new).unwrap();
    StructuralDiff::new()
        .compare(
            old,
            new,
            &tree1,
            &tree2,
            None,
            Path::new("old.js"),
            Path::new("new.js"),
        )
        .unwrap()
}

#[test]
fn one_line_bundle_uses_declaration_byte_ranges() {
    let result = compare(
        "function a(){return 1}function b(){return 2}",
        "function a(){return 1}function b(){return 3}",
    );

    assert_eq!(result.changes.len(), 1);
    let change = &result.changes[0];
    assert_eq!(change.structural_path, "global.b");
    assert_eq!(change.classification, Some(DiffClassification::Structural));
}

#[test]
fn keyword_literals_are_not_normalized_as_identifiers() {
    let result = compare("function a(){return true}", "function a(){return null}");

    assert!(!result.identical);
    assert_eq!(result.changes.len(), 1);
    assert_eq!(
        result.changes[0].classification,
        Some(DiffClassification::Structural)
    );
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

    let declarations = diff.extract_declarations_for_inspection(tree.root_node(), source);
    assert_eq!(declarations.len(), 1);
    assert!(declarations[0].fingerprint.is_none());
}
