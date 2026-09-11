use tree_sitter::Node;

fn print_tree(node: Node, source: &str, indent: usize) {
    let node_text = if node.child_count() == 0 && node.byte_range().len() < 50 {
        format!(" => \"{}\"", &source[node.byte_range()])
    } else {
        String::new()
    };

    println!(
        "{}{} [{}:{}]{}",
        " ".repeat(indent),
        node.kind(),
        node.start_position().row,
        node.start_position().column,
        node_text
    );

    // Check for field names
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();

            // Find field name for this child
            let mut field_name = None;
            for i in 0..node.child_count() {
                if let Some(n) = node.child(i) {
                    if n.id() == child.id() {
                        field_name = node.field_name_for_child(i as u32);
                        break;
                    }
                }
            }

            if let Some(field) = field_name {
                println!("{}[{}=", " ".repeat(indent + 2), field);
                print_tree(child, source, indent + 4);
                println!("{}]", " ".repeat(indent + 2));
            } else {
                // Also check if this child has field names for its children
                if node.kind() == "namespace_import" && child.kind() == "identifier" {
                    println!(
                        "{}NOTE: identifier in namespace_import",
                        " ".repeat(indent + 2)
                    );
                }
                print_tree(child, source, indent + 2);
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: debug_ast FILE.js"))?;
    let source = std::fs::read_to_string(path)?;
    let mut parser = astdiff::parser::JsParser::new()?;
    let tree = parser.parse(&source)?;
    print_tree(tree.root_node(), &source, 0);
    Ok(())
}
