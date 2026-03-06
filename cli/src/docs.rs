use std::fmt::Write as _;

use miette::Result;

const MANIFEST_DOCS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../compiler/manifest/README.md"
));
const README_DOCS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../README.md"));

struct ExampleDoc {
    name: &'static str,
    summary: &'static str,
    files: &'static [ExampleFile],
}

struct ExampleFile {
    path: &'static str,
    contents: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/docs_examples.rs"));

pub(crate) fn run(args: crate::DocsArgs) -> Result<()> {
    match args.command {
        crate::DocsCommand::Manifest => print!("{MANIFEST_DOCS}"),
        crate::DocsCommand::Readme => print!("{README_DOCS}"),
        crate::DocsCommand::Examples(args) => {
            if let Some(example) = args.example {
                print_example(&example)?;
            } else {
                print_examples_list();
            }
        }
    }

    Ok(())
}

fn print_examples_list() {
    let name_width = EXAMPLE_DOCS
        .iter()
        .map(|example| example.name.len())
        .max()
        .unwrap_or(0);
    let mut output = String::from("Examples\n\n");
    for example in EXAMPLE_DOCS {
        let _ = writeln!(
            &mut output,
            "{:<name_width$}  {}",
            example.name,
            example.summary,
            name_width = name_width
        );
    }
    output.push_str("\nRun `amber docs examples <example>` to dump that example's files.\n");
    print!("{output}");
}

fn print_example(name: &str) -> Result<()> {
    let example = EXAMPLE_DOCS.iter().find(|example| example.name == name);
    let Some(example) = example else {
        let available = EXAMPLE_DOCS
            .iter()
            .map(|example| example.name)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(miette::miette!(
            "unknown example `{name}`; available examples: {available}"
        ));
    };

    let mut output = String::new();
    for (index, file) in example.files.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }

        let language = fence_language(file.path);
        let _ = writeln!(&mut output, "## `{}`\n", file.path);
        let _ = writeln!(&mut output, "```{language}");
        output.push_str(file.contents);
        if !file.contents.ends_with('\n') {
            output.push('\n');
        }
        output.push_str("```\n");
    }

    print!("{output}");
    Ok(())
}

fn fence_language(path: &str) -> &'static str {
    match path.rsplit_once('.') {
        Some((_, "json")) => "json",
        Some((_, "json5")) => "json5",
        Some((_, "md")) => "markdown",
        _ => "text",
    }
}
