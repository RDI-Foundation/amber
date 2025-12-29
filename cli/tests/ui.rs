use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use similar::TextDiff;

#[test]
fn ui_tests() -> Result<(), Box<dyn std::error::Error>> {
    let ui_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("ui");
    let mut cases = Vec::new();
    collect_cases(&ui_dir, &mut cases)?;
    cases.sort();

    if cases.is_empty() {
        return Err(format!("no ui cases found under {}", ui_dir.display()).into());
    }

    for case in cases {
        run_case(&case)?;
    }

    Ok(())
}

fn collect_cases(dir: &Path, cases: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_cases(&path, cases)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("json5") {
            continue;
        }
        if path.with_extension("stderr").exists() {
            cases.push(path);
        }
    }
    Ok(())
}

fn run_case(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let args = read_args(path)?;
    let expected_stderr = read_expected(&path.with_extension("stderr"))?;
    let stdout_path = path.with_extension("stdout");
    let expected_stdout = stdout_path
        .exists()
        .then(|| read_expected(&stdout_path))
        .transpose()?;

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_amber"));
    cmd.arg("check").arg(path);
    cmd.args(args);
    cmd.env("NO_COLOR", "1");
    cmd.env("TERM", "dumb");
    cmd.env("CLICOLOR", "0");
    cmd.env("RUST_BACKTRACE", "0");

    let output = cmd.output()?;
    if output.status.success() {
        return Err(format!("expected failure for {}", path.display()).into());
    }

    let stdout = normalize_output(&output.stdout);
    let stderr = normalize_output(&output.stderr);

    if let Some(expected) = expected_stdout {
        assert_text_matches(path, "stdout", &expected, &stdout);
    } else if !stdout.is_empty() {
        return Err(format!("unexpected stdout for {}:\n{stdout}", path.display()).into());
    }

    assert_text_matches(path, "stderr", &expected_stderr, &stderr);
    Ok(())
}

fn read_args(case: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let args_path = case.with_extension("args");
    if !args_path.exists() {
        return Ok(Vec::new());
    }
    let contents = fs::read_to_string(args_path)?;
    let mut args = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        args.extend(line.split_whitespace().map(str::to_string));
    }
    Ok(args)
}

fn read_expected(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    Ok(normalize_text(&contents))
}

fn normalize_output(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    normalize_text(&text)
}

fn normalize_text(text: &str) -> String {
    let text = text.replace("\r\n", "\n");
    let text = strip_ansi(&text);
    normalize_paths(&text)
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && matches!(chars.peek(), Some('[')) {
            let _ = chars.next();
            while let Some(next) = chars.next() {
                let code = next as u32;
                if (0x40..=0x7e).contains(&code) {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

fn normalize_paths(text: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut out = text.replace(manifest_dir, "<CARGO_MANIFEST_DIR>");
    if cfg!(windows) {
        let manifest_dir = manifest_dir.replace('\\', "/");
        out = out.replace(&manifest_dir, "<CARGO_MANIFEST_DIR>");
    }
    out
}

fn assert_text_matches(case: &Path, stream: &str, expected: &str, actual: &str) {
    if expected == actual {
        return;
    }

    let diff = TextDiff::from_lines(expected, actual)
        .unified_diff()
        .header("expected", "actual")
        .to_string();

    panic!("ui test mismatch for {} ({stream})\n{diff}", case.display());
}
