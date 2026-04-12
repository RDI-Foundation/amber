use std::{
    env,
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::Command,
};

use miette::{IntoDiagnostic as _, Result, WrapErr as _};

fn main() -> Result<()> {
    let plan = parse_args()?;
    let amber = amber_cli_executable()?;
    let err = Command::new(amber)
        .arg("run-site-controller")
        .arg("--plan")
        .arg(plan)
        .exec();
    Err(miette::miette!(
        "failed to exec amber site controller wrapper: {err}"
    ))
}

fn parse_args() -> Result<PathBuf> {
    let mut args = env::args_os();
    let _exe = args.next();
    let Some(flag) = args.next() else {
        return usage_error();
    };
    if flag != "--plan" {
        return usage_error();
    }
    let Some(plan) = args.next() else {
        return usage_error();
    };
    if args.next().is_some() {
        return usage_error();
    }
    Ok(PathBuf::from(plan))
}

fn usage_error<T>() -> Result<T> {
    Err(miette::miette!("usage: amber-site-controller --plan FILE"))
}

fn amber_cli_executable() -> Result<PathBuf> {
    if let Some(path) = env::var_os("CARGO_BIN_EXE_amber") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }

    let current = env::current_exe()
        .into_diagnostic()
        .wrap_err("failed to resolve amber executable path")?;
    if let Some(candidate) = sibling_binary(&current, "amber") {
        return Ok(candidate);
    }
    Err(miette::miette!(
        "failed to locate the amber executable next to {}",
        current.display()
    ))
}

fn sibling_binary(current: &Path, name: &str) -> Option<PathBuf> {
    let exe_name = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let bin_dir = current.parent()?;
    for dir in [Some(bin_dir), bin_dir.parent()].into_iter().flatten() {
        let candidate = dir.join(&exe_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
