use std::{
    env, fs,
    path::Path,
    process::{Command, ExitCode},
};

use amber_compose_helper::{HelperError, RunPlan, build_run_plan};

fn main() -> ExitCode {
    match run_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn run_main() -> Result<(), HelperError> {
    let mut args = env::args();
    let _exe = args.next();
    let Some(command) = args.next() else {
        return Err(usage_error());
    };

    match command.as_str() {
        "install" => {
            let Some(dest) = args.next() else {
                return Err(usage_error());
            };
            if args.next().is_some() {
                return Err(usage_error());
            }
            install(Path::new(&dest))
        }
        "run" => {
            if args.next().is_some() {
                return Err(usage_error());
            }
            run()
        }
        _ => Err(usage_error()),
    }
}

fn usage_error() -> HelperError {
    HelperError::Msg("usage: amber-helper <install DEST|run>".to_string())
}

fn install(dest: &Path) -> Result<(), HelperError> {
    let exe = env::current_exe().map_err(|err| HelperError::Msg(err.to_string()))?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|err| HelperError::Msg(err.to_string()))?;
    }

    fs::copy(&exe, dest).map_err(|err| HelperError::Msg(err.to_string()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dest)
            .map_err(|err| HelperError::Msg(err.to_string()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(dest, perms).map_err(|err| HelperError::Msg(err.to_string()))?;
    }

    Ok(())
}

fn run() -> Result<(), HelperError> {
    let plan = build_run_plan(env::vars_os())?;
    exec_plan(plan)
}

fn exec_plan(plan: RunPlan) -> Result<(), HelperError> {
    let mut iter = plan.entrypoint.into_iter();
    let Some(program) = iter.next() else {
        return Err(HelperError::Msg(
            "program entrypoint must not be empty".to_string(),
        ));
    };

    let mut cmd = Command::new(program);
    cmd.args(iter);
    cmd.env_clear();
    cmd.envs(plan.env);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(HelperError::Msg(format!("failed to exec program: {err}")))
    }

    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .map_err(|err| HelperError::Msg(format!("failed to run program: {err}")))?;
        if !status.success() {
            return Err(HelperError::Msg(format!(
                "program exited with status {status}"
            )));
        }
        Ok(())
    }
}
