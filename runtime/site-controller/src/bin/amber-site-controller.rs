use std::{env, path::PathBuf};

use miette::Result;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    amber_site_controller::run_site_controller_default(parse_args()?).await
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
