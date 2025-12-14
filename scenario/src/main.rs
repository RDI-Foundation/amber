use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "amber-scenario", about = "Canonicalize an Amber manifest")]
struct Cli {
    /// Path to a JSON5 manifest file
    manifest: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let manifest =
        std::fs::read_to_string(&cli.manifest)?.parse::<amber_scenario::manifest::Manifest>()?;
    let json = serde_json::to_string_pretty(&manifest)?;
    println!("{json}");
    Ok(())
}
