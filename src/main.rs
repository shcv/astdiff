use anyhow::Result;
use astdiff::{run, Args};
use clap::Parser;

fn main() -> Result<()> {
    let args = Args::parse();
    run(args)?;
    Ok(())
}
