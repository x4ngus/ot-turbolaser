use clap::Parser;
use ot_turbolaser::cli::Cli;

fn main() {
    let cli = Cli::parse();
    std::process::exit(ot_turbolaser::dispatch(cli));
}
