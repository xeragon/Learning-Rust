use minigrep::search;
use std::env;
use std::error::Error;
use std::fs;
use std::process;

struct Config {
    query: String,
    target_file: String,
}

impl Config {
    fn new(args: &[String]) -> Result<Config, &'static str> {
        if args.len() != 3 {
            return Err("usage: ./minigrep <pattern> <path/to/file.txt>");
        }
        let query = args[1].clone();
        let target_file = args[2].clone();
        Ok(Config { query, target_file })
    }
}

fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string(config.target_file)?;
    for line in search(&config.query, &contents) {
        println!("{line}");
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let config = Config::new(&args).unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {err}");
        process::exit(1);
    });

    println!(
        "Looking for pattern \"{}\" in \"{}\" ",
        config.query, config.target_file
    );

    if let Err(e) = run(config) {
        eprintln!("Application error: {e}");
        process::exit(1);
    }
}
