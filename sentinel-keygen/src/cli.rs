// Minimal hand-rolled argument parsing. The workspace lockfile contains no CLI
// crate (no clap/structopt), and the build constraints forbid adding one, so we
// parse the small, fixed flag set directly.

pub const USAGE: &str = "\
sentinel-keygen — generate Sentinel deployment secrets

USAGE:
    sentinel-keygen --output <DIR> [--description <TEXT>]
    sentinel-keygen --rotate --output <DIR>
    sentinel-keygen --verify --output <DIR>
    sentinel-keygen --add-agent --binary <PATH> --description <TEXT> --allowlist <FILE>
    sentinel-keygen --remove-agent --binary-hash <HASH> --allowlist <FILE>

MODES (choose one; default is initial setup):
    (none)            Initial setup. Generate signing keypair, allowlist, and
                      install record into <DIR>.
    --rotate          Generate new signing keys, archiving the existing ones
                      with a UTC timestamp suffix. Prior keys stay verifiable.
    --add-agent       Hash a binary and append it to an allowlist.
    --remove-agent    Remove an allowlist entry by its binary hash.
    --verify          Check that an installation's artifacts exist and are
                      internally consistent.

OPTIONS:
    --output <DIR>        Installation directory (created if absent).
    --description <TEXT>  Human-readable label for this deployment / agent.
    --allowlist <FILE>    Path to the allowlist file (for --add/--remove-agent).
    --binary <PATH>       Agent binary to hash and allowlist.
    --binary-hash <HASH>  'sha256:<hex>' hash of an entry to remove.
    -h, --help            Show this help.
";

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    Generate,
    Rotate,
    Verify,
    AddAgent,
    RemoveAgent,
    Help,
}

#[derive(Debug, Default)]
pub struct Args {
    pub output: Option<String>,
    pub description: Option<String>,
    pub allowlist: Option<String>,
    pub binary: Option<String>,
    pub binary_hash: Option<String>,
}

pub struct Cli {
    pub mode: Mode,
    pub args: Args,
}

/// Parse argv (excluding the program name). Returns a human-readable error on
/// unknown flags, missing values, or conflicting modes.
pub fn parse(argv: &[String]) -> Result<Cli, String> {
    let mut args = Args::default();
    let mut modes: Vec<Mode> = Vec::new();

    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        match arg {
            "-h" | "--help" => return Ok(Cli { mode: Mode::Help, args }),
            "--rotate" => modes.push(Mode::Rotate),
            "--verify" => modes.push(Mode::Verify),
            "--add-agent" => modes.push(Mode::AddAgent),
            "--remove-agent" => modes.push(Mode::RemoveAgent),
            "--output" => args.output = Some(take_value(argv, &mut i, arg)?),
            "--description" => args.description = Some(take_value(argv, &mut i, arg)?),
            "--allowlist" => args.allowlist = Some(take_value(argv, &mut i, arg)?),
            "--binary" => args.binary = Some(take_value(argv, &mut i, arg)?),
            "--binary-hash" => args.binary_hash = Some(take_value(argv, &mut i, arg)?),
            other => {
                return Err(format!(
                    "unknown argument '{other}'. Run 'sentinel-keygen --help' for usage."
                ))
            }
        }
        i += 1;
    }

    let mode = match modes.len() {
        0 => Mode::Generate,
        1 => modes.pop().unwrap(),
        _ => {
            return Err(
                "more than one mode flag given. Choose exactly one of \
                 --rotate, --verify, --add-agent, --remove-agent."
                    .to_string(),
            )
        }
    };

    Ok(Cli { mode, args })
}

/// Consume the value that follows a `--flag` at position `*i`, advancing `*i`.
fn take_value(argv: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    argv.get(*i)
        .filter(|v| !v.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("'{flag}' requires a value."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn default_mode_is_generate() {
        let cli = parse(&argv(&["--output", "/tmp/x"])).unwrap();
        assert_eq!(cli.mode, Mode::Generate);
        assert_eq!(cli.args.output.as_deref(), Some("/tmp/x"));
    }

    #[test]
    fn rotate_and_description() {
        let cli = parse(&argv(&["--rotate", "--output", "/tmp/x"])).unwrap();
        assert_eq!(cli.mode, Mode::Rotate);
    }

    #[test]
    fn conflicting_modes_error() {
        assert!(parse(&argv(&["--rotate", "--verify"])).is_err());
    }

    #[test]
    fn missing_value_errors() {
        assert!(parse(&argv(&["--output"])).is_err());
        // A following flag is not a valid value.
        assert!(parse(&argv(&["--output", "--rotate"])).is_err());
    }

    #[test]
    fn unknown_flag_errors() {
        assert!(parse(&argv(&["--nope"])).is_err());
    }

    #[test]
    fn help_short_circuits() {
        let cli = parse(&argv(&["--help"])).unwrap();
        assert_eq!(cli.mode, Mode::Help);
    }
}
