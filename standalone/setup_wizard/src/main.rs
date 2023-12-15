use std::fs;
use std::ops::Not;
use std::sync::{Mutex, MutexGuard};
use crate::settings::{Endpoint, Settings};
use crate::user_interaction::{ask_for_input, checked_overwrite, select_index};

mod composer;
mod settings;
mod template_settings;
mod user_interaction;

const MODE_PARAM_NAME: &str = "mode";
const MODE_NON_INTERACTIVE: &str = "non-interactive";
const MODE_INTERACTIVE: &str = "interactive";
const ENDPOINT_ADDRESS_PARAM_NAME: &str = "address";
const HOSTNAME_PARAM_NAME: &str = "host";
const CREDENTIALS_PARAM_NAME: &str = "creds";
const CERTIFICATE_FILE_PARAM_NAME: &str = "cert";
const SETTINGS_FILE_PARAM_NAME: &str = "settings";

#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum Mode {
    NonInteractive,
    Interactive,
}

static MODE: Mutex<Mode> = Mutex::new(Mode::Interactive);

pub fn get_mode() -> Mode {
    *MODE.lock().unwrap()
}

#[derive(Default, Clone)]
pub struct PredefinedParameters {
    endpoint_addresses: Option<Vec<String>>,
    hostname: Option<String>,
    credentials: Option<(String, String)>,
    certificate: Option<String>,
    settings_file: Option<String>,
}

lazy_static::lazy_static! {
    pub static ref PREDEFINED_PARAMS: Mutex<PredefinedParameters> = Mutex::default();
}

pub fn get_predefined_params() -> MutexGuard<'static, PredefinedParameters> {
    PREDEFINED_PARAMS.lock().unwrap()
}

fn main() {
    let args = clap::Command::new("VPN client setup wizard")
        .args(&[
            clap::Arg::new(MODE_PARAM_NAME)
                .short('m')
                .long("mode")
                .action(clap::ArgAction::Set)
                .value_parser([MODE_INTERACTIVE, MODE_NON_INTERACTIVE])
                .default_value(MODE_INTERACTIVE)
                .help(format!(r#"Available wizard running modes:
    * {MODE_INTERACTIVE} - set up only the essential without deep diving into details
    * {MODE_NON_INTERACTIVE} - prepare the setup without interacting with a user,
        requires some parameters set up via command-line arguments
"#)),
            clap::Arg::new(ENDPOINT_ADDRESS_PARAM_NAME)
                .short('a')
                .long("address")
                .action(clap::ArgAction::Append)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .required_if_eq(MODE_PARAM_NAME, MODE_NON_INTERACTIVE)
                .help(format!(r#"{}.
Values of each parameter occurence are gathered into a list.
Required in non-interactive mode."#,
                              Endpoint::doc_addresses())),
            clap::Arg::new(HOSTNAME_PARAM_NAME)
                .short('n')
                .long("hostname")
                .action(clap::ArgAction::Set)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .required_if_eq(MODE_PARAM_NAME, MODE_NON_INTERACTIVE)
                .help(format!("{}.\nRequired in non-interactive mode.", Endpoint::doc_hostname())),
            clap::Arg::new(CREDENTIALS_PARAM_NAME)
                .short('c')
                .long("creds")
                .action(clap::ArgAction::Set)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .required_if_eq(MODE_PARAM_NAME, MODE_NON_INTERACTIVE)
                .help(r#"A user credentials formatted as: <username>:<password>.
Required in non-interactive mode."#),
            clap::Arg::new(CERTIFICATE_FILE_PARAM_NAME)
                .long("cert")
                .action(clap::ArgAction::Set)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .help(Endpoint::doc_certificate()),
            clap::Arg::new(SETTINGS_FILE_PARAM_NAME)
                .long("settings")
                .action(clap::ArgAction::Set)
                .value_parser(clap::builder::NonEmptyStringValueParser::new())
                .required_if_eq(MODE_PARAM_NAME, MODE_NON_INTERACTIVE)
                .help(r#"Path to store the library settings file.
Required in non-interactive mode."#),
        ])
        .get_matches();

    *MODE.lock().unwrap() = match args.get_one::<String>(MODE_PARAM_NAME)
        .map(String::as_str)
        .unwrap_or(MODE_INTERACTIVE)
    {
        MODE_NON_INTERACTIVE => Mode::NonInteractive,
        MODE_INTERACTIVE => Mode::Interactive,
        _ => unreachable!(),
    };

    *PREDEFINED_PARAMS.lock().unwrap() = PredefinedParameters {
        endpoint_addresses: args.get_many::<String>(ENDPOINT_ADDRESS_PARAM_NAME)
            .map(Iterator::cloned)
            .map(Iterator::collect),
        hostname: args.get_one::<String>(HOSTNAME_PARAM_NAME).cloned(),
        credentials: args.get_one::<String>(CREDENTIALS_PARAM_NAME)
            .map(|x| x.splitn(2, ':'))
            .and_then(|mut x| x.next().zip(x.next()))
            .map(|(a, b)| (a.to_string(), b.to_string())),
        certificate: args.get_one::<String>(CERTIFICATE_FILE_PARAM_NAME).cloned(),
        settings_file: args.get_one::<String>(SETTINGS_FILE_PARAM_NAME).cloned(),
    };

    println!("Welcome to the setup wizard");

    let settings_path = {
        #[allow(clippy::large_enum_variant)]
        enum Action {
            UseExisting { path: String },
            ModifyAndOverwrite { path: String, settings: Settings },
            MakeFromScratch,
        }

        let action =
            if let Some((path, settings)) = get_mode().eq(&Mode::NonInteractive).not()
                .then(|| find_existent_settings::<Settings>("."))
                .flatten()
            {
                let selection = select_index(
                    format!("Found existing settings: {path}."),
                    &["Use it", "Modify and overwrite", "Make new from scratch"],
                    Some(0),
                );
                match selection {
                    0 => Action::UseExisting { path },
                    1 => Action::ModifyAndOverwrite { path, settings },
                    2 => Action::MakeFromScratch,
                    _ => unreachable!("{:?}", selection),
                }
            } else {
                Action::MakeFromScratch
            };
        match action {
            Action::UseExisting { path } => path,
            Action::ModifyAndOverwrite { path, settings } => {
                println!("Let's build the settings");
                let settings = settings::build(Some(&settings));
                println!("The settings are successfully built\n");

                let doc = composer::compose_document(Some(&path), &settings);
                fs::write(&path, doc.to_string())
                    .expect("Couldn't write the settings to a file");

                path
            }
            Action::MakeFromScratch => {
                println!("Let's build the settings");
                let settings = settings::build(None);
                println!("The settings are successfully built\n");

                let path = ask_for_input::<String>(
                    "Path to a file to store the settings",
                    get_predefined_params().settings_file.clone()
                        .or(Some("standalone_client.toml".into())),
                );
                if checked_overwrite(&path, "Overwrite the existing settings file?") {
                    let doc = composer::compose_document(None, &settings);
                    fs::write(&path, doc.to_string())
                        .expect("Couldn't write the settings to a file");
                }
                path
            }
        }
    };

    println!("To start client, run the following command:");
    println!("\tstandalone_client -c {settings_path}");
    println!("To see full set of the available options, run the following command:");
    println!("\tstandalone_client -h");
}

fn find_existent_settings<T: serde::de::DeserializeOwned>(path: &str) -> Option<(String, T)> {
    fs::read_dir(path).ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.metadata()
            .map(|meta| meta.is_file()).unwrap_or_default())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|fname| fs::read_to_string(&fname).ok().zip(Some(fname)))
        .find_map(|(content, fname)| Some(fname).zip(toml::from_str::<T>(&content).ok()))
}
