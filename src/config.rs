use log;
use nix::unistd::{Gid, Uid};
use std::env;
use std::env::VarError;
use std::error::Error;
use std::fmt;
use std::io;
use std::option::Option;
use std::path::PathBuf;
use std::process;
use std::result::Result;
use yaml_rust::{Yaml, YamlLoader};

#[derive(Debug)]
pub struct Config {
    pub log_level: log::Level,
    pub target_uid: Option<Uid>,
    pub target_gid: Option<Gid>,
    pub app_account: String,
    pub mock_app_account_uid: Option<Uid>,
    pub mock_app_account_gid: Option<Gid>,
    pub dry_run: bool,
}

pub const DEFAULT_CONFIG_FILE_PATH: &str = "/etc/activatepid1user.yml";

pub fn load_config() -> Config {
    let file_config = load_config_file_yaml();

    Config {
        log_level: load_config_key_or_abort::<log::Level>(
            "AP1U_LOG_LEVEL",
            &file_config,
            "log_level",
            log::Level::Info,
            &parse_log_level,
            &|doc| doc.as_str().and_then(parse_log_level),
        ),
        target_uid: load_config_key_or_abort::<Option<Uid>>(
            "AP1U_TARGET_UID",
            &file_config,
            "target_uid",
            None,
            &parse_uid_str,
            &parse_uid_yaml,
        ),
        target_gid: load_config_key_or_abort::<Option<Gid>>(
            "AP1U_TARGET_GID",
            &file_config,
            "target_gid",
            None,
            &parse_gid_str,
            &parse_gid_yaml,
        ),
        app_account: load_config_key_or_abort(
            "AP1U_APP_ACCOUNT",
            &file_config,
            "app_account",
            String::from("app"),
            &|env_val| Some(String::from(env_val)),
            &|doc| doc.clone().into_string(),
        ),
        mock_app_account_uid: load_config_key_or_abort::<Option<Uid>>(
            "AP1U_MOCK_APP_ACCOUNT_UID",
            &file_config,
            "mock_app_account_uid",
            None,
            &parse_uid_str,
            &parse_uid_yaml,
        ),
        mock_app_account_gid: load_config_key_or_abort::<Option<Gid>>(
            "AP1U_MOCK_APP_ACCOUNT_GID",
            &file_config,
            "mock_app_account_gid",
            None,
            &parse_gid_str,
            &parse_gid_yaml,
        ),
        dry_run: load_config_key_or_abort::<bool>(
            "AP1U_DRY_RUN",
            &file_config,
            "dry_run",
            false,
            &parse_bool_str,
            &parse_bool_yaml,
        ),
    }
}

fn get_config_file_path() -> PathBuf {
    match env::var_os("AP1U_CONFIG_FILE") {
        Some(val) => PathBuf::from(val),
        None => PathBuf::from(DEFAULT_CONFIG_FILE_PATH),
    }
}

fn load_config_file_yaml() -> Yaml {
    let config_file_path = &get_config_file_path();
    let file_config_str = std::fs::read_to_string(config_file_path);
    let file_config_str = file_config_str.unwrap_or_else(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            String::from("{}")
        } else {
            eprintln!("Error reading from {}: {}", config_file_path.display(), err);
            process::exit(1);
        }
    });

    let yaml_object = YamlLoader::load_from_str(file_config_str.as_str());
    let documents = yaml_object.unwrap_or_else(|err| {
        eprintln!("Error loading {}: {}", config_file_path.display(), err);
        process::exit(1);
    });

    if documents.len() != 1 {
        eprintln!(
            "Error loading {}: the file must contain exactly 1 YAML document",
            config_file_path.display()
        );
        process::exit(1);
    }

    match documents[0].as_hash() {
        Some(_) => documents[0].clone(),
        None => {
            eprintln!(
                "Error loading {}: the file must contain a YAML key-value map",
                config_file_path.display()
            );
            process::exit(1);
        }
    }
}

#[derive(Debug)]
pub enum ConfigLoadError<'a> {
    EnvVarInvalidValue(&'a str, String),
    EnvVarNotUnicode(&'a str),
    ConfigFileInvalidValue(&'a str, &'a Yaml),
}

impl<'a> fmt::Display for ConfigLoadError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfigLoadError::EnvVarInvalidValue(key, val) => {
                write!(f, "Env variable {} contains invalid value '{}'", key, val)
            }
            ConfigLoadError::EnvVarNotUnicode(key) => {
                write!(f, "Env variable {} contains invalid UTF-8", key)
            }
            ConfigLoadError::ConfigFileInvalidValue(key, doc) => {
                write!(f, "Config option {} contains invalid value {:?}", key, doc)
            }
        }
    }
}

impl<'a> Error for ConfigLoadError<'a> {}

type EnvValParser<T> = Fn(&str) -> Option<T>;
type ConfigFileValParser<T> = Fn(&Yaml) -> Option<T>;

fn load_config_key<'a, T>(
    env_key: &'a str,
    config_file: &'a Yaml,
    config_key: &'a str,
    default_value: T,
    env_val_parser: &EnvValParser<T>,
    config_file_val_parser: &ConfigFileValParser<T>,
) -> Result<T, ConfigLoadError<'a>> {
    let config_val = &config_file[config_key];

    match env::var(env_key) {
        Ok(env_val) => {
            if env_val.is_empty() {
                Ok(default_value)
            } else {
                match env_val_parser(env_val.as_str()) {
                    Some(result) => Ok(result),
                    None => Err(ConfigLoadError::EnvVarInvalidValue(env_key, env_val)),
                }
            }
        }
        Err(VarError::NotPresent) => match config_val {
            Yaml::Real(..)
            | Yaml::Integer(..)
            | Yaml::String(..)
            | Yaml::Boolean(..)
            | Yaml::Array(..)
            | Yaml::Hash(..)
            | Yaml::Alias(..) => match config_file_val_parser(&config_val) {
                Some(result) => Ok(result),
                None => Err(ConfigLoadError::ConfigFileInvalidValue(
                    config_key,
                    &config_val,
                )),
            },
            Yaml::Null | Yaml::BadValue => Ok(default_value),
        },
        Err(VarError::NotUnicode(_)) => Err(ConfigLoadError::EnvVarNotUnicode(env_key)),
    }
}

fn load_config_key_or_abort<'a, T>(
    env_key: &'a str,
    config_file: &'a Yaml,
    config_key: &'a str,
    default_value: T,
    env_val_parser: &EnvValParser<T>,
    config_file_val_parser: &ConfigFileValParser<T>,
) -> T {
    load_config_key::<T>(
        env_key,
        config_file,
        config_key,
        default_value,
        env_val_parser,
        config_file_val_parser,
    )
    .unwrap_or_else(|err| {
        eprintln!("{}", err);
        process::exit(1);
    })
}

fn parse_log_level(level: &str) -> Option<log::Level> {
    match level.to_lowercase().as_str() {
        "error" | "e" => Some(log::Level::Error),
        "warn" | "warning" | "w" => Some(log::Level::Warn),
        "info" | "i" => Some(log::Level::Info),
        "debug" | "d" => Some(log::Level::Debug),
        "trace" | "t" => Some(log::Level::Trace),
        _ => None,
    }
}

fn parse_uid_str(val: &str) -> Option<Option<Uid>> {
    match val.parse().map(Uid::from_raw) {
        Ok(uid) => Some(Some(uid)),
        Err(_) => None,
    }
}

fn parse_uid_yaml(doc: &Yaml) -> Option<Option<Uid>> {
    Some(doc.clone().into_i64().map(|num| Uid::from_raw(num as u32)))
}

fn parse_gid_str(val: &str) -> Option<Option<Gid>> {
    match val.parse().map(Gid::from_raw) {
        Ok(gid) => Some(Some(gid)),
        Err(_) => None,
    }
}

fn parse_gid_yaml(doc: &Yaml) -> Option<Option<Gid>> {
    Some(doc.clone().into_i64().map(|num| Gid::from_raw(num as u32)))
}

fn parse_bool_str(val: &str) -> Option<bool> {
    match val.to_lowercase().as_str() {
        "true" | "t" | "yes" | "y" | "1" | "on" => Some(true),
        "false" | "f" | "no" | "n" | "0" | "off" => Some(false),
        _ => None,
    }
}

fn parse_bool_yaml(doc: &Yaml) -> Option<bool> {
    doc.clone().into_bool()
}
