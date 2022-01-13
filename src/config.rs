use super::abort;
use log::{error, warn};
use nix::unistd::{self, Gid, Uid};
use std::env::{self, VarError};
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
    pub host_uid: Option<Uid>,
    pub host_gid: Option<Gid>,
    pub app_account: String,
    pub app_group: String,
    pub mock_app_account_uid: Option<Uid>,
    pub mock_app_group_gid: Option<Gid>,
    pub hooks_dir: PathBuf,
    pub chown_home: bool,
    pub dry_run: bool,
}

pub const DEFAULT_CONFIG_FILE_PATH: &str = "/etc/matchhostfsowner/config.yml";

pub fn load_config() -> Config {
    let file_config = load_config_file_yaml();

    Config {
        log_level: load_config_key_or_abort(
            "MHF_LOG_LEVEL",
            &file_config,
            "log_level",
            true,
            log::Level::Info,
            &parse_log_level,
            &|doc| doc.as_str().and_then(parse_log_level),
        ),
        host_uid: load_config_key_or_abort(
            "MHF_HOST_UID",
            &file_config,
            "host_uid",
            false,
            None,
            &parse_uid_str,
            &parse_uid_yaml,
        ),
        host_gid: load_config_key_or_abort(
            "MHF_HOST_GID",
            &file_config,
            "host_gid",
            false,
            None,
            &parse_gid_str,
            &parse_gid_yaml,
        ),
        app_account: load_config_key_or_abort(
            "MHF_APP_ACCOUNT",
            &file_config,
            "app_account",
            false,
            String::from("app"),
            &|env_val| Some(String::from(env_val)),
            &|doc| doc.clone().into_string(),
        ),
        app_group: load_config_key_or_abort(
            "MHF_APP_GROUP",
            &file_config,
            "app_group",
            false,
            String::from(""), // default to be set in set_config_dynamic_defaults()
            &|env_val| Some(String::from(env_val)),
            &|doc| doc.clone().into_string(),
        ),
        mock_app_account_uid: load_config_key_or_abort(
            "MHF_MOCK_APP_ACCOUNT_UID",
            &file_config,
            "mock_app_account_uid",
            false,
            None,
            &parse_uid_str,
            &parse_uid_yaml,
        ),
        mock_app_group_gid: load_config_key_or_abort(
            "MHF_MOCK_APP_GROUP_GID",
            &file_config,
            "mock_app_group_gid",
            false,
            None,
            &parse_gid_str,
            &parse_gid_yaml,
        ),
        hooks_dir: load_config_key_or_abort(
            "MHF_HOOKS_DIR",
            &file_config,
            "hooks_dir",
            false,
            PathBuf::from("/etc/matchhostfsowner/hooks.d"),
            &parse_path_str,
            &parse_path_yaml,
        ),
        chown_home: load_config_key_or_abort(
            "MHF_CHOWN_HOME",
            &file_config,
            "chown_home",
            true,
            true,
            &parse_bool_str,
            &parse_bool_yaml,
        ),
        dry_run: load_config_key_or_abort(
            "MHF_DRY_RUN",
            &file_config,
            "dry_run",
            true,
            false,
            &parse_bool_str,
            &parse_bool_yaml,
        ),
    }
}

pub fn set_config_dynamic_defaults(mut config: Config) -> Config {
    if config.app_group.is_empty() {
        config.app_group = config.app_account.clone();
    }
    config
}

pub fn sanity_check_config(config: &Config) {
    fn format<T: std::fmt::Display>(opt: Option<T>) -> String {
        match opt {
            Some(val) => format!("{}", val),
            None => String::from("<no value>"),
        }
    }

    if config.host_uid.is_some() != config.host_gid.is_some() {
        abort!(
            "Configuration error: MHF_HOST_UID (set to '{}') and MHF_HOST_GID (set to '{}') \
             must both be given, or neither must be given.",
            format(config.host_uid),
            format(config.host_gid),
        );
    }
}

fn got_root_via_setuid_bit() -> bool {
    unistd::geteuid().is_root() && !unistd::getuid().is_root()
}

fn get_config_file_path() -> PathBuf {
    match env::var_os("MHF_CONFIG_FILE") {
        Some(val) => {
            if got_root_via_setuid_bit() {
                warn!(
                    "Ignoring MHF_CONFIG_FILE env var because we got \
                     root privileges via the setuid root bit. Will only \
                     load configuration from {}.",
                    DEFAULT_CONFIG_FILE_PATH
                );
                PathBuf::from(DEFAULT_CONFIG_FILE_PATH)
            } else {
                PathBuf::from(val)
            }
        }
        None => PathBuf::from(DEFAULT_CONFIG_FILE_PATH),
    }
}

fn load_config_file_yaml() -> Yaml {
    let config_file_path = &get_config_file_path();
    // TODO: check whether config file is only only writable by root
    let file_config_str = std::fs::read_to_string(config_file_path);
    let file_config_str = file_config_str.unwrap_or_else(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            String::from("{}")
        } else {
            abort!("Error reading from {}: {}", config_file_path.display(), err);
        }
    });

    let yaml_object = YamlLoader::load_from_str(file_config_str.as_str());
    let documents = yaml_object.unwrap_or_else(|err| {
        abort!("Error loading {}: {}", config_file_path.display(), err);
    });

    if documents.len() != 1 {
        abort!(
            "Error loading {}: the file must contain exactly 1 YAML document",
            config_file_path.display()
        );
    }

    match documents[0].as_hash() {
        Some(_) => documents[0].clone(),
        None => {
            abort!(
                "Error loading {}: the file must contain a YAML key-value map",
                config_file_path.display()
            );
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

type EnvValParser<T> = dyn Fn(&str) -> Option<T>;
type ConfigFileValParser<T> = dyn Fn(&Yaml) -> Option<T>;

fn load_config_key<'a, T: Clone>(
    env_key: &'a str,
    config_file: &'a Yaml,
    config_key: &'a str,
    setuid_root_safe: bool,
    default_value: T,
    env_val_parser: &EnvValParser<T>,
    config_file_val_parser: &ConfigFileValParser<T>,
) -> Result<T, ConfigLoadError<'a>> {
    let config_val = &config_file[config_key];
    let default_value = &default_value;

    let load_from_config_file = || match config_val {
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
        Yaml::Null | Yaml::BadValue => Ok(default_value.clone()),
    };

    match env::var(env_key) {
        Ok(env_val) => {
            if !setuid_root_safe && got_root_via_setuid_bit() {
                warn!(
                    "Ignoring {} env var because we got root privileges via \
                     the setuid root bit.",
                    env_key
                );
                load_from_config_file()
            } else if env_val.is_empty() {
                Ok(default_value.clone())
            } else {
                match env_val_parser(env_val.as_str()) {
                    Some(result) => Ok(result),
                    None => Err(ConfigLoadError::EnvVarInvalidValue(env_key, env_val)),
                }
            }
        }
        Err(VarError::NotPresent) => load_from_config_file(),
        Err(VarError::NotUnicode(_)) => {
            if !setuid_root_safe && got_root_via_setuid_bit() {
                warn!(
                    "Ignoring {} env var because we got root privileges via \
                     the setuid root bit.",
                    env_key
                );
                load_from_config_file()
            } else {
                Err(ConfigLoadError::EnvVarNotUnicode(env_key))
            }
        }
    }
}

fn load_config_key_or_abort<'a, T: Clone>(
    env_key: &'a str,
    config_file: &'a Yaml,
    config_key: &'a str,
    setuid_root_safe: bool,
    default_value: T,
    env_val_parser: &EnvValParser<T>,
    config_file_val_parser: &ConfigFileValParser<T>,
) -> T {
    load_config_key::<T>(
        env_key,
        config_file,
        config_key,
        setuid_root_safe,
        default_value,
        env_val_parser,
        config_file_val_parser,
    )
    .unwrap_or_else(|err| {
        abort!("{}", err);
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

pub fn parse_bool_str(val: &str) -> Option<bool> {
    match val.to_lowercase().as_str() {
        "true" | "t" | "yes" | "y" | "1" | "on" => Some(true),
        "false" | "f" | "no" | "n" | "0" | "off" => Some(false),
        _ => None,
    }
}

fn parse_bool_yaml(doc: &Yaml) -> Option<bool> {
    doc.clone().into_bool()
}

fn parse_path_str(val: &str) -> Option<PathBuf> {
    Some(PathBuf::from(val))
}

fn parse_path_yaml(doc: &Yaml) -> Option<PathBuf> {
    doc.clone().into_string().map(|s| PathBuf::from(s))
}
