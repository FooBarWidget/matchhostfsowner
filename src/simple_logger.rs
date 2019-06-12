//! A logger that prints all messages with a readable output format.
// Forked from https://github.com/borntyping/rust-simple_logger
// to allow reconfiguring the log level after initialization.

use chrono::Local;
use colored::*;
use log::{self, Level, Log, Metadata, Record, SetLoggerError};

pub struct SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level_string = {
                match record.level() {
                    Level::Error => record.level().to_string().red(),
                    Level::Warn => record.level().to_string().yellow(),
                    Level::Info => record.level().to_string().cyan(),
                    Level::Debug => record.level().to_string().purple(),
                    Level::Trace => record.level().to_string().normal(),
                }
            };
            eprintln!(
                "{} {:<5} [{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S,%3f"),
                level_string,
                record.module_path().unwrap_or_default(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

/// Initializes the global logger with a SimpleLogger instance with
/// `max_log_level` set to a specific log level.
///
/// ```
/// # #[macro_use] extern crate log;
/// # extern crate simple_logger;
/// #
/// # fn main() {
/// simple_logger::init_with_level(log::Level::Warn).unwrap();
///
/// warn!("This is an example message.");
/// info!("This message will not be logged.");
/// # }
/// ```
pub fn init_with_level(level: Level) -> Result<(), SetLoggerError> {
    let logger = SimpleLogger {};
    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(level.to_level_filter());
    Ok(())
}
