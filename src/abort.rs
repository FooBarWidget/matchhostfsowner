// Prints an error message with `error!`, then aborts with exit code 1.
// Accepts format arguments like `eprintln!`.
#[macro_export]
macro_rules! abort {
    ($($arg:tt)+) => {{
        error!($($arg)+);
        process::exit(1);
    }};
}
