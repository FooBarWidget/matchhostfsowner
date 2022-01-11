use std::{error, fmt, fs::File, io, io::Write, path::Path, process, process::Command, thread};
use tempfile;
use thiserror::Error;

#[derive(Error)]
#[error("{0}")]
pub struct GenericError(pub String);

impl GenericError {
    pub fn new_boxed(message: impl Into<String>) -> Box<GenericError> {
        Box::new(GenericError(message.into()))
    }
}

impl fmt::Debug for GenericError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[macro_export]
macro_rules! assert_contains_substr {
    ($str:expr, $substr:expr) => {{
        let (str, substr) = (&($str), &($substr));
        if str.find(substr).is_none() {
            panic!(
                "assertion failed: `contains_substr(str, subtr)`\n\
                    substr: `{:?}`\n\
                    str:\n\
                    ---------- BEGIN ----------\n\
                    {}\n\
                    ----------- END -----------\n",
                substr,
                strip_trailing_newline(str),
            );
        }
    }};
    ($str:expr, $substr:expr, ) => {{
        assert_contains_substr!($str, $substr);
    }};
}

pub fn strip_trailing_newline(input: &impl AsRef<str>) -> String {
    match input.as_ref().strip_suffix("\n") {
        Some(x) => x.to_string(),
        None => input.as_ref().to_string(),
    }
}

pub struct TestImage {
    pub image_name: String,
}

impl Drop for TestImage {
    fn drop(&mut self) {
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg("exec \"$@\" 2>&1")
            .arg("docker")
            .arg("docker")
            .arg("rmi")
            .arg(self.image_name.clone())
            .output();
        match output {
            Err(e) => eprintln!("Warning: error removing image {}: {}", self.image_name, e),
            Ok(output) => {
                if !output.status.success() {
                    eprintln!(
                        "Warning: error removing image {}. \
                        Output:\n\
                         -------- BEGIN OUTPUT --------\n\
                         {}\n\
                         --------- END OUTPUT ---------\n",
                        self.image_name,
                        strip_trailing_newline(&String::from_utf8_lossy(&output.stdout)),
                    );
                }
            }
        }
    }
}

pub fn build_image(build_script: &[&str]) -> Result<TestImage, Box<dyn error::Error>> {
    let image_name = format!(
        "matchhostfsowner-test:{}-{}",
        process::id(),
        thread_id_to_string(thread::current().id())
    );
    let tempdir = tempfile::tempdir()?;
    let dockerfile_path = tempdir.path().join("Dockerfile");

    create_dockerfile(dockerfile_path.as_path(), build_script)?;
    run_docker_build(
        image_name.as_str(),
        dockerfile_path.as_path(),
        Path::new("."),
    )?;
    Ok(TestImage {
        image_name: image_name,
    })
}

fn thread_id_to_string(id: thread::ThreadId) -> String {
    let result = format!("{:?}", id);
    result.replace("ThreadId(", "").replace(")", "")
}

fn create_dockerfile(path: &Path, build_script: &[&str]) -> io::Result<()> {
    let contents = format!(
        "FROM matchhostfsowner-integration-test-base\n\
         {}\n",
        build_script.join("\n")
    );

    let mut f = File::create(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

fn run_docker_build(
    image_name: &str,
    dockerfile_path: &Path,
    source_path: &Path,
) -> Result<(), Box<dyn error::Error>> {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("exec \"$@\" 2>&1")
        .arg("docker")
        .arg("docker")
        .arg("build")
        .arg("-t")
        .arg(image_name)
        .arg("-f")
        .arg(dockerfile_path)
        .arg(source_path);
    let output = command.output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(GenericError::new_boxed(format!(
            "Error building test image: 'docker build' exited with code {}. \
             Output:\n\
             -------- BEGIN OUTPUT --------\n\
             {}\n\
             --------- END OUTPUT ---------\n",
            output
                .status
                .code()
                .map(|c| format!("{}", c))
                .unwrap_or(String::from("unknown")),
            String::from_utf8_lossy(&output.stdout),
        )))
    }
}

pub struct ExitStatus {
    pub code: Option<i32>,
}

impl ExitStatus {
    pub fn from_process_exit_status(e: &process::ExitStatus) -> ExitStatus {
        ExitStatus { code: e.code() }
    }

    pub fn success(&self) -> bool {
        self.code.is_some() && self.code.unwrap() == 0
    }
}

pub struct ContainerOutput {
    pub status: ExitStatus,
    pub text: String,
}

pub fn run_container(
    image: &TestImage,
    docker_args: &[&str],
    command_args: &[&str],
) -> io::Result<ContainerOutput> {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("exec \"$@\" 2>&1")
        .arg("docker")
        .arg("docker")
        .arg("run")
        .arg("--rm")
        .arg("-e")
        .arg("MHF_LOG_LEVEL=debug");
    for &arg in docker_args {
        command.arg(arg);
    }
    command.arg(image.image_name.clone());
    for &arg in command_args {
        command.arg(arg);
    }
    let output = command.output()?;
    Ok(ContainerOutput {
        status: ExitStatus::from_process_exit_status(&output.status),
        text: String::from_utf8_lossy(&output.stdout).to_string(),
    })
}

pub struct BackgroundContainer {
    pub container_id: String,
}

impl Drop for BackgroundContainer {
    fn drop(&mut self) {
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg("exec \"$@\" 2>&1")
            .arg("docker")
            .arg("docker")
            .arg("rm")
            .arg("-f")
            .arg(self.container_id.clone())
            .output();
        match output {
            Err(e) => eprintln!(
                "Warning: error removing container {}: {}",
                self.container_id, e
            ),
            Ok(output) => {
                if !output.status.success() {
                    eprintln!(
                        "Warning: error removing container {}. \
                        Output:\n\
                         -------- BEGIN OUTPUT --------\n\
                         {}\n\
                         --------- END OUTPUT ---------\n",
                        self.container_id,
                        strip_trailing_newline(&String::from_utf8_lossy(&output.stdout)),
                    );
                }
            }
        }
    }
}

pub fn run_restartable_container(
    image: &TestImage,
    docker_args: &[&str],
    command_args: &[&str],
) -> Result<BackgroundContainer, Box<dyn error::Error>> {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("exec \"$@\" 2>&1")
        .arg("docker")
        .arg("docker")
        .arg("run")
        .arg("-d")
        .arg("-e")
        .arg("MHF_LOG_LEVEL=debug");
    for &arg in docker_args {
        command.arg(arg);
    }
    command.arg(image.image_name.clone());
    for &arg in command_args {
        command.arg(arg);
    }
    let output = command.output()?;
    if output.status.success() {
        Ok(BackgroundContainer {
            container_id: strip_trailing_newline(&String::from_utf8_lossy(&output.stdout)),
        })
    } else {
        Err(GenericError::new_boxed(format!(
            "Exit status {}",
            output
                .status
                .code()
                .map(|c| format!("{}", c))
                .unwrap_or(String::from("unknown")),
        )))
    }
}

pub fn restart_container(container_id: &str) -> Result<(), Box<dyn error::Error>> {
    let mut command = Command::new("docker");
    command.arg("start").arg(container_id);
    let output = command.output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(GenericError::new_boxed(format!(
            "Exit status {}",
            output
                .status
                .code()
                .map(|c| format!("{}", c))
                .unwrap_or(String::from("unknown")),
        )))
    }
}

pub fn wait_container_and_capture_output(
    container_id: &str,
) -> Result<ContainerOutput, Box<dyn error::Error>> {
    let code = {
        let mut command = Command::new("docker");
        command.arg("wait").arg(container_id);
        let output = command.output()?;
        if !output.status.success() {
            return Err(GenericError::new_boxed(format!(
                "Error waiting for container: 'docker wait' exited with code {}",
                output
                    .status
                    .code()
                    .map(|c| format!("{}", c))
                    .unwrap_or(String::from("unknown")),
            )));
        }
        let output_text = {
            let s = String::from_utf8_lossy(&output.stdout);
            match s.strip_suffix("\n") {
                Some(s2) => s2.to_string(),
                None => s.into_owned(),
            }
        };
        match output_text.parse::<i32>() {
            Ok(x) => x,
            Err(_) =>
                return Err(GenericError::new_boxed(format!(
                    "Error waiting for container: 'docker wait' did not output a parseable exit code ('{}')",
                    output_text,
                ))),
        }
    };

    let logs = {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("exec \"$@\" 2>&1")
            .arg("docker")
            .arg("docker")
            .arg("logs")
            .arg(container_id);
        let output = command.output()?;
        if !output.status.success() {
            return Err(GenericError::new_boxed(format!(
                "Error querying container logs: 'docker logs' exited with code {}",
                output
                    .status
                    .code()
                    .map(|c| format!("{}", c))
                    .unwrap_or(String::from("unknown")),
            )));
        }
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    Ok(ContainerOutput {
        status: ExitStatus { code: Some(code) },
        text: logs,
    })
}
