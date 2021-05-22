use std::{error, fmt, fs::File, io, io::Write, path::Path, process, process::Command, thread};
use tempfile;
use thiserror::Error;

#[derive(Error)]
#[error("{0}")]
struct GenericError(String);

impl GenericError {
    fn new_boxed(message: String) -> Box<GenericError> {
        Box::new(GenericError(message))
    }
}

impl fmt::Debug for GenericError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct TestImage {
    pub image_name: String,
}

impl Drop for TestImage {
    fn drop(&mut self) {
        let output = Command::new("docker")
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
                        String::from_utf8_lossy(&output.stdout),
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

fn thread_id_to_string(id: thread::ThreadId) -> String {
    let result = format!("{:?}", id);
    result.replace("ThreadId(", "").replace(")", "")
}

pub struct ContainerOutput {
    pub status: process::ExitStatus,
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
        status: output.status,
        text: String::from_utf8_lossy(&output.stdout).to_string(),
    })
}
