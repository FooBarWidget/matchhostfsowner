# MatchHostFsOwner: a solution for the Docker host filesystem owner matching problem

> This documentation is incomplete. It is a work in progress.

`matchhostfsowner` is a program whose goal is to solve the Docker host filesystem owner matching problem.

When you run a Docker container without root privileges, then that container may not have permission to access host directory mounts, because the UID inside the container may not match the UID of the mounted files. If you run the container with the same UID as those of the files, then that may break various programs inside the container because there may not be a user account within the container with that UID.

`matchhostfsowner` helps solve this problem by ensuring that the UID that the container runs as, has a corresponding user database entry inside the container.

Surprisingly, creating such a database entry in a robust manner is more complicated than it seems. See this blog post: [Docker and the host filesystem owner matching problem
Docker and the host filesystem owner matching problem](https://www.joyfulbikeshedding.com/blog/2021-03-15-docker-and-the-host-filesystem-owner-matching-problem.html)

## Usage

### Mode 1: start container without root privileges

In this mode, `matchostfsowner` requires the setuid root bit so that it has root privileges in order to do its jobs. `matchhostfsowner` drops its setuid root bit as soon as possible.

 1. Setup an account named `app` in your container.
 2. Setup `matchhostfsowner` as the container entrypoint.
 3. Make `matchhostfsowner` setuid root.
 4. Finally, the user is supposed to run the container with `docker run --user "$(id -u):$(id -g)" ...`.

Caveats of this mode:

 - The container cannot be started a second time.
 - Not compatible with Docker Compose (because it may start the container a second time).
 - Requires that the filesystem in which `matchhostfsowner` is located, to be writable (in order to drop the setuid root bit).

### Mode 2: start container with root privileges

This mode is most suitable if any of the following is applicable:

 - You're using Docker Compose.
 - The container could be started a second time (as happens with e.g. Docker Compose).
 - The filesystem in which `matchostfsowner` is located is read-only.

Instructions:

 1. Setup an account named `app` in your container.
 2. Setup `matchhostfsowner` as the container entrypoint.
 3. Finally, the user is supposed to run the container with `docker run -e "MHF_HOST_UID=$(id -u)" -e "MHF_HOST_GID=$(id -g)" ...`.

    Using Docker Compose? Set those environment variables from your YAML file, for example:

    ~~~yaml
    services:
      foo:
        ...
        environment:
          - MHF_HOST_UID=${UID}
          - MHF_HOST_GID=${GID}
    ~~~

    Then every time you run `docker-compose up`, make sure you pass the `UID` and `GID` environment variables. For example:

    ~~~bash
    env UID=$(id -u) GID=$(id -g) docker-compose up
    ~~~

### Troubleshooting

If something goes wrong and you don't know why, then set the env var `MHF_LOG_LEVEL=debug` to see debugging logs.

## Running tests

Before running tests, build the integration test base image first. Do this every time you've modified the sources.

~~~bash
make integration-test-base
~~~

Then:

~~~bash
cargo test
~~~
