# MatchHostFsOwner: a solution for the Docker host filesystem matching problem

> This documentation is incomplete. It is a work in progress.

`matchhostfsowner` is a program whose goal is to solve the Docker host filesystem owner matching problem.

When you run a Docker container without root privileges, then that container may not have permission to access host directory mounts, because the UID inside the container may not match the UID of the mounted files. If you run the container with the same UID as those of the files, then that may break various programs inside the container because there may not be a user account within the container with that UID.

`matchhostfsowner` helps solve this problem by ensuring that the UID that the container runs as, has a corresponding user database entry inside the container.

Surprisingly, creating such a database entry in a robust manner is more complicated than it seems. TODO: blog about this.

## Usage

 1. Setup an account named `app` in your container.
 2. Setup `matchhostfsowner` as the container entrypoint.
 3. Finally, the user is supposed to run the container with `docker run --user "$(id -u):$(id -g)" ...`.

If something goes wrong and you don't know why, then set the env var `MHF_LOG_LEVEL=debug` to see debugging logs.
