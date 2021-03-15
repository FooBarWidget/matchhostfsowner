#!/bin/bash
# This hook script is run inside the ekidd/rust-musl-builder container
# to perform a limited chown of /home/rust. The default chown performed
# by matchhostfsowner chowns everything in /home/rust recursively,
# but that is very slow because there's a large number of files in
# /home/rust/.rustup. In this script we only chown a small number of
# files, enough to make the container work after having modified the UID
# of the 'rust' account.
set -e
shopt -s dotglob

chown "$MHF_HOST_UID:$MHF_HOST_GID" "$MHF_HOST_HOME"
chown "$MHF_HOST_UID:$MHF_HOST_GID" "$MHF_HOST_HOME"/*
