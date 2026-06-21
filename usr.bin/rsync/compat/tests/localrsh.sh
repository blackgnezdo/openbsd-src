#!/bin/sh
# Fake remote shell for interop tests: invoked as `localrsh HOST CMD...`.
# Drop the host argument and run the command locally, so we exercise the
# rsync wire protocol over a pipe without needing ssh.
shift
exec "$@"
