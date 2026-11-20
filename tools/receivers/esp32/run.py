"""Runs a host build of an ESP32 scanner firmware (see build.sh) on a capture.

Usage: python run.py HARNESS CAPTURE

On Windows the harness is a Linux binary and runs under WSL. Its stdout
(the firmware's USB serial output) is passed through and its exit status
is kept, so a crash fails the replay.
"""

import os
import subprocess
import sys


def wsl_path(p):
    p = os.path.abspath(p)
    return "/mnt/" + p[0].lower() + p[2:].replace("\\", "/")


harness, capture = sys.argv[1], sys.argv[2]
if os.name == "nt":
    cmd = ["wsl", "-d", os.environ.get("REPLAY_WSL_DISTRO", "Ubuntu-24.04"), "--", wsl_path(harness), wsl_path(capture)]
else:
    cmd = [harness, capture]
r = subprocess.run(cmd, stdout=sys.stdout, stderr=sys.stderr)
code = r.returncode
if code < 0 or code >= 128:
    sys.stderr.write(f"harness died with signal {(-code) if code < 0 else code - 128}\n")
sys.exit(code)
