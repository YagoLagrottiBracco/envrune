"""Load environment variables from the EnvRune vault instead of a .env file.

The values come from the ``envrune`` CLI, which must be able to unlock the
vault without a prompt: run ``envrune unlock`` first. It never falls back to
a .env file.

    import envrune
    envrune.load()
"""

import json
import os
import re
import subprocess
from typing import Dict, Optional

__all__ = ["EnvruneError", "load"]


class EnvruneError(RuntimeError):
    """EnvRune could not provide the variables."""


def load(
    environment: Optional[str] = None,
    *,
    cwd: Optional[str] = None,
    override: bool = False,
    binary: Optional[str] = None,
) -> Dict[str, str]:
    """Load the variables of the nearest envrune.yml into os.environ.

    environment: the environment to load; the default one otherwise.
    cwd: the folder to look for envrune.yml from; the current one otherwise.
    override: replace variables that are already set.
    binary: the envrune executable; ENVRUNE_BIN or "envrune" otherwise.

    Returns the variables that EnvRune provided.
    """
    executable = binary or os.environ.get("ENVRUNE_BIN") or "envrune"
    args = [executable, "env", "--format", "json", "--no-prompt"]
    if environment:
        args += ["--env", environment]
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env={**os.environ, "NO_COLOR": "1"},
        )
    except FileNotFoundError as error:
        raise EnvruneError(
            f"envrune was not found ({executable}). Install EnvRune and make sure it "
            "is on PATH, or set ENVRUNE_BIN."
        ) from error
    if completed.returncode != 0:
        detail = re.sub(r"^\[ERROR\]\s*", "", completed.stderr.strip(), flags=re.MULTILINE)
        raise EnvruneError(
            detail
            or f"envrune exited with code {completed.returncode}. Run `envrune env` in a terminal to see why."
        )
    try:
        values = json.loads(completed.stdout)
    except ValueError as error:
        raise EnvruneError("envrune printed something that is not JSON. Update EnvRune.") from error
    for name, value in values.items():
        if override or name not in os.environ:
            os.environ[name] = value
    return values
