"""Source resolution: URL / shorthand / local path → local Path for analysis.

Cloning untrusted URLs is the primary attack surface. This module's
responsibility is to either (a) clone a repo into an isolated, hardened,
auto-cleaning temp dir, or (b) pass through a local path as-is.

Hardening goals:
- Neutralize git-level RCE vectors: LFS smudge, .gitattributes filter drivers,
  submodule recursion, inherited user git config, inherited credential env
  (SSH_AUTH_SOCK, GIT_ASKPASS, GIT_SSH_COMMAND).
- Refuse protocols that enable local/credential escapes (file://, ssh://).
- Guarantee cleanup of temp clones on success AND failure paths.

Phase 1 does not sandbox the clone (no bubblewrap / sandbox-exec / container).
That is a Phase 1.5+ concern; the flag set here is the cost-free first layer.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator, Literal

SourceType = Literal["url", "shorthand", "path"]

CLONE_TIMEOUT = 120  # seconds

# GitHub slug rules: owner is 1-39 chars (alphanumeric + hyphen, no leading/trailing hyphen),
# repo is 1-100 chars (alphanumeric + ._-). Tighter than the \w+/\w+ regex.
_GITHUB_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")


class GriffithCloneError(RuntimeError):
    """Raised when `git clone` fails; preserves the underlying git stderr message."""


def griffith_cache_dir() -> Path:
    """Return the user-owned clone staging directory at ~/.cache/griffith/clones (0700)."""
    cache = Path.home() / ".cache" / "griffith" / "clones"
    cache.mkdir(parents=True, exist_ok=True)
    os.chmod(cache, 0o700)  # enforce even if pre-existing with different perms
    return cache


def _is_shorthand(source: str) -> bool:
    return bool(_GITHUB_SHORTHAND_RE.match(source))


def _is_url(source: str) -> bool:
    return source.startswith(("http://", "https://", "git@"))


def _is_refused_protocol(source: str) -> bool:
    """file:// and ssh:// are refused in Phase 1 (no credential flow; no local escape)."""
    return source.startswith(("file://", "ssh://"))


def _expand_github_shorthand(source: str) -> str:
    return f"https://github.com/{source}.git"


def _build_scrubbed_env(empty_home: Path) -> dict[str, str]:
    """Build the env passed to `git clone`: minimal PATH + hardening vars only.

    Explicitly strips SSH_AUTH_SOCK, GIT_ASKPASS, SSH_ASKPASS, GIT_SSH_COMMAND
    by constructing the env from scratch rather than filtering os.environ.
    """
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "HOME": str(empty_home),
    }


_HARDENING_CONFIG = [
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "core.symlinks=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "filter.lfs.smudge=",
    "-c", "filter.lfs.required=false",
    "-c", "submodule.recurse=false",
]


@contextmanager
def _clone_hardened(url: str) -> Iterator[Path]:
    """Clone `url` into a fresh temp dir with hardening flags; auto-cleans on exit."""
    cache = griffith_cache_dir()
    with TemporaryDirectory(prefix="griffith-", dir=str(cache)) as tmp:
        os.chmod(tmp, 0o700)
        empty_home = Path(tmp) / ".empty-home"
        empty_home.mkdir(mode=0o700)

        target = Path(tmp) / "repo"
        env = _build_scrubbed_env(empty_home)
        cmd = [
            "git",
            *_HARDENING_CONFIG,
            "clone",
            "--depth", "1",
            "--no-tags",
            "--no-recurse-submodules",
            url,
            str(target),
        ]
        try:
            subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                check=True,
                timeout=CLONE_TIMEOUT,
            )
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or "").strip() or "unknown error"
            raise GriffithCloneError(f"git clone failed: {stderr}") from e
        except subprocess.TimeoutExpired as e:
            raise GriffithCloneError(
                f"git clone timed out after {CLONE_TIMEOUT}s: {url}"
            ) from e
        yield target


@contextmanager
def resolve(source: str) -> Iterator[tuple[Path, SourceType]]:
    """Resolve a plugin source string to a local Path for analysis.

    Source formats:
        - GitHub shorthand "owner/repo" (cloned from github.com)
        - Git URL "https://...", "http://...", "git@host:org/repo.git" (cloned)
        - Local path (absolute or relative, existing on disk)

    For cloned sources, the underlying temp directory is cleaned up on context
    exit, including on exceptions raised inside the `with` block.

    Yields:
        (path, source_type) where source_type is "url" | "shorthand" | "path".

    Raises:
        ValueError: if the source uses a refused protocol (file://, ssh://).
        FileNotFoundError: if a local path source does not exist.
        GriffithCloneError: if git clone fails or times out.
    """
    if _is_refused_protocol(source):
        raise ValueError(
            f"Refused protocol: {source!r}. "
            "Phase 1 supports https://, http://, git@, GitHub shorthand, and local paths."
        )

    if _is_shorthand(source):
        url = _expand_github_shorthand(source)
        print(f"griffith: expanding {source!r} -> {url}", file=sys.stderr)
        with _clone_hardened(url) as path:
            yield path, "shorthand"
    elif _is_url(source):
        with _clone_hardened(source) as path:
            yield path, "url"
    else:
        path = Path(source).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Local path does not exist: {source}")
        yield path, "path"
