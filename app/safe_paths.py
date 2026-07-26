"""Filesystem containment for paths built out of request data.

Every path assembled from a caller-supplied value goes through
:func:`resolve_within`, which validates each segment and then proves — on the
*resolved* path, after symlinks and ``..`` have been collapsed — that the
result stayed underneath the permitted root.

Why ``realpath`` + ``startswith`` and not ``Path.relative_to`` or a
``Path.parent`` comparison: at runtime all three are equivalent, but only the
realpath/startswith form is recognised as a sanitiser by CodeQL's
py/path-injection dataflow. The earlier ``parent``/``relative_to`` spellings
were correct and still reported as unguarded flows, so the check is written in
the form the analyser understands as well as the reader.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# One path segment. No separators, and never a dots-only name: the character
# class permits ".", so without the leading negative lookahead both "." and
# ".." would satisfy it and could be appended as a traversal step.
SAFE_SEGMENT_RE = re.compile(r"\A(?!\.+\Z)[A-Za-z0-9._-]{1,128}\Z")


def is_safe_segment(value: object) -> bool:
    """True if ``value`` is a string usable as a single path segment."""
    return isinstance(value, str) and SAFE_SEGMENT_RE.match(value) is not None


def resolve_within(root: str | os.PathLike[str], *parts: str) -> Path:
    """Join ``parts`` under ``root`` and return the resolved path.

    Raises
    ------
    ValueError
        If ``parts`` is empty, if any part is not a plain path segment, or if
        the resolved path lands outside ``root`` — whether by traversal or by
        following a symlink out of the tree.
    """
    if not parts:
        raise ValueError("resolve_within requires at least one path segment")

    for part in parts:
        if not is_safe_segment(part):
            raise ValueError(f"unsafe path segment: {part!r}")

    root_real = os.path.realpath(root)
    full = os.path.realpath(os.path.join(root_real, *parts))
    if not full.startswith(root_real + os.sep):
        raise ValueError("path escapes its permitted root")
    return Path(full)
