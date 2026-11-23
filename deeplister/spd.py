"""Streaming metadata extractor for Cadence PowerSI (.spd) files."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

_CHUNK_SIZE = 1024 * 1024

_PARTIAL_START_RE = re.compile(r"^\.PartialCkt(?:\s|$)", re.IGNORECASE)
_PARTIAL_RE = re.compile(r"^\.PartialCkt\s+(.+?)\s+ExtNode\s*=\s*(.*)$", re.IGNORECASE)
_END_PARTIAL_RE = re.compile(r"^\.EndPartialCkt(?:\s|$)", re.IGNORECASE)
_CONNECT_RE = re.compile(r"^\.Connect\s+(\S+)\s+(\S+)(?:\s|$)", re.IGNORECASE)
_NETLIST_START_RE = re.compile(r"^\.NetList(?:\s|$)", re.IGNORECASE)
_END_NETLIST_RE = re.compile(r"^\.EndNetList(?:\s|$)", re.IGNORECASE)
_NETLIST_DEFAULT_RE = re.compile(r"^(?:RiseTime|%Coupling)\s*=", re.IGNORECASE)
_NET_ARROW_RE = re.compile(r"^(\S+)\s*->\s*(\S+)")
_UNSELECTED_RE = re.compile(r"::Unselected(?=::|\|\||$)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class SpdInfo:
    """Extracted summary counts from a Cadence PowerSI .spd file."""

    active_nets: int
    component_types: int
    refdes_count: int


def is_spd_file(filename: str) -> bool:
    """Return True if filename has a Cadence PowerSI .spd extension."""
    return filename.lower().endswith(".spd")


def _parse_component_name(line: str) -> str:
    match = _PARTIAL_RE.match(line)
    if match:
        return match.group(1).strip()
    parts = line.split(None, 2)
    return parts[1].strip() if len(parts) >= 2 else ""


def _net_token_name(token: str) -> str:
    return token.split("::", 1)[0].split("||", 1)[0]


class SpdCounter:
    """Chunk-fed streaming parser counting active NETs, component types, and RefDes."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._first_line = True
        self._in_partial = False
        self._in_netlist = False
        self._active_nets: set[str] = set()
        self._component_types: set[str] = set()
        self._refdes_count = 0

    def feed(self, chunk: bytes | bytearray | memoryview) -> None:
        if not chunk:
            return
        data = bytes(chunk)
        start = 0
        if self._buf:
            nl = data.find(b"\n")
            if nl < 0:
                self._buf.extend(data)
                return
            self._buf.extend(data[:nl])
            self._process_line(bytes(self._buf))
            self._buf.clear()
            start = nl + 1

        last_nl = data.rfind(b"\n", start)
        if last_nl < 0:
            if start < len(data):
                self._buf.extend(data[start:])
            return

        for raw_line in data[start:last_nl].split(b"\n"):
            self._process_line(raw_line)
        if last_nl + 1 < len(data):
            self._buf.extend(data[last_nl + 1 :])

    def finish(self) -> SpdInfo:
        if self._buf:
            self._process_line(bytes(self._buf))
            self._buf.clear()
        return SpdInfo(
            active_nets=len(self._active_nets),
            component_types=len(self._component_types),
            refdes_count=self._refdes_count,
        )

    def _process_line(self, raw: bytes) -> None:
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if self._first_line:
            self._first_line = False
            if raw.startswith(b"\xef\xbb\xbf"):
                raw = raw[3:]

        if self._in_partial:
            if raw.startswith(b"."):
                line = raw.decode("utf-8", errors="replace")
                if _END_PARTIAL_RE.match(line):
                    self._in_partial = False
            return

        if self._in_netlist:
            line = raw.decode("utf-8", errors="replace")
            stripped = line.strip()
            if not stripped or stripped.startswith("*"):
                return
            if stripped.startswith("."):
                if _END_NETLIST_RE.match(stripped):
                    self._in_netlist = False
                return
            first_token = stripped.split(None, 1)[0]
            if (
                first_token.startswith(("::", "||"))
                or first_token == "+"
                or _NETLIST_DEFAULT_RE.match(stripped)
            ):
                return
            net_name = _net_token_name(first_token)
            if not net_name:
                return
            arrow = _NET_ARROW_RE.match(stripped)
            disabled = bool(
                _UNSELECTED_RE.search(first_token)
                or (arrow and _UNSELECTED_RE.search(arrow.group(2)))
            )
            if not disabled:
                self._active_nets.add(net_name)
            return

        # Outside .PartialCkt and .NetList, only dot directives at column 0 matter.
        if not raw.startswith(b"."):
            return
        line = raw.decode("utf-8", errors="replace")
        if _PARTIAL_START_RE.match(line):
            self._in_partial = True
            comp = _parse_component_name(line)
            if comp:
                self._component_types.add(comp)
            return
        connect_match = _CONNECT_RE.match(line)
        if connect_match:
            self._refdes_count += 1
            self._component_types.add(connect_match.group(2))
            return
        if _NETLIST_START_RE.match(line):
            self._in_netlist = True


def parse_spd_stream(
    stream: BinaryIO,
    cancel_event: threading.Event | None = None,
) -> SpdInfo | None:
    """Parse a binary stream for SPD counts; returns None if cancelled mid-read."""
    counter = SpdCounter()
    while True:
        if cancel_event is not None and cancel_event.is_set():
            return None
        chunk = stream.read(_CHUNK_SIZE)
        if not chunk:
            break
        counter.feed(chunk)
    return counter.finish()


def parse_spd_file(
    path: Path,
    cancel_event: threading.Event | None = None,
) -> SpdInfo | None:
    """Parse a filesystem .spd file without loading it into memory."""
    with path.open("rb", buffering=_CHUNK_SIZE) as fp:
        return parse_spd_stream(fp, cancel_event=cancel_event)
