"""Tests for the global temp disk budget used when nested archives are unpacked."""

from __future__ import annotations

import io
import tarfile
import threading
import time
import zipfile
from pathlib import Path

import py7zr
import pytest

from deeplister import scanner as scanner_module
from deeplister.models import ScanOptions, ScanResult
from deeplister.scanner import ScanEngine, auto_temp_limit

KB = 1024


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    """A stored (uncompressed) ZIP, so its size is predictable from its payload."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _leaf_zip(leaf_name: str, payload_kb: int) -> bytes:
    return _zip_bytes({leaf_name: b"\xa5" * (payload_kb * KB)})


def _make_7z(path: Path, members: dict[str, bytes]) -> None:
    with py7zr.SevenZipFile(path, "w") as sz:
        for name, data in members.items():
            sz.writestr(data, name)


def _names(result: ScanResult) -> set[str]:
    return {e.name for e in result.entries}


def _scan(paths: list[Path], timeout: float = 60.0, **options) -> tuple[ScanEngine, ScanResult]:
    """Run a scan on a helper thread so a deadlock fails the test instead of hanging it."""
    engine = ScanEngine(ScanOptions(**options))
    box: dict[str, object] = {}

    def _run() -> None:
        try:
            box["result"] = engine.scan(paths)
        except BaseException as exc:  # surfaced below
            box["error"] = exc

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        engine.cancel_event.set()
        pytest.fail(f"scan did not finish within {timeout:.0f}s (deadlock?)")
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    return engine, box["result"]  # type: ignore[return-value]


def _track_disk_use(engine: ScanEngine, monkeypatch) -> list[int]:
    """Record the real size of the temp work folder each time a temp-backed archive is queued."""
    observed: list[int] = []
    original_enqueue = engine._enqueue

    def _measuring_enqueue(task) -> None:
        root = engine._temp_root
        if root is not None and getattr(task, "temp_charge", 0):
            total = 0
            for f in root.iterdir():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass  # deleted by another worker meanwhile
            observed.append(total)
        original_enqueue(task)

    monkeypatch.setattr(engine, "_enqueue", _measuring_enqueue)
    return observed


def test_auto_temp_limit_leaves_headroom() -> None:
    gib = 1024**3
    assert auto_temp_limit(None) is None  # unknown free space: no limit
    assert auto_temp_limit(0) == 0
    assert auto_temp_limit(100 * gib) == 90 * gib  # keeps 10%
    assert auto_temp_limit(1 * gib) == 1 * gib - 256 * 1024 * 1024  # ...but at least 256 MiB
    assert auto_temp_limit(100 * 1024 * 1024) == 50 * 1024 * 1024  # never more than half


def test_user_limit_never_exceeds_what_the_disk_can_hold(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "a.txt").write_bytes(b"x")
    gib = 1024**3
    monkeypatch.setattr(scanner_module, "_free_bytes", lambda _path: 10 * gib)

    _, result = _scan([tmp_path], max_workers=1)
    assert result.stats.temp_limit_bytes == 9 * gib  # automatic

    _, result = _scan([tmp_path], max_workers=1, max_temp_bytes=2 * gib)
    assert result.stats.temp_limit_bytes == 2 * gib  # the user's lower limit

    _, result = _scan([tmp_path], max_workers=1, max_temp_bytes=500 * gib)
    assert result.stats.temp_limit_bytes == 9 * gib  # capped by the disk

    monkeypatch.setattr(scanner_module, "_free_bytes", lambda _path: None)
    _, result = _scan([tmp_path], max_workers=1)
    assert result.stats.temp_limit_bytes is None  # free space unknown: unlimited
    _, result = _scan([tmp_path], max_workers=1, max_temp_bytes=2 * gib)
    assert result.stats.temp_limit_bytes == 2 * gib


@pytest.mark.parametrize("workers", [1, 4])
def test_7z_nested_archives_are_unpacked_in_passes_within_the_limit(
    tmp_path: Path, monkeypatch, workers: int
) -> None:
    archive = tmp_path / "outer.7z"
    _make_7z(archive, {f"nested/n{i}.zip": _leaf_zip(f"leaf{i}.bin", 100) for i in range(5)})
    limit = 250 * KB  # two of the five ~100 KB archives at a time

    engine = ScanEngine(ScanOptions(max_workers=workers, max_temp_bytes=limit))
    observed = _track_disk_use(engine, monkeypatch)
    result = engine.scan([archive])

    assert not result.warnings
    assert {f"leaf{i}.bin" for i in range(5)} <= _names(result)
    stats = result.stats
    assert stats.temp_limit_bytes == limit
    assert 100 * KB < stats.temp_peak_bytes <= limit
    assert observed and max(observed) <= limit  # the real folder size, not just the bookkeeping
    assert engine._temp_used == 0  # everything was given back
    if workers == 1:
        assert stats.temp_wait_count >= 1  # later passes had to wait for earlier ones


def test_without_a_limit_all_nested_archives_are_unpacked_at_once(
    tmp_path: Path, monkeypatch
) -> None:
    archive = tmp_path / "outer.7z"
    _make_7z(archive, {f"nested/n{i}.zip": _leaf_zip(f"leaf{i}.bin", 100) for i in range(5)})
    monkeypatch.setattr(scanner_module, "_free_bytes", lambda _path: None)

    _, result = _scan([archive], max_workers=1)

    assert not result.warnings
    assert {f"leaf{i}.bin" for i in range(5)} <= _names(result)
    assert result.stats.temp_limit_bytes is None
    assert result.stats.temp_peak_bytes > 500 * KB  # all five on disk together
    assert result.stats.temp_wait_count == 0


def test_only_the_nested_archive_larger_than_the_limit_is_skipped(tmp_path: Path) -> None:
    archive = tmp_path / "outer.7z"
    _make_7z(
        archive,
        {
            "small.zip": _leaf_zip("small_leaf.bin", 50),
            "big.zip": _leaf_zip("big_leaf.bin", 300),
        },
    )

    _, result = _scan([archive], max_workers=2, max_temp_bytes=200 * KB)

    names = _names(result)
    assert {"small.zip", "big.zip", "small_leaf.bin"} <= names
    assert "big_leaf.bin" not in names
    assert len(result.warnings) == 1
    reason = result.warnings[0].reason
    assert "임시 폴더 여유 공간이 부족" in reason
    assert "중첩 압축파일 1개" in reason
    assert "'최대 사용' 한도" in reason  # says what to change


@pytest.mark.parametrize("kind", ["zip", "tar"])
@pytest.mark.parametrize("workers", [1, 4])
def test_zip_and_tar_parents_wait_for_space_instead_of_failing(
    tmp_path: Path, kind: str, workers: int
) -> None:
    nested = {f"n{i}.zip": _leaf_zip(f"leaf{i}.bin", 100) for i in range(4)}
    if kind == "zip":
        archive = tmp_path / "outer.zip"
        archive.write_bytes(_zip_bytes(nested))
    else:
        archive = tmp_path / "outer.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            for name, data in nested.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    limit = 150 * KB  # one ~100 KB nested archive at a time

    engine, result = _scan(
        [archive],
        max_workers=workers,
        max_temp_bytes=limit,
        max_memory_archive_bytes=0,  # unpack to disk instead of memory
    )

    assert not result.warnings
    assert {f"leaf{i}.bin" for i in range(4)} <= _names(result)
    assert 0 < result.stats.temp_peak_bytes <= limit
    assert engine._temp_used == 0
    if workers == 1:
        assert result.stats.temp_wait_count >= 1


def _make_three_level_archive(path: Path) -> None:
    """outer.7z > mid.zip (~210 KB) > inner.zip (~150 KB) > deep_leaf.bin"""
    inner = _leaf_zip("deep_leaf.bin", 150)
    mid = _zip_bytes({"inner.zip": inner, "mid_note.bin": b"m" * (50 * KB)})
    _make_7z(path, {"mid.zip": mid})


def test_nesting_chain_that_fits_the_limit_is_scanned(tmp_path: Path) -> None:
    archive = tmp_path / "outer.7z"
    _make_three_level_archive(archive)

    _, result = _scan(
        [archive], max_workers=2, max_temp_bytes=400 * KB, max_memory_archive_bytes=0
    )

    assert not result.warnings
    assert {"mid.zip", "inner.zip", "mid_note.bin", "deep_leaf.bin"} <= _names(result)
    # mid.zip stays on disk while inner.zip is unpacked from it
    assert 350 * KB < result.stats.temp_peak_bytes <= 400 * KB


def test_nesting_chain_larger_than_the_limit_is_reported_not_hung(tmp_path: Path) -> None:
    archive = tmp_path / "outer.7z"
    _make_three_level_archive(archive)

    _, result = _scan(
        [archive], max_workers=2, max_temp_bytes=300 * KB, max_memory_archive_bytes=0
    )

    names = _names(result)
    assert {"mid.zip", "inner.zip", "mid_note.bin"} <= names  # everything that did fit
    assert "deep_leaf.bin" not in names
    assert len(result.warnings) == 1
    assert result.warnings[0].path.endswith("inner.zip")
    assert "임시 폴더 여유 공간이 부족" in result.warnings[0].reason
    assert result.stats.temp_peak_bytes <= 300 * KB


@pytest.mark.parametrize("limit_kb", [400, 250])
@pytest.mark.parametrize("workers", [1, 2, 4, 8])
def test_mixed_tree_under_a_tight_limit_never_deadlocks_or_exceeds_it(
    tmp_path: Path, monkeypatch, workers: int, limit_kb: int
) -> None:
    """Several parents competing for a small budget: finish, stay within it, lose nothing.

    Every request here can be met once the other archives are finished (the largest nested
    archive is ~120 KB and the deepest chain needs ~100 KB), so a missing entry would mean
    a worker gave up too early.
    """
    root = tmp_path / "tree"
    root.mkdir()
    expected: set[str] = set()

    for p in range(3):
        members = {}
        for i in range(4):
            leaf = f"p{p}_leaf{i}.bin"
            expected.add(leaf)
            members[f"n{i}.zip"] = _leaf_zip(leaf, 60 + 20 * i)
        # one archive per parent goes a level deeper
        deep_leaf = f"p{p}_deep.bin"
        expected.add(deep_leaf)
        members["chain.zip"] = _zip_bytes(
            {"inner.zip": _leaf_zip(deep_leaf, 40), "pad.bin": b"p" * (20 * KB)}
        )
        _make_7z(root / f"parent{p}.7z", members)

    zip_members = {}
    for i in range(4):
        leaf = f"z_leaf{i}.bin"
        expected.add(leaf)
        zip_members[f"z{i}.zip"] = _leaf_zip(leaf, 80)
    (root / "plain.zip").write_bytes(_zip_bytes(zip_members))

    limit = limit_kb * KB
    for _round in range(3):
        engine = ScanEngine(
            ScanOptions(max_workers=workers, max_temp_bytes=limit, max_memory_archive_bytes=0)
        )
        observed = _track_disk_use(engine, monkeypatch)
        box: dict[str, ScanResult] = {}
        thread = threading.Thread(target=lambda: box.update(result=engine.scan([root])), daemon=True)
        thread.start()
        thread.join(60)
        if thread.is_alive():
            engine.cancel_event.set()
            pytest.fail(f"scan with {workers} workers did not finish (deadlock?)")
        result = box["result"]

        assert result.stats.temp_peak_bytes <= limit
        assert observed and max(observed) <= limit
        assert engine._temp_used == 0
        assert engine._temp_settled_waiters == 0 and engine._busy_workers == 0
        assert not result.warnings, [w.reason for w in result.warnings]
        assert expected <= _names(result)
        assert result.stats.temp_wait_count >= 1  # the budget really was contended


def test_limited_scan_lists_exactly_what_an_unlimited_scan_lists(
    tmp_path: Path, monkeypatch
) -> None:
    """The budget changes when archives are unpacked, never what ends up in the list."""
    root = tmp_path / "tree"
    root.mkdir()
    inner_7z = io.BytesIO()
    with py7zr.SevenZipFile(inner_7z, "w") as sz:  # 7z nested in 7z, as in real backups
        sz.writestr(b"d" * (70 * KB), "docs/drawing.dwg")
        sz.writestr(_leaf_zip("deep.bin", 30), "deeper.zip")
    _make_7z(
        root / "backup_a.7z",
        {
            "parts/model.7z": inner_7z.getvalue(),
            "parts/a1.zip": _leaf_zip("a1.bin", 90),
            "parts/a2.zip": _leaf_zip("a2.bin", 110),
            "readme.txt": b"plain member",
        },
    )
    _make_7z(root / "backup_b.7z", {f"b{i}.zip": _leaf_zip(f"b{i}.bin", 80) for i in range(4)})
    (root / "mail.zip").write_bytes(
        _zip_bytes({f"m{i}.zip": _leaf_zip(f"m{i}.bin", 60) for i in range(3)})
    )

    def listing(result: ScanResult) -> list[tuple]:
        return [
            (e.directory, e.name, e.size, e.kind, e.archive_depth, e.source, e.modified_at)
            for e in result.entries
        ]

    monkeypatch.setattr(scanner_module, "_free_bytes", lambda _path: None)  # no automatic limit
    _, unlimited = _scan([root], max_workers=4, max_memory_archive_bytes=0)
    assert unlimited.stats.temp_limit_bytes is None
    assert not unlimited.warnings
    assert {"drawing.dwg", "deep.bin", "a2.bin", "b3.bin", "m2.bin"} <= _names(unlimited)

    for workers in (1, 3, 8):
        engine, limited = _scan(
            [root], max_workers=workers, max_temp_bytes=260 * KB, max_memory_archive_bytes=0
        )
        assert not limited.warnings, [w.reason for w in limited.warnings]
        assert listing(limited) == listing(unlimited)
        assert limited.stats.temp_peak_bytes <= 260 * KB < unlimited.stats.temp_peak_bytes
        assert limited.stats.temp_wait_count >= 1
        assert engine._temp_used == 0


def _idle_engine(limit: int, used: int = 0, busy: int = 1) -> ScanEngine:
    engine = ScanEngine(ScanOptions(max_workers=2))
    engine._temp_limit = limit
    engine._temp_used = used
    engine._busy_workers = busy
    return engine


def test_reserve_gives_up_at_once_when_nobody_can_free_space() -> None:
    # 80 of 100 is held, this is the only busy worker and nothing is queued: waiting is pointless
    engine = _idle_engine(limit=100, used=80, busy=1)

    started = time.perf_counter()
    assert engine._reserve_temp(50) is False
    assert time.perf_counter() - started < 1.0
    assert engine._temp_used == 80
    assert engine._temp_settled_waiters == 0


def test_reserve_fails_when_request_cannot_fit_even_in_an_empty_budget() -> None:
    engine = _idle_engine(limit=100, used=0, busy=1)
    assert engine._reserve_temp(101) is False
    assert engine._reserve_temp(100) is True
    assert engine._temp_used == 100 and engine._temp_peak == 100
    engine._release_temp(100)
    assert engine._temp_used == 0


def test_reserve_waits_until_another_worker_releases_space() -> None:
    # Another worker is busy (and not waiting), so space may still be freed
    engine = _idle_engine(limit=100, used=80, busy=2)
    outcome: list[bool] = []
    waiter = threading.Thread(target=lambda: outcome.append(engine._reserve_temp(50)), daemon=True)
    waiter.start()

    time.sleep(0.4)
    assert waiter.is_alive() and not outcome  # still waiting
    engine._release_temp(80)
    waiter.join(5)

    assert outcome == [True]
    assert engine._temp_used == 50
    assert engine._temp_wait_count == 1
    assert engine._temp_settled_waiters == 0


def test_reserve_stops_waiting_when_the_scan_is_cancelled() -> None:
    engine = _idle_engine(limit=100, used=80, busy=2)
    outcome: list[bool] = []
    waiter = threading.Thread(target=lambda: outcome.append(engine._reserve_temp(50)), daemon=True)
    waiter.start()

    time.sleep(0.2)
    engine.cancel_event.set()
    waiter.join(5)

    assert outcome == [False]
    assert engine._temp_used == 80


def test_waiting_worker_scans_a_queued_archive_to_free_its_space(tmp_path: Path) -> None:
    # The whole budget is held by one queued nested archive; the only worker must scan it itself
    nested = tmp_path / "queued.zip"
    nested.write_bytes(_leaf_zip("freed_leaf.bin", 4))
    engine = _idle_engine(limit=100, used=100, busy=1)
    engine._temp_root = tmp_path
    engine._pending_count = 1
    engine._temp_tasks.append(
        scanner_module._ArchiveTask(
            archive_type="zip",
            virtual_path=str(nested),
            depth=1,
            source_path=nested,
            cleanup_path=nested,
            temp_charge=100,
        )
    )

    assert engine._reserve_temp(60) is True

    assert engine._temp_used == 60  # the queued archive's 100 was released, then 60 reserved
    assert not nested.exists()  # ...and its temp file deleted
    assert "freed_leaf.bin" in {e.name for e in engine._entries}
    assert not engine._temp_tasks
