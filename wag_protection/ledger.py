# SPDX-License-Identifier: AGPL-3.0-or-later
"""SQLite accounting under one nonblocking, process-owned Linux flock."""

import concurrent.futures
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
import errno
import fcntl
from importlib.metadata import PackageNotFoundError
import os
from pathlib import Path
import secrets
import select
import signal
import sqlite3
import subprocess
import sys
from types import MappingProxyType
import stat
import tempfile
import threading
import time
from typing import TypeGuard, TypedDict, cast
from urllib.parse import quote

from .contract import (
    CALLERS, OUTCOMES, PHASES, REASONS, PRODUCTION_ROOT, VERSION,
    EngineFailure, EngineOutcome, ProtectionError, Refusal, canonical_json, canonical_path, finite,
    hex_value, json_digest, load_json, validate_evidence, validate_manifest, validate_registry,
    MaintenanceCapability, PoisonSelection, RecoveryProofV1, RecoveryResult, SenderBinding,
    RECOVERY_DECISIONS, recovery_authorization, _MAINTENANCE_TOKEN,
)

SCHEMA = """
CREATE TABLE state (id TEXT PRIMARY KEY, root TEXT NOT NULL, checkpoint TEXT NOT NULL);
CREATE TABLE contract_meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL CHECK(version=2),
 registry_digest TEXT NOT NULL, migration_wall REAL NOT NULL, migration_mono REAL NOT NULL,
 migration_boot TEXT NOT NULL);
CREATE TABLE engine_identities (
 engine TEXT PRIMARY KEY, domestic INTEGER NOT NULL CHECK(domestic IN (0,1)), module TEXT NOT NULL,
 capability TEXT NOT NULL CHECK(capability='online_one_send'), source_digest TEXT NOT NULL, profile_json TEXT NOT NULL);
CREATE TABLE aliases (alias TEXT PRIMARY KEY, engine TEXT NOT NULL REFERENCES engine_identities(engine));
CREATE TABLE attempts (
 attempt_id INTEGER PRIMARY KEY, dispatch_id TEXT NOT NULL, engine TEXT NOT NULL REFERENCES engine_identities(engine),
 domestic INTEGER NOT NULL CHECK(domestic IN (0,1)), stamp REAL NOT NULL, outcome TEXT NULL,
 reserved_mono REAL NULL, finished_mono REAL NULL, account_boot TEXT NOT NULL, account_mono REAL NOT NULL,
 caller TEXT NOT NULL, phase TEXT NOT NULL,
 connection_attempted INTEGER NULL CHECK(connection_attempted IN (0,1)),
 http_attempted INTEGER NULL CHECK(http_attempted IN (0,1)), elapsed REAL NULL,
 source TEXT NOT NULL CHECK(source IN ('legacy','v2')));
CREATE INDEX attempts_engine_account ON attempts(engine,account_boot,account_mono);
CREATE INDEX attempts_domestic_account ON attempts(domestic,account_boot,account_mono);
CREATE INDEX attempts_dispatch ON attempts(dispatch_id);
CREATE TABLE pauses (
 engine TEXT PRIMARY KEY REFERENCES engine_identities(engine), strikes INTEGER NOT NULL CHECK(strikes>=0),
 until REAL NOT NULL);
CREATE TABLE poison (reason TEXT NOT NULL);
CREATE TABLE release_checks (
 release_id TEXT PRIMARY KEY, artifact_digest TEXT NOT NULL, config_digest TEXT NOT NULL, boot TEXT NOT NULL,
 claimed_mono REAL NOT NULL, deadline_mono REAL NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('claimed','complete','unknown')),
 ingress_used INTEGER NOT NULL CHECK(ingress_used IN (0,1)), finished_mono REAL NULL, evidence_json TEXT NULL);
CREATE TABLE recoveries (
 recovery_id INTEGER PRIMARY KEY, authorization TEXT NOT NULL, old_checkpoint TEXT NOT NULL,
 old_poison_json TEXT NOT NULL, new_boot TEXT NOT NULL, wall REAL NOT NULL, mono REAL NOT NULL, decision TEXT NOT NULL);
CREATE TABLE recovery_attempts (
 recovery_id INTEGER NOT NULL REFERENCES recoveries(recovery_id),
 attempt_id INTEGER NOT NULL REFERENCES attempts(attempt_id),
 old_row_json TEXT NOT NULL, PRIMARY KEY(recovery_id,attempt_id));
CREATE TABLE recovery_pauses (
 recovery_id INTEGER NOT NULL REFERENCES recoveries(recovery_id),
 engine TEXT NOT NULL REFERENCES engine_identities(engine),
 old_strikes INTEGER NULL, old_until REAL NULL, PRIMARY KEY(recovery_id,engine));
PRAGMA user_version=2;
"""
# Exact original ProbeLedger.initialize DDL, reviewed at source lines522–527.
LEGACY_SCHEMA = """
CREATE TABLE state (id TEXT, root TEXT, checkpoint TEXT);
CREATE TABLE attempts (engine TEXT, domestic INTEGER, stamp REAL, outcome TEXT);
CREATE TABLE pauses (engine TEXT PRIMARY KEY, strikes INTEGER, until REAL);
CREATE TABLE poison (reason TEXT);
"""
LEGACY_TABLES = frozenset(('state', 'attempts', 'pauses', 'poison'))
TABLES = frozenset((
    'state', 'contract_meta', 'engine_identities', 'aliases', 'attempts', 'pauses', 'poison',
    'release_checks', 'recoveries', 'recovery_attempts', 'recovery_pauses',
))


class ClockSample(TypedDict):
    wall: float
    mono: float
    boot: str


class SenderRecord(TypedDict):
    process: subprocess.Popen[str]
    pidfd: int | None
    binding: SenderBinding | None
    reaped: bool


CURRENT_DISPATCH: ContextVar['Dispatch | None'] = ContextVar('wag_protection_dispatch', default=None)
# Only lock descriptors are tracked here, never a dispatch, DB or send permit.
_LOCK_FDS = set()
_LOCK_FDS_MUTEX = threading.Lock()
_FORK_HOOK_INSTALLED = False


def _after_fork_child():
    try:
        for fd in _LOCK_FDS:
            os.close(fd)
        _LOCK_FDS.clear()
    finally:
        _LOCK_FDS_MUTEX.release()


def _open_lock(path):
    global _FORK_HOOK_INSTALLED
    with _LOCK_FDS_MUTEX:
        if not _FORK_HOOK_INSTALLED:
            os.register_at_fork(before=_LOCK_FDS_MUTEX.acquire,
                                after_in_parent=_LOCK_FDS_MUTEX.release, after_in_child=_after_fork_child)
            _FORK_HOOK_INSTALLED = True
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        _LOCK_FDS.add(fd)
        return fd


def _close_lock(fd, pid):
    # The child hook already closed this FD. Its number may since have been
    # reused; neither close nor SQLite cleanup may touch an inherited owner.
    if os.getpid() == pid:
        with _LOCK_FDS_MUTEX:
            _LOCK_FDS.remove(fd)
            os.close(fd)


def _clock() -> ClockSample:
    return {'wall': time.time(), 'mono': time.monotonic(),
            'boot': Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()}


def _valid_clock(clock: object) -> TypeGuard[ClockSample]:
    if not isinstance(clock, dict) or set(clock) != {'wall', 'mono', 'boot'}:
        return False
    sample = cast(dict[str, object], clock)
    return (finite(sample['wall']) and finite(sample['mono'])
            and isinstance(sample['boot'], str) and 0 < len(sample['boot']) <= 128)


def _clock_matches(previous: object, now: object) -> bool:
    return (_valid_clock(previous) and _valid_clock(now) and previous['boot'] == now['boot']
            and now['wall'] >= previous['wall'] and now['mono'] >= previous['mono']
            and abs((now['wall'] - previous['wall']) - (now['mono'] - previous['mono'])) <= 2.0)


def _secure(path, manifest, directory=False):
    canonical_path(path)
    info = path.stat(follow_symlinks=False)
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or (not directory and info.st_nlink != 1):
        raise ProtectionError('identity_error')
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid not in manifest['allowed_uids'] or info.st_gid != manifest['shared_gid']:
        raise ProtectionError('identity_error')
    if mode & 0o007 or (not directory and mode & 0o111) or not mode & 0o600:
        raise ProtectionError('identity_error')
    return info


def _fsync_root(root):
    # SQLite FULL protects the journal transaction; also persist directory entries.
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# A completion marker is a durable admission barrier, not a replacement store.
# It is removed only after the final outcomes and directory entries are durable.
# A crash/error leaves it for explicit offline operator review; never auto-clear.
_COMPLETION_PENDING = 'completion.pending'


def _require_completion_clear(root):
    try:
        (root / _COMPLETION_PENDING).lstat()
    except FileNotFoundError:
        return
    raise ProtectionError('storage_error')


def _commit(db, root, *, completion=False):
    marker = root / _COMPLETION_PENDING
    if completion:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        # If preparing the marker fails, do not commit any pending final UPDATEs.
        # Closing the connection leaves the previous durable NULL reservation.
        _fsync_root(root)
    try:
        db.commit()
        _fsync_root(root)
    except (OSError, sqlite3.Error):
        # Either commit or directory fsync may fail after SQLite made the write
        # visible. Attempt poison, but retain the completion barrier regardless.
        try:
            db.execute('INSERT INTO poison VALUES (?)', ('storage_error',))
            db.commit()
            _fsync_root(root)
        except (OSError, sqlite3.Error):
            try:
                db.rollback()
            except sqlite3.Error:
                pass  # Preserve the original storage error and durable barrier.
        raise
    # The completion caller retains the marker through notification accounting;
    # a cancelled publication may still need a durable unfinished transition.


def _schema_signature(db, table_names=TABLES):
    objects = tuple(tuple(row) for row in db.execute(
        'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'
    ))
    tables = []
    for name in sorted(table_names):
        columns = tuple(tuple(row) for row in db.execute(f'PRAGMA table_xinfo("{name}")'))
        foreign_keys = tuple(tuple(row) for row in db.execute(f'PRAGMA foreign_key_list("{name}")'))
        indices = []
        for row in db.execute(f'PRAGMA index_list("{name}")'):
            # PRAGMA enumeration order is not part of the durable contract.
            index = tuple(row)[1:]
            index_name = index[0].replace('"', '""')
            fields = tuple(tuple(field) for field in db.execute(f'PRAGMA index_xinfo("{index_name}")'))
            indices.append((index, fields))
        tables.append((name, columns, foreign_keys, tuple(sorted(indices))))
    return objects, tuple(tables)


def _validate_schema(db):
    # Compile only the reviewed v2 DDL. No on-disk creation or schema repair;
    # legacy schemas belong to the separately authorized migration API.
    reference = sqlite3.connect(':memory:')
    try:
        reference.executescript(SCHEMA)
        if db.execute('SELECT 1 FROM sqlite_temp_master LIMIT 1').fetchone() or (
            _schema_signature(db) != _schema_signature(reference)
        ):
            raise ProtectionError('schema_error')
    finally:
        reference.close()


def _insert_registry(db, registry):
    for entry in registry:
        db.execute('INSERT INTO engine_identities VALUES (?,?,?,?,?,?)', (
            entry['engine'], int(entry['domestic']), entry['module'], entry['capability'],
            entry['source_digest'], canonical_json(entry['profile']),
        ))
        db.executemany('INSERT INTO aliases VALUES (?,?)', [(alias, entry['engine']) for alias in entry['aliases']])


def initialize_fixture(root, *, registry, clock):
    """Create disposable synthetic state only, never a production identity."""
    root = canonical_path(root)
    temporary_root = canonical_path(tempfile.gettempdir())
    if (root == PRODUCTION_ROOT or PRODUCTION_ROOT in root.parents or root == temporary_root
            or temporary_root not in root.parents or root.exists() or Path(str(root) + '.identity').exists()):
        raise ValueError('fixture requires a new explicit disposable root')
    registry = validate_registry(registry)
    now = clock()
    if not _valid_clock(now):
        raise ValueError('invalid fixture clock')
    root.mkdir(mode=0o700)
    identity = secrets.token_hex(16).encode('ascii')
    for path, data in ((root / 'identity', identity), (Path(str(root) + '.identity'), identity), (root / 'lock', b'')):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    fd = os.open(root / 'ledger.sqlite', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    db = sqlite3.connect(root / 'ledger.sqlite', timeout=0)
    try:
        db.execute('PRAGMA journal_mode=DELETE')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA foreign_keys=ON')
        db.executescript(SCHEMA)
        db.execute('INSERT INTO state VALUES (?,?,?)', (identity.decode('ascii'), str(root), canonical_json(now)))
        db.execute('INSERT INTO contract_meta VALUES (1,2,?,?,?,?)',
                   (json_digest(registry), now['wall'], now['mono'], now['boot']))
        _insert_registry(db, registry)
        _commit(db, root)
    finally:
        db.close()


class DispatchNotification:
    """One dispatch's cancellation notice; never contains a context, DB or FD."""

    def __init__(self):
        self._pid = os.getpid()
        self._worker = None
        self._lock = threading.Lock()
        self._cancelled = threading.Event()
        self._requested = threading.Event()
        self._result = None
        self._reservations = 0

    @property
    def reservations(self):
        self._check_pid()
        with self._lock:
            return self._reservations

    def _record_reservation(self):
        self._check_pid()
        if self._worker != threading.get_ident():
            raise ProtectionError('capability_refused')
        with self._lock:
            self._reservations += 1

    def _check_pid(self):
        if os.getpid() != self._pid:
            raise ProtectionError('capability_refused')

    def _bind(self):
        self._check_pid()
        with self._lock:
            if self._worker is not None:
                raise ProtectionError('capability_refused')
            self._worker = threading.get_ident()

    @property
    def cancelled(self):
        self._check_pid()
        return self._cancelled.is_set()

    @property
    def cancellation_requested(self):
        self._check_pid()
        return self._requested.is_set()

    def cancel(self):
        """Request stop, without claiming that the sender has stopped."""
        self._check_pid()
        with self._lock:
            if self._result is None:
                self._requested.set()

    def notify(self):
        self._check_pid()
        # This mutex arbitrates notification/publication, including the final
        # marker unlink. It never covers network I/O, DB commits or worker waits.
        with self._lock:
            if self._result is None:
                self._cancelled.set()
            return self._result

    def _publish(self, result, *, unfinished=False, completion_marker=None):
        self._check_pid()
        if self._worker != threading.get_ident():
            raise ProtectionError('capability_refused')
        with self._lock:
            if not unfinished and (self.cancelled or (
                    self.cancellation_requested and getattr(result, 'outcome', None) != 'cancelled')):
                return False
            if completion_marker is not None:
                completion_marker.unlink()
            self._result = result
            return True


class Store:
    """A validated handle, not a cached admission or a transferable lock."""

    def __init__(self, root, manifest, mode):
        self.root = root
        self.manifest = manifest
        self.mode = mode
        self.pid = os.getpid()

    @contextmanager
    def _locked(self, *, readonly=False, migration=False) -> Generator[sqlite3.Connection, None, None]:
        if self.pid != os.getpid():
            raise ProtectionError('capability_refused')
        for path, directory in ((self.root, True), (self.root / 'lock', False),
                                (self.root / 'identity', False), (self.root / 'ledger.sqlite', False),
                                (Path(str(self.root) + '.identity'), False)):
            _secure(path, self.manifest, directory)
        for suffix in ('-journal', '-wal', '-shm'):
            path = Path(str(self.root / 'ledger.sqlite') + suffix)
            if path.exists() or path.is_symlink():
                _secure(path, self.manifest)
                if suffix != '-journal':
                    raise ProtectionError('schema_error')
        fd = _open_lock(self.root / 'lock')
        db: sqlite3.Connection | None = None
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EACCES):
                    raise ProtectionError('lock_busy') from None
                raise
            if os.fstat(fd).st_ino != (self.root / 'lock').stat().st_ino:
                raise ProtectionError('identity_error')
            _require_completion_clear(self.root)
            uri = 'file:' + quote(str(self.root / 'ledger.sqlite')) + ('?mode=ro' if readonly else '?mode=rw')
            db = sqlite3.connect(uri, uri=True, timeout=0, check_same_thread=False)
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA synchronous=FULL')
            if migration and db.execute('PRAGMA user_version').fetchone()[0] == 0:
                db.execute('BEGIN IMMEDIATE')
                self._validate_legacy(db)
            else:
                self._validate(db)
            assert db is not None
            yield db
        finally:
            if db is not None and os.getpid() == self.pid:
                db.close()
            _close_lock(fd, self.pid)

    def _validate_legacy(self, db):
        if (db.execute('PRAGMA journal_mode').fetchone()[0] != 'delete'
                or db.execute('PRAGMA user_version').fetchone()[0] != 0
                or db.execute('PRAGMA quick_check').fetchone()[0] != 'ok'):
            raise ProtectionError('schema_error')
        reference = sqlite3.connect(':memory:')
        try:
            reference.executescript(LEGACY_SCHEMA)
            if (db.execute('SELECT 1 FROM sqlite_temp_master LIMIT 1').fetchone()
                    or _schema_signature(db, LEGACY_TABLES) != _schema_signature(reference, LEGACY_TABLES)):
                raise ProtectionError('schema_error')
        finally:
            reference.close()
        states = db.execute('SELECT * FROM state').fetchall()
        if len(states) != 1:
            raise ProtectionError('identity_error')
        state = states[0]
        identity = (self.root / 'identity').read_bytes()
        anchor = Path(str(self.root) + '.identity').read_bytes()
        if (not hex_value(state['id'], 32) or identity != state['id'].encode('ascii') or anchor != identity
                or state['root'] != str(self.root)):
            raise ProtectionError('identity_error')
        if not _valid_clock(load_json(state['checkpoint'])):
            raise ProtectionError('clock_error')
        expected = {entry['engine']: entry for entry in self.manifest['registry']}
        for row in db.execute('SELECT * FROM attempts'):
            if (row['engine'] not in expected or type(row['domestic']) is not int
                    or row['domestic'] != int(expected[row['engine']]['domestic']) or not finite(row['stamp'])
                    or (row['outcome'] is not None and row['outcome'] not in OUTCOMES)):
                raise ProtectionError('schema_error')
        for row in db.execute('SELECT * FROM pauses'):
            if (row['engine'] not in expected or type(row['strikes']) is not int
                    or row['strikes'] < 0 or not finite(row['until'])):
                raise ProtectionError('schema_error')
        if any(not isinstance(row[0], str) for row in db.execute('SELECT reason FROM poison')):
            raise ProtectionError('schema_error')

    def _validate(self, db):
        if db.execute('PRAGMA journal_mode').fetchone()[0] != 'delete':
            raise ProtectionError('schema_error')
        if db.execute('PRAGMA user_version').fetchone()[0] != VERSION:
            raise ProtectionError('schema_error')
        _validate_schema(db)
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok' or db.execute('PRAGMA foreign_key_check').fetchone():
            raise ProtectionError('schema_error')
        states = db.execute('SELECT * FROM state').fetchall()
        if len(states) != 1:
            raise ProtectionError('identity_error')
        state = states[0]
        identity = (self.root / 'identity').read_bytes()
        anchor = Path(str(self.root) + '.identity').read_bytes()
        if (not hex_value(state['id'], 32) or identity != state['id'].encode('ascii') or anchor != identity
                or state['root'] != str(self.root)):
            raise ProtectionError('identity_error')
        if not _valid_clock(load_json(state['checkpoint'])):
            raise ProtectionError('clock_error')
        meta = db.execute('SELECT * FROM contract_meta').fetchall()
        if (len(meta) != 1 or meta[0]['singleton'] != 1 or meta[0]['version'] != VERSION
                or meta[0]['registry_digest'] != self.manifest['registry_digest']
                or not finite(meta[0]['migration_wall']) or not finite(meta[0]['migration_mono'])
                or not meta[0]['migration_boot']):
            raise ProtectionError('schema_error')
        expected = {entry['engine']: entry for entry in self.manifest['registry']}
        actual = db.execute('SELECT * FROM engine_identities').fetchall()
        if len(actual) != len(expected):
            raise ProtectionError('provenance_error')
        for entry in actual:
            approved = expected.get(entry['engine'])
            if approved is None or tuple(entry) != (
                approved['engine'], int(approved['domestic']), approved['module'], approved['capability'],
                approved['source_digest'], canonical_json(approved['profile']),
            ):
                raise ProtectionError('provenance_error')
        aliases = {alias: entry['engine'] for entry in expected.values() for alias in entry['aliases']}
        if dict(db.execute('SELECT alias,engine FROM aliases').fetchall()) != aliases:
            raise ProtectionError('provenance_error')
        for row in db.execute('SELECT * FROM attempts'):
            if (not isinstance(row['dispatch_id'], str) or not 1 <= len(row['dispatch_id']) <= 80
                    or row['domestic'] not in (0, 1) or row['domestic'] != int(expected[row['engine']]['domestic'])
                    or not finite(row['stamp']) or not finite(row['account_mono']) or not row['account_boot']
                    or row['caller'] not in CALLERS or row['phase'] not in PHASES
                    or row['source'] not in ('legacy', 'v2')
                    or (row['outcome'] is not None and row['outcome'] not in OUTCOMES)):
                raise ProtectionError('schema_error')
            for name in ('reserved_mono', 'finished_mono', 'elapsed'):
                if row[name] is not None and not finite(row[name]):
                    raise ProtectionError('schema_error')
            for name in ('connection_attempted', 'http_attempted'):
                if row[name] is not None and (type(row[name]) is not int or row[name] not in (0, 1)):
                    raise ProtectionError('schema_error')
            if row['source'] == 'v2' and row['reserved_mono'] is None:
                raise ProtectionError('schema_error')
        for row in db.execute('SELECT * FROM pauses'):
            if type(row['strikes']) is not int or row['strikes'] < 0 or not finite(row['until']):
                raise ProtectionError('schema_error')
        for row in db.execute('SELECT * FROM recoveries'):
            poison = load_json(row['old_poison_json'])
            if (not _valid_clock(load_json(row['old_checkpoint']))
                    or not isinstance(poison, list) or any(not isinstance(reason, str) for reason in poison)
                    or not _valid_clock({'wall': row['wall'], 'mono': row['mono'], 'boot': row['new_boot']})
                    or row['decision'] not in ('clock_reanchor', 'terminated_sender', 'combined')):
                raise ProtectionError('schema_error')

    def _admit(self, db, now, *, dispatch_id=None, engine=None, deadline=None, persist_clock=True):
        checkpoint = load_json(db.execute('SELECT checkpoint FROM state').fetchone()[0])
        if not _clock_matches(checkpoint, now):
            if persist_clock:
                db.execute('INSERT INTO poison VALUES (?)', ('clock_error',))
                _commit(db, self.root)
            raise ProtectionError('clock_error')
        poison = db.execute('SELECT reason FROM poison ORDER BY rowid LIMIT 1').fetchone()
        if poison:
            raise ProtectionError(poison[0] if poison[0] in REASONS else 'storage_error')
        unfinished = db.execute('SELECT dispatch_id FROM attempts WHERE outcome IS NULL').fetchall()
        if any(row[0] != dispatch_id for row in unfinished):
            raise ProtectionError('unfinished_attempt')
        if deadline is not None and (not finite(deadline) or now['mono'] >= deadline):
            raise ProtectionError('deadline_exceeded')
        if engine is None:
            return
        if engine['profile']['live_hold']:
            raise ProtectionError('operator_hold')
        pause = db.execute('SELECT until FROM pauses WHERE engine=?', (engine['engine'],)).fetchone()
        if pause and now['mono'] < pause[0]:
            raise ProtectionError('cooldown')
        args = (engine['engine'], now['boot'], now['mono'] - 60)
        if (
            db.execute('SELECT count(*) FROM attempts WHERE engine=? AND account_boot=? AND account_mono>?', args)
            .fetchone()[0]
            >= 6
        ):
            raise ProtectionError('engine_rate')
        if engine['domestic'] and db.execute(
            'SELECT count(*) FROM attempts WHERE domestic=1 AND account_boot=? AND account_mono>?',
            (now['boot'], now['mono'] - 60),
        ).fetchone()[0] >= 30:
            raise ProtectionError('domestic_rate')

    def check_admission(self):
        """Read-only service admission, not an engine permit or supply proof."""
        try:
            with self._locked(readonly=True) as db:
                self._admit(db, _clock(), persist_clock=False)
            return None
        except ProtectionError as error:
            return Refusal(error.reason)
        except FileNotFoundError:
            return Refusal('identity_error')
        except (OSError, sqlite3.Error):
            return Refusal('storage_error')
        except (ValueError, TypeError, KeyError):
            return Refusal('schema_error')

    @staticmethod
    def _execute_engine(context, build, send, parse):
        outcome = 'request_refused'
        results = None
        result_count = None
        suspension_s = 0
        try:
            context.phase = 'build'
            request = build()
            context.check_deadline()
            outcome = 'error'
            context.phase = 'send'
            response = send(context, request)
            context.check_deadline()
            outcome = 'parser_error'
            context.phase = 'parse'
            results = parse(response)
            context.check_deadline()
            result_count = len(results) if results is not None else 0
            outcome = 'ok' if result_count else 'empty'
        except EngineFailure as error:
            outcome = error.outcome
            suspension_s = error.suspension_s
        except ProtectionError as error:
            if error.reason not in ('deadline_exceeded', 'capability_refused'):
                context.finish_unfinished()
                raise
            outcome = {'deadline_exceeded': 'timeout', 'capability_refused': 'runtime_error'}[error.reason]
        except (OSError, sqlite3.Error):
            # Storage errors from send-adjacent reservations must not be treated
            # as ordinary callback failures and then finalized as completed rows.
            context.finish_unfinished()
            raise
        except Exception:  # callbacks may contain private request/response data
            pass
        return outcome, results, result_count, suspension_s

    def _finish_engine(
        self, db, context, entry, started, deadline_mono, observer, outcome, results, result_count, suspension_s
    ):
        if os.getpid() != self.pid:
            raise ProtectionError('capability_refused')
        finished = _clock()
        if not _clock_matches(started, finished):
            db.execute('INSERT INTO poison VALUES (?)', ('clock_error',))
            _commit(db, self.root)
            return Refusal('clock_error')
        if context.unfinished or (observer is not None and (
                observer.cancelled or (observer.cancellation_requested and finished['mono'] >= deadline_mono))):
            return context.finish_unfinished()
        db.execute(
            'UPDATE attempts SET outcome=?,stamp=?,finished_mono=?,account_boot=?,account_mono=?,elapsed=? '
            'WHERE dispatch_id=?',
            (outcome, finished['mono'], finished['mono'], finished['boot'], finished['mono'],
             finished['mono'] - started['mono'], context.dispatch_id),
        )
        if outcome in ('captcha', 'access_denied', 'rate_limited', 'challenge_unknown'):
            previous = db.execute('SELECT strikes,until FROM pauses WHERE engine=?', (entry['engine'],)).fetchone()
            strikes = (previous['strikes'] if previous else 0) + 1
            until = max(previous['until'] if previous else 0,
                        finished['mono'] + max(suspension_s, 1800 * 2 ** min(strikes - 1, 16)))
            db.execute('INSERT OR REPLACE INTO pauses VALUES (?,?,?)', (entry['engine'], strikes, until))
        elif outcome == 'ok' and result_count:
            db.execute('DELETE FROM pauses WHERE engine=?', (entry['engine'],))
        db.execute('UPDATE state SET checkpoint=?', (canonical_json(finished),))
        _commit(db, self.root, completion=True)
        result = EngineOutcome(
            entry['engine'], outcome, len(context.rows), context.connections, context.headers,
            result_count, finished['mono'] - started['mono'], finished['mono'] >= deadline_mono, results,
        )
        if observer is not None:
            if not observer._publish(result, completion_marker=self.root / _COMPLETION_PENDING):
                # Keep the marker until cancellation accounting is also durable.
                unfinished = context.finish_unfinished()
                (self.root / _COMPLETION_PENDING).unlink()
                return unfinished
        else:
            # No removal fsync is needed for safety: a crash either restores the
            # conservative marker or leaves the already-durable final outcome.
            (self.root / _COMPLETION_PENDING).unlink()
        return result

    def run_engine(self, engine_name, *, caller, deadline_mono, build, send, parse, observer=None):
        if observer is not None:
            if not isinstance(observer, DispatchNotification):
                return Refusal('capability_refused')
            try:
                observer._bind()
            except ProtectionError as error:
                return Refusal(error.reason)
        if caller not in CALLERS or caller == 'legacy_probe':
            return Refusal('capability_refused')
        context = None
        token = None
        try:
            with self._locked() as db:
                canonical = db.execute('SELECT engine FROM aliases WHERE alias=?', (engine_name,)).fetchone()
                if canonical is None:
                    return Refusal('capability_refused')
                entry = next(entry for entry in self.manifest['registry'] if entry['engine'] == canonical[0])
                now = _clock()
                self._admit(db, now, engine=entry, deadline=deadline_mono)
                context = Dispatch(self, db, entry, caller, deadline_mono, now, observer)
                context.reserve('engine_http')
                token = CURRENT_DISPATCH.set(context)
                outcome, results, result_count, suspension_s = self._execute_engine(context, build, send, parse)
                return self._finish_engine(
                    db, context, entry, now, deadline_mono, observer,
                    outcome, results, result_count, suspension_s,
                )
        except ProtectionError as error:
            return Refusal(error.reason)
        except (OSError, sqlite3.Error):
            return Refusal('storage_error')
        except (ValueError, TypeError, KeyError, StopIteration):
            return Refusal('schema_error')
        finally:
            if context is not None:
                context.active = False
            if token is not None:
                CURRENT_DISPATCH.reset(token)

    def _release_fingerprint(self, release_id, artifact_digest, config_digest):
        if (not hex_value(release_id, 32) or artifact_digest != self.manifest['artifact_digest']
                or config_digest != self.manifest['config_digest']):
            raise ProtectionError('release_consumed')

    def _release_row(self, db, release_id, artifact_digest, config_digest, now):
        self._release_fingerprint(release_id, artifact_digest, config_digest)
        self._admit(db, now)
        row = db.execute('SELECT * FROM release_checks WHERE release_id=?', (release_id,)).fetchone()
        if (row is None or row['artifact_digest'] != artifact_digest or row['config_digest'] != config_digest
                or row['boot'] != now['boot'] or now['mono'] >= row['deadline_mono']):
            raise ProtectionError('release_consumed')
        return row

    def claim_release(self, release_id, artifact_digest, config_digest, deadline_mono):
        try:
            with self._locked() as db:
                now = _clock()
                self._release_fingerprint(release_id, artifact_digest, config_digest)
                self._admit(db, now)
                if not finite(deadline_mono) or not now['mono'] < deadline_mono <= now['mono'] + 10:
                    return Refusal('deadline_exceeded')
                if db.execute('SELECT 1 FROM release_checks WHERE release_id=?', (release_id,)).fetchone():
                    return Refusal('release_consumed')
                db.execute(
                    'INSERT INTO release_checks VALUES (?,?,?,?,?,?,?,0,NULL,NULL)',
                    (release_id, artifact_digest, config_digest, now['boot'], now['mono'], deadline_mono, 'claimed'),
                )
                db.execute('UPDATE state SET checkpoint=?', (canonical_json(now),))
                _commit(db, self.root)
                return ReleaseReceipt(self, release_id, artifact_digest, config_digest)
        except ProtectionError as error:
            return Refusal(error.reason)
        except (OSError, sqlite3.Error):
            return Refusal('storage_error')
        except (ValueError, TypeError, KeyError):
            return Refusal('schema_error')

    def consume_release_ingress(self, release_id, artifact_digest, config_digest):
        try:
            with self._locked() as db:
                now = _clock()
                row = self._release_row(db, release_id, artifact_digest, config_digest, now)
                if row['state'] != 'unknown' or row['ingress_used'] != 0:
                    return Refusal('release_consumed')
                db.execute('UPDATE release_checks SET ingress_used=1 WHERE release_id=?', (release_id,))
                db.execute('UPDATE state SET checkpoint=?', (canonical_json(now),))
                _commit(db, self.root)
                return True
        except ProtectionError as error:
            return Refusal(error.reason)
        except (OSError, sqlite3.Error):
            return Refusal('storage_error')
        except (ValueError, TypeError, KeyError):
            return Refusal('schema_error')

    def run_release_check(self, receipt, operation):
        if (not isinstance(receipt, ReleaseReceipt) or receipt.store is not self or receipt.consumed
                or receipt.pid != os.getpid() or receipt.thread != threading.get_ident()):
            return Refusal('release_consumed')
        receipt.consumed = True
        try:
            with self._locked() as db:
                row = self._release_row(db, receipt.release_id, receipt.artifact, receipt.config, _clock())
                if row['state'] != 'claimed' or row['ingress_used'] != 0:
                    return Refusal('release_consumed')
                db.execute('UPDATE release_checks SET state=? WHERE release_id=?', ('unknown', receipt.release_id))
                _commit(db, self.root)
            # The short claim lock MUST be released before any MCP/native operation.
            try:
                evidence = load_json(canonical_json(operation()))
                validate_evidence(evidence)
            except Exception:
                return Refusal('evidence_unknown')
            with self._locked() as db:
                now = _clock()
                row = self._release_row(db, receipt.release_id, receipt.artifact, receipt.config, now)
                if row['state'] != 'unknown' or row['ingress_used'] != 1 or evidence['age_s'] != 0:
                    return Refusal('evidence_unknown')
                if (evidence['release_id'] != receipt.release_id or evidence['artifact_digest'] != receipt.artifact
                        or evidence['config_digest'] != receipt.config):
                    return Refusal('provenance_error')
                db.execute('UPDATE release_checks SET state=?,finished_mono=?,evidence_json=? WHERE release_id=?',
                           ('complete', now['mono'], canonical_json(evidence), receipt.release_id))
                db.execute('UPDATE state SET checkpoint=?', (canonical_json(now),))
                _commit(db, self.root, completion=True)
                (self.root / _COMPLETION_PENDING).unlink()
                return evidence
        except ProtectionError as error:
            return Refusal(error.reason)
        except (OSError, sqlite3.Error):
            return Refusal('storage_error')
        except (ValueError, TypeError, KeyError):
            return Refusal('schema_error')

    def public_snapshot(self, artifact_digest, config_digest, *, max_age_s=60):
        try:
            with self._locked(readonly=True) as db:
                now = _clock()
                self._admit(db, now, persist_clock=False)
                if (
                    artifact_digest != self.manifest['artifact_digest']
                    or config_digest != self.manifest['config_digest']
                    or not finite(max_age_s)
                    or max_age_s > 60
                ):
                    return Refusal('provenance_error')
                row = db.execute('''SELECT * FROM release_checks WHERE artifact_digest=? AND config_digest=?
                    ORDER BY claimed_mono DESC,rowid DESC LIMIT 1''', (artifact_digest, config_digest)).fetchone()
                if (row is None or row['state'] != 'complete' or row['ingress_used'] != 1
                        or row['boot'] != now['boot'] or row['finished_mono'] is None
                        or not 0 <= now['mono'] - row['finished_mono'] <= max_age_s or row['evidence_json'] is None):
                    return Refusal('evidence_unknown')
                evidence = validate_evidence(load_json(row['evidence_json']))
                if (evidence['release_id'] != row['release_id'] or evidence['artifact_digest'] != artifact_digest
                        or evidence['config_digest'] != config_digest):
                    return Refusal('provenance_error')
                evidence['age_s'] = now['mono'] - row['finished_mono']
                return evidence
        except ProtectionError as error:
            return Refusal(error.reason)
        except (OSError, sqlite3.Error):
            return Refusal('storage_error')
        except (ValueError, TypeError, KeyError):
            return Refusal('schema_error')


class ReleaseReceipt:
    """Only the claiming stack can consume this ephemeral execution receipt."""

    def __init__(self, store, release_id, artifact, config):
        self.store = store
        self.release_id = release_id
        self.artifact = artifact
        self.config = config
        self.pid = os.getpid()
        self.thread = threading.get_ident()
        self.consumed = False


class Dispatch:
    """Internal, stack-scoped adapter context; never a reusable admission token."""

    def __init__(self, store, db, entry, caller, deadline, started, observer=None):
        self.observer = observer
        self.store = store
        self.db = db
        self.entry = entry
        self.caller = caller
        self.deadline = deadline
        self.started = started
        self.pid = os.getpid()
        self.owner_thread = threading.get_ident()
        self.async_thread = None
        self.async_task = None
        self.dispatch_id = secrets.token_hex(16)
        self.rows = []
        self.active = True
        self.unfinished = False
        self.phase = 'reserve'
        self.connections = 0
        self.headers = 0
        self.main_calls = 0
        self.armed_row = None
        self.proxy_connect = False

    def check_deadline(self):
        if (not self.active or self.pid != os.getpid() or CURRENT_DISPATCH.get() is not self
                or threading.get_ident() not in (self.owner_thread, self.async_thread)):
            raise ProtectionError('capability_refused')
        if threading.get_ident() == self.async_thread:
            import asyncio  # imported only at the explicit bridge, not package import

            if asyncio.current_task() is not self.async_task:
                raise ProtectionError('capability_refused')
        if (self.observer is not None and self.observer.cancelled) or time.monotonic() >= self.deadline:
            if self.observer is not None:
                self.unfinished = True
            raise ProtectionError('deadline_exceeded')
        if self.observer is not None and self.observer.cancellation_requested:
            raise EngineFailure('cancelled')

    def finish_unfinished(self):
        if threading.get_ident() != self.owner_thread or os.getpid() != self.pid:
            raise ProtectionError('capability_refused')
        self.unfinished = True
        self.db.execute('UPDATE attempts SET outcome=NULL,finished_mono=NULL,elapsed=NULL WHERE dispatch_id=?',
                        (self.dispatch_id,))
        self.db.execute('INSERT INTO poison VALUES (?)', ('unfinished_attempt',))
        _commit(self.db, self.store.root)
        result = Refusal('unfinished_attempt')
        if self.observer is not None:
            self.observer._publish(result, unfinished=True)
        return result

    def run_async(self, operation, loop):
        """Bind this one dispatch explicitly while the flock-owning thread waits."""
        self.check_deadline()
        if (threading.get_ident() != self.owner_thread or self.phase != 'send'
                or self.async_thread is not None or loop is None):
            raise ProtectionError('capability_refused')
        stopped = threading.Event()
        async def execute():
            import asyncio

            token = CURRENT_DISPATCH.set(self)
            self.async_thread = threading.get_ident()
            self.async_task = asyncio.current_task()
            try:
                self.check_deadline()
                return await operation()
            finally:
                self.async_task = None
                self.async_thread = None
                CURRENT_DISPATCH.reset(token)
        future = concurrent.futures.Future()
        task = None
        def completed(done):
            try:
                if not future.done():
                    if done.cancelled():
                        future.set_exception(EngineFailure('cancelled'))
                    elif done.exception() is not None:
                        future.set_exception(done.exception())
                    else:
                        future.set_result(done.result())
            finally:
                stopped.set()
        def begin():
            nonlocal task
            if self.unfinished:
                stopped.set()
                return
            task = loop.create_task(execute())
            task.add_done_callback(completed)
        def cancel():
            if task is not None:
                task.cancel()
            else:
                stopped.set()
        loop.call_soon_threadsafe(begin)
        cancellation_sent = False
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                self.unfinished = True
                if not cancellation_sent:
                    loop.call_soon_threadsafe(cancel)
                # Only the task completion callback proves stop. An uncooperative
                # sender keeps the owning worker's flock until it actually exits.
                stopped.wait()
                raise EngineFailure('timeout') from None
            if (self.observer is not None and (
                    self.observer.cancellation_requested or self.observer.cancelled)) and not cancellation_sent:
                loop.call_soon_threadsafe(cancel)
                cancellation_sent = True
            try:
                return future.result(min(remaining, 0.02) if self.observer is not None else remaining)
            except concurrent.futures.TimeoutError:
                continue

    def reserve(self, phase):
        now = _clock()
        self.db.execute('BEGIN IMMEDIATE')
        self.store._admit(self.db, now, dispatch_id=self.dispatch_id, engine=self.entry, deadline=self.deadline)
        row = self.db.execute('''INSERT INTO attempts
            (dispatch_id,engine,domestic,stamp,outcome,reserved_mono,finished_mono,account_boot,account_mono,
             caller,phase,connection_attempted,http_attempted,elapsed,source)
            VALUES (?,?,?,?,NULL,?,NULL,?,?,?,?,0,0,NULL,'v2')''',
                              (self.dispatch_id, self.entry['engine'], int(self.entry['domestic']), now['mono'],
                               now['mono'], now['boot'], now['mono'], self.caller, phase))
        self.rows.append(row.lastrowid)
        self.db.execute('UPDATE state SET checkpoint=?', (canonical_json(now),))
        _commit(self.db, self.store.root)
        if self.observer is not None:
            self.observer._record_reservation()


def _freeze_manifest(value: object) -> object:
    if type(value) is dict:
        mapping = cast(dict[str, object], value)
        return MappingProxyType({key: _freeze_manifest(item) for key, item in mapping.items()})
    if type(value) is list:
        return tuple(_freeze_manifest(item) for item in cast(list[object], value))
    return value


def _recovery_files(store):
    paths = ((store.root, True), (store.root / 'lock', False), (store.root / 'identity', False),
             (Path(str(store.root) + '.identity'), False), (store.root / 'ledger.sqlite', False))
    return tuple((info.st_dev, info.st_ino) for path, directory in paths
                 for info in (_secure(path, store.manifest, directory),))


def _recovery_snapshot(db):
    return canonical_json({name: [tuple(row) for row in db.execute(f'SELECT rowid,* FROM {name} ORDER BY rowid')]
                           for name in sorted(TABLES)})


# Fixed, cooperative fixture sender: no caller code, network, descendants or
# work transfer. The startup pipe is released only after parent birth/pidfd registration.
_SYNTHETIC_SENDER = '''
import json
import os
import sys
import time
def denied(event, args):
    if event.startswith('socket.') or event in ('os.fork', 'os.forkpty', 'subprocess.Popen'):
        raise RuntimeError('synthetic sender forbids network and descendants')
sys.addaudithook(denied)
value = json.loads(sys.stdin.readline())
sys.path.insert(0, value['manifest']['module_root'])
import wag_protection
from wag_protection.ledger import CURRENT_DISPATCH
time.time = lambda: value['clock']['wall']
time.monotonic = lambda: value['clock']['mono']
registered = {'attempt_ids': [], 'dispatch_id': None}
if value['engine'] is not None:
    store = wag_protection.open_store(value['root'], manifest=value['manifest'], mode='synthetic')
    if isinstance(store, wag_protection.Refusal):
        sys.exit(2)
    def interrupted_build():
        context = CURRENT_DISPATCH.get()
        registered.update(attempt_ids=context.rows, dispatch_id=context.dispatch_id)
        raise SystemExit(0)
    try:
        store.run_engine(value['engine'], caller='probe', deadline_mono=value['clock']['mono'] + 3,
                         build=interrupted_build, send=None, parse=None)
    except SystemExit:
        pass
print(json.dumps(registered), flush=True)
os.read(0, 1)
os._exit(0)
'''


class _SyntheticMaintenanceSession:
    """Private disposable fixture owner, not a production sender-set witness."""

    def __init__(self, root, *, manifest, authorization, decision):
        if (not recovery_authorization(authorization) or type(decision) is not str
                or decision not in RECOVERY_DECISIONS):
            raise ProtectionError('capability_refused')
        root = canonical_path(root)
        temporary_root = canonical_path(tempfile.gettempdir())
        if root == temporary_root or temporary_root not in root.parents:
            raise ProtectionError('evidence_unknown')
        approved = validate_manifest(manifest, root, 'synthetic')
        self._manifest_json = canonical_json(approved)
        self._manifest = _freeze_manifest(approved)
        self._store = Store(root, approved, 'synthetic')
        self._pid = os.getpid()
        self._thread = threading.get_ident()
        self._authorization = authorization
        self._decision = decision
        self._issued = _clock()
        if not _valid_clock(self._issued) or len(self._issued['boot'].encode('utf-8')) > 128:
            raise ProtectionError('clock_error')
        self._records: list[SenderRecord] = []
        self._proof = None
        self._capability = None
        self._used = False
        self._closed = False
        with self._store._locked(readonly=True) as db:
            self._files = _recovery_files(self._store)
            self._identity = db.execute('SELECT id FROM state').fetchone()[0]

    def _check_owner(self):
        if (type(self) is not _SyntheticMaintenanceSession or self._pid != os.getpid()
                or self._thread != threading.get_ident() or self._closed):
            raise ProtectionError('capability_refused')

    def __enter__(self):
        self._check_owner()
        return self

    def __exit__(self, *unused):
        self.close()

    def start_sender(self, engine=None):
        self._check_owner()
        if self._proof is not None or len(self._records) >= 64:
            raise ProtectionError('capability_refused')
        if engine is not None and (type(engine) is not str or engine not in {
                entry['engine'] for entry in self._store.manifest['registry']}):
            raise ProtectionError('capability_refused')
        if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
            raise ProtectionError('evidence_unknown')
        with self._store._locked(readonly=True) as db:
            previous = [dict(row) for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')]
        process = subprocess.Popen([sys.executable, '-I', '-S', '-c', _SYNTHETIC_SENDER],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, close_fds=True)
        record: SenderRecord = {'process': process, 'pidfd': None, 'binding': None, 'reaped': False}
        self._records.append(record)
        try:
            if process.stdin is None or process.stdout is None:
                raise ProtectionError('evidence_unknown')
            record['pidfd'] = os.pidfd_open(process.pid, 0)
            birth = Path(f'/proc/{process.pid}/stat').read_text(encoding='ascii').rsplit(')', 1)[1].split()
            if int(birth[1]) != self._pid:
                raise ProtectionError('evidence_unknown')
            start_ticks = int(birth[19])
            process.stdin.write(
                canonical_json({
                    'root': str(self._store.root),
                    'manifest': load_json(self._manifest_json),
                    'engine': engine,
                    'clock': _clock(),
                })
                + '\n'
            )
            process.stdin.flush()
            if not select.select([process.stdout], [], [], 5)[0]:
                raise ProtectionError('evidence_unknown')
            message = load_json(process.stdout.readline())
            with self._store._locked(readonly=True) as db:
                rows = [dict(row) for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')]
            if rows[:len(previous)] != previous:
                raise ProtectionError('evidence_unknown')
            added = rows[len(previous):]
            if engine is None:
                valid = not added and message == {'attempt_ids': [], 'dispatch_id': None}
            else:
                valid = (len(added) == 1 and added[0]['engine'] == engine and added[0]['source'] == 'v2'
                         and added[0]['caller'] == 'probe' and added[0]['outcome'] is None
                         and added[0]['dispatch_id'] == message.get('dispatch_id')
                         and message.get('attempt_ids') == [added[0]['attempt_id']])
            if not valid:
                raise ProtectionError('evidence_unknown')
            binding = SenderBinding(process.pid, start_ticks, self._issued['boot'],
                                    tuple(row['attempt_id'] for row in added), _MAINTENANCE_TOKEN)
            record['binding'] = binding
            return binding
        except (OSError, ValueError, TypeError, KeyError):
            raise ProtectionError('evidence_unknown') from None

    def stop_sender(self, binding):
        self._check_owner()
        record = next((item for item in self._records if item['binding'] is binding), None)
        if type(binding) is not SenderBinding or record is None or record['reaped']:
            raise ProtectionError('capability_refused')
        process = record['process']
        stdin = process.stdin
        if stdin is None:
            raise AttributeError("'NoneType' object has no attribute 'write'")
        stdin.write('x')
        stdin.flush()
        pidfd = record['pidfd']
        if pidfd is None:
            raise TypeError('argument must be an int, or have a fileno() method.')
        if not select.select([pidfd], [], [], 5)[0]:
            raise ProtectionError('evidence_unknown')
        pid, status = os.waitpid(binding.pid, 0)
        if pid != binding.pid or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise ProtectionError('evidence_unknown')
        record['reaped'] = True
        process.returncode = os.waitstatus_to_exitcode(status)

    def seal(self, *, clear_poison=()):
        self._check_owner()
        if self._proof is not None or not self._records:
            raise ProtectionError('evidence_unknown')
        registered: list[SenderBinding] = []
        for item in self._records:
            binding = item['binding']
            if binding is None:
                raise ProtectionError('evidence_unknown')
            registered.append(binding)
        if (type(clear_poison) is not tuple or len(clear_poison) > 64
                or any(type(item) is not PoisonSelection for item in clear_poison)
                or len({item.rowid for item in clear_poison}) != len(clear_poison)):
            raise ProtectionError('capability_refused')
        bindings = tuple(registered)
        ids = tuple(attempt_id for binding in bindings for attempt_id in binding.attempt_ids)
        with self._store._locked(readonly=True) as db:
            unknown = tuple(
                row[0]
                for row in db.execute('SELECT attempt_id FROM attempts WHERE outcome IS NULL ORDER BY attempt_id')
            )
            if len(ids) > 64 or len(ids) != len(set(ids)) or tuple(sorted(ids)) != unknown:
                raise ProtectionError('evidence_unknown')
            if self._files != _recovery_files(self._store):
                raise ProtectionError('identity_error')
            self._snapshot = _recovery_snapshot(db)
        capability = MaintenanceCapability(self._authorization, self._decision, self._store.root,
                                           self._issued['boot'], self._issued['mono'], self._issued['mono'] + 300,
                                           clear_poison, _MAINTENANCE_TOKEN)
        self._capability = capability
        self._proof = RecoveryProofV1(1, capability, self._manifest, bindings, self)
        return self._proof

    def close(self):
        self._check_owner()
        for record in self._records:
            process, fd = record['process'], record['pidfd']
            if not record['reaped']:
                if fd is not None:
                    if not select.select([fd], [], [], 0)[0]:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    _, status = os.waitpid(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                else:
                    process.kill()
                    process.wait(timeout=5)
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is None:
                    raise AttributeError("'NoneType' object has no attribute 'close'")
                pipe.close()
            if fd is not None:
                os.close(fd)
        self._closed = True


def _recovery_witness(root, authorization, decision, proof):
    if type(proof) is not RecoveryProofV1 or type(proof._witness) is not _SyntheticMaintenanceSession:
        raise ProtectionError('capability_refused')
    session = proof._witness
    _SyntheticMaintenanceSession._check_owner(session)
    capability = proof.capability
    if (session._proof is not proof or type(capability) is not MaintenanceCapability
            or session._capability is not capability or session._used or capability._issuance is not _MAINTENANCE_TOKEN
            or type(proof.version) is not int or proof.version != 1
            or authorization != capability.authorization or decision != capability.decision):
        raise ProtectionError('capability_refused')
    if root != capability.root:
        raise ProtectionError('identity_error')
    if proof.approved_manifest is not session._manifest:
        raise ProtectionError('provenance_error')
    now = _clock()
    if (not _valid_clock(now) or now['boot'] != capability.boot
            or not capability.issued_mono <= now['mono'] < capability.deadline_mono):
        raise ProtectionError('evidence_unknown')
    if (type(proof.sender_bindings) is not tuple or not 1 <= len(proof.sender_bindings) <= 64
            or len(proof.sender_bindings) != len(session._records)):
        raise ProtectionError('evidence_unknown')
    for binding, record in zip(proof.sender_bindings, session._records):
        if (
            type(binding) is not SenderBinding
            or record['binding'] is not binding
            or binding._issuance is not _MAINTENANCE_TOKEN
            or binding.boot != now['boot']
            or not record['reaped']
            or record['pidfd'] is None
                or not select.select([record['pidfd']], [], [], 0)[0]):
            raise ProtectionError('evidence_unknown')
    approved = validate_manifest(load_json(session._manifest_json), root, 'synthetic')
    store = Store(root, approved, 'synthetic')
    if _recovery_files(store) != session._files:
        raise ProtectionError('identity_error')
    return session, store, now


def recover(root, *, authorization, decision, proof) -> RecoveryResult | Refusal:
    """Audited synthetic-only maintenance. Never returns a sending permit."""
    if (not recovery_authorization(authorization) or type(decision) is not str
            or decision not in RECOVERY_DECISIONS):
        return Refusal('capability_refused')
    try:
        root = canonical_path(root)
        # No production sender-set witness is approved. Do not open live state.
        if root == PRODUCTION_ROOT or PRODUCTION_ROOT in root.parents:
            return Refusal('evidence_unknown')
        session, store, now = _recovery_witness(root, authorization, decision, proof)
        with store._locked() as db:
            db.execute('BEGIN IMMEDIATE')
            session, _, now = _recovery_witness(root, authorization, decision, proof)
            if (db.execute('SELECT id FROM state').fetchone()[0] != session._identity
                    or _recovery_snapshot(db) != session._snapshot):
                raise ProtectionError('evidence_unknown')
            if db.execute('SELECT 1 FROM recoveries WHERE authorization=?', (authorization,)).fetchone():
                raise ProtectionError('capability_refused')
            old_checkpoint = db.execute('SELECT checkpoint FROM state').fetchone()[0]
            checkpoint = load_json(old_checkpoint)
            attempts = [dict(row) for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')]
            unfinished = [row for row in attempts if row['outcome'] is None]
            ids = sorted(attempt_id for binding in proof.sender_bindings for attempt_id in binding.attempt_ids)
            if ids != [row['attempt_id'] for row in unfinished]:
                raise ProtectionError('evidence_unknown')
            if decision == 'clock_reanchor' and unfinished:
                raise ProtectionError('evidence_unknown')
            if decision == 'terminated_sender' and not _clock_matches(checkpoint, now):
                raise ProtectionError('clock_error')
            reanchor = decision in ('clock_reanchor', 'combined')
            changed = attempts if reanchor else unfinished
            poison = [tuple(row) for row in db.execute('SELECT rowid,reason FROM poison ORDER BY rowid')]
            for selection in proof.capability.clear_poison:
                if ((selection.rowid, selection.reason) not in poison
                        or (selection.reason == 'clock_error' and not reanchor)
                        or (selection.reason == 'unfinished_attempt' and not unfinished)):
                    raise ProtectionError('evidence_unknown')
            old_pauses = {row['engine']: (row['strikes'], row['until']) for row in db.execute('SELECT * FROM pauses')}
            affected = {row['engine'] for row in unfinished}
            pause_plan = {}
            for engine in sorted(set(old_pauses) | affected if reanchor else affected):
                strikes, until = old_pauses.get(engine, (0, checkpoint['mono']))
                strikes += int(engine in affected)
                remaining = max(until - checkpoint['mono'], 1800 * 2 ** min(max(strikes - 1, 0), 16), 0)
                new_until = now['mono'] + remaining
                if not finite(new_until):
                    raise ProtectionError('clock_error')
                pause_plan[engine] = (strikes, new_until)
            audit_rows = [(row['attempt_id'], canonical_json(row)) for row in changed]
            if any(len(text.encode('utf-8')) > 8192 for _, text in audit_rows):
                raise ProtectionError('schema_error')
            # Consume before the first write: commit uncertainty must not permit
            # replay, even when SQLite committed but the following fsync failed.
            session._used = True
            recovery_id = db.execute('INSERT INTO recoveries '
                '(authorization,old_checkpoint,old_poison_json,new_boot,wall,mono,decision) VALUES (?,?,?,?,?,?,?)',
                (authorization, old_checkpoint, canonical_json([reason for _, reason in poison]),
                 now['boot'], now['wall'], now['mono'], decision)).lastrowid
            if recovery_id is None:
                raise sqlite3.OperationalError('recovery row was not assigned an id')
            db.executemany('INSERT INTO recovery_attempts VALUES (?,?,?)',
                           [(recovery_id, attempt_id, text) for attempt_id, text in audit_rows])
            db.executemany('INSERT INTO recovery_pauses VALUES (?,?,?,?)',
                           [(recovery_id, engine, *old_pauses.get(engine, (None, None))) for engine in pause_plan])
            for row in changed:
                if reanchor or row['outcome'] is None:
                    db.execute('UPDATE attempts SET account_boot=?,account_mono=? WHERE attempt_id=?',
                               (now['boot'], now['mono'], row['attempt_id']))
                if row['outcome'] is None:
                    db.execute(
                        'UPDATE attempts SET outcome=? WHERE attempt_id=?',
                        ('unknown_terminated', row['attempt_id']),
                    )
            for engine, (strikes, until) in pause_plan.items():
                db.execute('INSERT OR REPLACE INTO pauses VALUES (?,?,?)', (engine, strikes, until))
            db.execute('UPDATE state SET checkpoint=?', (canonical_json(now),))
            for selection in proof.capability.clear_poison:
                db.execute('DELETE FROM poison WHERE rowid=? AND reason=?', (selection.rowid, selection.reason))
            _commit(db, root, completion=True)
            (root / _COMPLETION_PENDING).unlink()
            return RecoveryResult(recovery_id, decision, len(unfinished), len(attempts) if reanchor else 0)
    except ProtectionError as error:
        return Refusal(error.reason)
    except FileNotFoundError:
        return Refusal('identity_error')
    except (OSError, sqlite3.Error):
        return Refusal('storage_error')
    except (ValueError, TypeError, KeyError, PackageNotFoundError):
        return Refusal('provenance_error')


def migrate_legacy(root, *, manifest, authorization) -> Store | Refusal:
    """Offline maintenance; the caller must stop all cooperative senders first.

    Authorization is a nonsecret operation reference (1..256 UTF-8 bytes,
    no control characters), not a live-search permit or sender-stop proof.
    """
    try:
        if (not isinstance(authorization, str) or not 1 <= len(authorization.encode('utf-8')) <= 256
                or not authorization.strip() or any(not char.isprintable() for char in authorization)):
            return Refusal('capability_refused')
    except UnicodeError:
        return Refusal('capability_refused')
    try:
        root = canonical_path(root)
        if not isinstance(manifest, dict):
            path = canonical_path(manifest)
            if not path.is_file() or path.stat().st_size > 131072:
                raise ValueError('invalid manifest file')
            manifest = load_json(path.read_text(encoding='utf-8'))
        if not isinstance(manifest, dict):
            raise ValueError('invalid manifest')
        approved = validate_manifest(manifest, root, manifest.get('mode'))
    except (OSError, ValueError, TypeError, KeyError, PackageNotFoundError):
        return Refusal('provenance_error')
    try:
        store = Store(root, approved, approved['mode'])
        with store._locked(migration=True) as db:
            if db.execute('PRAGMA user_version').fetchone()[0] == VERSION:
                return store
            now = _clock()
            if not _valid_clock(now):
                raise ProtectionError('clock_error')
            checkpoint = load_json(db.execute('SELECT checkpoint FROM state').fetchone()[0])
            for name in sorted(LEGACY_TABLES):
                db.execute(f'ALTER TABLE {name} RENAME TO migration_{name}')
            # executescript would implicitly commit the renames. Execute the
            # fixed statements individually within the original transaction.
            for statement in SCHEMA.split(';'):
                if statement.strip():
                    db.execute(statement)
            _insert_registry(db, approved['registry'])
            db.execute('INSERT INTO state SELECT id,root,checkpoint FROM migration_state')
            db.execute('INSERT INTO contract_meta VALUES (1,2,?,?,?,?)',
                       (approved['registry_digest'], now['wall'], now['mono'], now['boot']))
            db.execute('''INSERT INTO attempts SELECT
                rowid,'legacy:' || rowid,engine,domestic,stamp,outcome,NULL,
                CASE WHEN outcome IS NOT NULL THEN stamp ELSE NULL END,?,stamp,
                'legacy_probe','legacy',NULL,NULL,NULL,'legacy'
                FROM migration_attempts ORDER BY rowid''', (checkpoint['boot'],))
            db.execute('INSERT INTO pauses SELECT engine,strikes,until FROM migration_pauses')
            db.execute('INSERT INTO poison SELECT reason FROM migration_poison ORDER BY rowid')
            for name in sorted(LEGACY_TABLES):
                db.execute(f'DROP TABLE migration_{name}')
            store._validate(db)
            _commit(db, root)
        return store
    except ProtectionError as error:
        return Refusal(error.reason)
    except FileNotFoundError:
        return Refusal('identity_error')
    except (OSError, sqlite3.Error):
        return Refusal('storage_error')
    except (ValueError, TypeError, KeyError):
        return Refusal('schema_error')


def open_store(root, *, manifest, mode, readonly=False) -> Store | Refusal:
    try:
        root = canonical_path(root)
        approved = validate_manifest(manifest, root, mode)
    except (OSError, ValueError, TypeError, KeyError, PackageNotFoundError):
        return Refusal('provenance_error')
    try:
        store = Store(root, approved, mode)
        with store._locked(readonly=readonly):
            pass
        return store
    except ProtectionError as error:
        return Refusal(error.reason)
    except FileNotFoundError:
        return Refusal('identity_error')
    except (OSError, sqlite3.Error):
        return Refusal('storage_error')
    except (ValueError, TypeError, KeyError):
        return Refusal('schema_error')
