# SPDX-License-Identifier: AGPL-3.0-or-later
# Match the repository test convention without renaming externally selected test IDs.
# pylint: disable=missing-class-docstring,invalid-name
# Lazy imports keep native settings/network side effects inside prepared fixtures.
# pylint: disable=import-outside-toplevel
# Keep the public-contract gate and its isolated child-process harness in one test module.
# pylint: disable=too-many-lines
"""Offline public-contract tests; no SearXNG imports or production state."""

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
import socket
import sqlite3
from typing import TypedDict
from unittest.mock import patch
import subprocess
import sys
import tempfile
import unittest


WORKSPACE = Path(__file__).resolve().parents[2]


class FixtureClock(TypedDict):
    """Synthetic clock fields, including deliberately invalid numeric samples."""

    wall: float
    mono: float
    boot: str


def _reap_owned_fork(child):
    import select
    import signal

    pidfd = os.pidfd_open(child, 0)
    try:
        if not select.select([pidfd], [], [], 1)[0]:
            os.kill(child, signal.SIGKILL)
            if not select.select([pidfd], [], [], 1)[0]:
                raise TimeoutError('owned fork child did not exit after SIGKILL')
        pid, status = os.waitpid(child, os.WNOHANG)
        if pid != child:
            raise AssertionError('owned fork child was not reaped')
        return pid, status
    finally:
        os.close(pidfd)


class ImportTest(unittest.TestCase):
    def test_import_has_no_settings_network_or_storage_side_effects(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as root:
            script = '''
import importlib.abc
import pathlib
import socket
import sys
class NoSearx(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'searx' or fullname.startswith('searx.'):
            raise AssertionError('core imported SearXNG')
sys.meta_path.insert(0, NoSearx())
def denied(*args, **kwargs):
    raise AssertionError('core attempted network')
socket.socket = denied
import wag_protection
assert wag_protection.CONTRACT == 'wag.outbound.v2'
assert wag_protection.VERSION == 2
assert not list(pathlib.Path(sys.argv[1]).iterdir())
'''
            env = {**os.environ, 'PYTHONPATH': str(WORKSPACE), 'PYTHONDONTWRITEBYTECODE': '1'}
            child = subprocess.run(
                [sys.executable, '-S', '-c', script, root],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(child.returncode, 0, child.stdout + child.stderr)


class ForkCleanupTest(unittest.TestCase):
    def test_owned_child_cleanup_reaps_normal_and_stalled_forks(self):
        import signal

        for stalled in (False, True):
            with self.subTest(stalled=stalled):
                read_fd, write_fd = os.pipe()
                child = os.fork()
                if child == 0:
                    os.close(write_fd)
                    if stalled:
                        os.read(read_fd, 1)
                    # A fork child must terminate without running inherited Python cleanups.
                    os._exit(0)  # pylint: disable=protected-access
                os.close(read_fd)
                try:
                    pid, status = _reap_owned_fork(child)
                    self.assertEqual(pid, child)
                    self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL if stalled else 0)
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(child, os.WNOHANG)
                finally:
                    os.close(write_fd)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def registry():
    return [
        {
            'engine': name,
            'domestic': domestic,
            'module': module,
            'capability': 'online_one_send',
            'source_digest': hashlib.sha256((WORKSPACE / f'searx/engines/{module}.py').read_bytes()).hexdigest(),
            'aliases': [name],
            'profile': {
                'live_hold': False,
                'settings': {
                    'quark': {'quark_category': 'general'},
                    'yandex': {'search_type': 'web'},
                    'chinaso news': {'chinaso_news_source': 'all'},
                    'bing': {},
                }[name],
            },
        }
        for name, domestic, module in [
            ('bing', False, 'bing'),
            ('chinaso news', True, 'chinaso'),
            ('quark', True, 'quark'),
            ('yandex', False, 'yandex'),
        ]
    ]


def fixture_manifest(root, engines):
    files = {
        str(path.relative_to(WORKSPACE)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [
            *sorted((WORKSPACE / 'wag_protection').glob('*.py')),
            *(WORKSPACE / f'searx/engines/{entry["module"]}.py' for entry in engines),
            WORKSPACE / 'searx/data/engine_traits.json',
            WORKSPACE / 'searx/engines/__init__.py',
            WORKSPACE / 'searx/settings.yml',
            WORKSPACE / 'searx/settings_defaults.py',
            WORKSPACE / 'searx/network/__init__.py',
            WORKSPACE / 'searx/network/client.py',
            WORKSPACE / 'searx/network/network.py',
            WORKSPACE / 'searx/network/protected.py',
            WORKSPACE / 'searx/search/__init__.py',
            WORKSPACE / 'searx/search/processors/abstract.py',
            WORKSPACE / 'searx/search/processors/online.py',
            WORKSPACE / 'searx/settings_loader.py',
            WORKSPACE / 'searx/results.py',
            WORKSPACE / 'searx/webutils.py',
            WORKSPACE / 'searx/webapp.py',
            WORKSPACE / 'searx/exceptions.py',
            WORKSPACE / 'searx/utils.py',
        ]
    }
    python = Path(sys.executable).resolve()
    manifest = {
        'schema': 'wag.protection-artifact.v2',
        'contract': 'wag.outbound.v2',
        'mode': 'synthetic',
        'fork_commit': '9fea41204fdfa7a5cfa15b0ebd12904c520478ce',
        'registry_digest': digest(engines),
        'config_digest': 'a' * 64,
        'python_digest': hashlib.sha256(python.read_bytes()).hexdigest(),
        'module_root': str(WORKSPACE),
        'python_executable': str(python),
        'root': str(root),
        'shared_gid': os.getgid(),
        'allowed_uids': sorted({0, os.getuid()}),
        'files': files,
        'distributions': {},
        'wheels': {},
        'registry': engines,
    }
    manifest['artifact_digest'] = digest(
        {
            key: manifest[key]
            for key in (
                'contract',
                'fork_commit',
                'files',
                'distributions',
                'wheels',
                'registry_digest',
                'python_digest',
            )
        }
    )
    return manifest


# One fixture owns these related migration, recovery and admission contract tests.
class StoreTest(unittest.TestCase):  # pylint: disable=too-many-public-methods
    def setUp(self):
        import wag_protection

        self.api = wag_protection
        # addCleanup owns this directory even if the rest of setUp fails.
        self.parent = tempfile.TemporaryDirectory(  # pylint: disable=consider-using-with
            dir=os.environ['TMPDIR']
        )
        self.addCleanup(self.parent.cleanup)
        self.root = Path(self.parent.name) / 'synthetic-state'
        self.engines = registry()
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='utf-8').strip()
        self.now: FixtureClock = {'wall': 10000.0, 'mono': 100.0, 'boot': self.boot}
        self.wall = patch('time.time', side_effect=lambda: self.now['wall'])
        self.mono = patch('time.monotonic', side_effect=lambda: self.now['mono'])
        self.wall.start()
        self.mono.start()
        self.addCleanup(self.wall.stop)
        self.addCleanup(self.mono.stop)
        self.api.initialize_fixture(self.root, registry=self.engines, clock=lambda: dict(self.now))
        self.manifest = fixture_manifest(self.root, self.engines)

    def open(self):
        return self.api.open_store(self.root, manifest=self.manifest, mode='synthetic')

    def legacy_fixture(self, name='legacy-state', *, unfinished=False, poison=()):
        root = Path(self.parent.name) / name
        root.mkdir(mode=0o700)
        identity = b'1' * 32  # Disposable synthetic token, never a copied live identity.
        for path, data in [
            (root / 'identity', identity),
            (Path(str(root) + '.identity'), identity),
            (root / 'lock', b''),
            (root / 'ledger.sqlite', b''),
        ]:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as file:
                file.write(data)
        checkpoint = json.dumps({'wall': 10000.0, 'mono': 8073000.0, 'boot': self.boot})
        self.now.update(wall=10001.0, mono=8073001.0)
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            # Original probe source lines522–527; no v2 DDL or production copy.
            db.execute('CREATE TABLE state (id TEXT, root TEXT, checkpoint TEXT)')
            db.execute('CREATE TABLE attempts (engine TEXT, domestic INTEGER, stamp REAL, outcome TEXT)')
            db.execute('CREATE TABLE pauses (engine TEXT PRIMARY KEY, strikes INTEGER, until REAL)')
            db.execute('CREATE TABLE poison (reason TEXT)')
            db.execute('INSERT INTO state VALUES (?,?,?)', (identity.decode(), str(root), checkpoint))
            db.executemany(
                'INSERT INTO attempts(rowid,engine,domestic,stamp,outcome) VALUES (?,?,?,?,?)',
                [
                    (7, 'chinaso news', 1, 8072913.0, 'ok'),
                    (19, 'chinaso news', 1, 8072914.25, 'ok'),
                    (41, 'quark', 1, 8072915.728828768, 'captcha'),
                ],
            )
            if unfinished:
                db.execute(
                    'INSERT INTO attempts(rowid,engine,domestic,stamp,outcome) VALUES (53,?,?,?,NULL)',
                    ('bing', 0, 8072999.0),
                )
            db.execute('INSERT INTO pauses VALUES (?,?,?)', ('quark', 1, 8074715.728828768))
            db.executemany('INSERT INTO poison(reason) VALUES (?)', [(reason,) for reason in poison])
        return root, fixture_manifest(root, self.engines), checkpoint

    def test_migration_preserves_original_history_identity_and_is_idempotent(self):
        root, manifest, checkpoint = self.legacy_fixture()
        token = (root / 'identity').read_bytes()
        inode = (root / 'lock').stat().st_ino
        refused = self.api.open_store(root, manifest=manifest, mode='synthetic')
        assert isinstance(refused, self.api.Refusal)
        self.assertEqual(refused.reason, 'schema_error')
        migrated = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:stage6-migration')
        self.assertFalse(isinstance(migrated, self.api.Refusal))
        self.assertTrue((root / 'identity').read_bytes() == token)
        self.assertTrue(Path(str(root) + '.identity').read_bytes() == token)
        self.assertEqual((root / 'lock').stat().st_ino, inode)
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            state = db.execute('SELECT id,root,checkpoint FROM state').fetchone()
            self.assertTrue(state[0].encode() == token)
            self.assertEqual(state[1:], (str(root), checkpoint))
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertEqual(
                db.execute(
                    'SELECT registry_digest,migration_wall,migration_mono,migration_boot FROM contract_meta'
                ).fetchone(),
                (manifest['registry_digest'], 10001.0, 8073001.0, self.boot),
            )
            rows = db.execute(
                'SELECT attempt_id,dispatch_id,engine,domestic,stamp,outcome,reserved_mono,finished_mono,'
                'account_boot,account_mono,caller,phase,connection_attempted,http_attempted,elapsed,source '
                'FROM attempts ORDER BY attempt_id'
            ).fetchall()
            self.assertEqual(
                rows,
                [
                    (
                        7,
                        'legacy:7',
                        'chinaso news',
                        1,
                        8072913.0,
                        'ok',
                        None,
                        8072913.0,
                        self.boot,
                        8072913.0,
                        'legacy_probe',
                        'legacy',
                        None,
                        None,
                        None,
                        'legacy',
                    ),
                    (
                        19,
                        'legacy:19',
                        'chinaso news',
                        1,
                        8072914.25,
                        'ok',
                        None,
                        8072914.25,
                        self.boot,
                        8072914.25,
                        'legacy_probe',
                        'legacy',
                        None,
                        None,
                        None,
                        'legacy',
                    ),
                    (
                        41,
                        'legacy:41',
                        'quark',
                        1,
                        8072915.728828768,
                        'captcha',
                        None,
                        8072915.728828768,
                        self.boot,
                        8072915.728828768,
                        'legacy_probe',
                        'legacy',
                        None,
                        None,
                        None,
                        'legacy',
                    ),
                ],
            )
            self.assertEqual(db.execute('SELECT * FROM pauses').fetchall(), [('quark', 1, 8074715.728828768)])
        original_db = (root / 'ledger.sqlite').read_bytes()
        self.advance(17)
        repeated = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:repeat-validation')
        self.assertFalse(isinstance(repeated, self.api.Refusal))
        assert not isinstance(repeated, self.api.Refusal)
        self.assertTrue((root / 'ledger.sqlite').read_bytes() == original_db, 'v2 repeat rewrote durable state')
        calls = []
        outcome = repeated.run_engine(
            'bing',
            caller='probe',
            deadline_mono=self.now['mono'] + 3,
            build=lambda: calls.append('build'),
            send=lambda context, request: None,
            parse=lambda response: [],
        )
        self.assertEqual((outcome.outcome, calls), ('empty', ['build']))
        refused = repeated.run_engine(
            'quark',
            caller='probe',
            deadline_mono=self.now['mono'] + 3,
            build=lambda: calls.append('quark'),
            send=lambda context, request: None,
            parse=lambda response: [],
        )
        self.assertEqual((refused.reason, calls), ('cooldown', ['build']))

    def test_migration_keeps_null_poison_order_and_old_clock_without_recovery(self):
        for number, poison in enumerate([(), ('clock_error', 'legacy_reason', 'clock_error')]):
            with self.subTest(poison=poison):
                root, manifest, checkpoint = self.legacy_fixture(
                    f'legacy-uncertain-{number}', unfinished=True, poison=poison
                )
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    db.execute('UPDATE poison SET rowid=rowid+100')
                migrated = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:retain-unknown')
                self.assertFalse(isinstance(migrated, self.api.Refusal))
                assert not isinstance(migrated, self.api.Refusal)
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    self.assertEqual(db.execute('SELECT checkpoint FROM state').fetchone()[0], checkpoint)
                    self.assertEqual(
                        db.execute('SELECT reason FROM poison ORDER BY rowid').fetchall(),
                        [(reason,) for reason in poison],
                    )
                    self.assertEqual(
                        db.execute(
                            'SELECT attempt_id,outcome,reserved_mono,finished_mono,account_boot,'
                            'account_mono,connection_attempted,http_attempted,elapsed '
                            'FROM attempts WHERE attempt_id=53'
                        ).fetchone(),
                        (53, None, None, None, self.boot, 8072999.0, None, None, None),
                    )
                calls = []
                result = migrated.run_engine(
                    'bing',
                    caller='probe',
                    deadline_mono=self.now['mono'] + 3,
                    build=lambda calls=calls: calls.append('build'),
                    send=lambda context, request: None,
                    parse=lambda response: [],
                )
                self.assertEqual((result.reason, calls), ('clock_error' if poison else 'unfinished_attempt', []))
        root, manifest, checkpoint = self.legacy_fixture('legacy-old-boot')
        old = json.loads(checkpoint)
        old['boot'] = 'synthetic-old-boot'
        checkpoint = json.dumps(old)
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            db.execute('UPDATE state SET checkpoint=?', (checkpoint,))
        migrated = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:no-reanchor')
        self.assertFalse(isinstance(migrated, self.api.Refusal))
        assert not isinstance(migrated, self.api.Refusal)
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT checkpoint FROM state').fetchone()[0], checkpoint)
            self.assertEqual(
                db.execute('SELECT DISTINCT account_boot FROM attempts').fetchall(), [('synthetic-old-boot',)]
            )
        calls = []
        result = migrated.run_engine(
            'bing',
            caller='probe',
            deadline_mono=self.now['mono'] + 3,
            build=lambda calls=calls: calls.append('build'),
            send=lambda context, request: None,
            parse=lambda response: [],
        )
        self.assertEqual((result.reason, calls), ('clock_error', []))

    def test_migration_rejects_unknown_schema_version_and_illegal_legacy_rows(self):
        mutations = [
            ('CREATE TABLE extra (value TEXT)', 'schema_error'),
            ('CREATE VIEW extra AS SELECT * FROM attempts', 'schema_error'),
            ('CREATE TRIGGER extra AFTER INSERT ON attempts BEGIN DELETE FROM poison; END', 'schema_error'),
            ('CREATE INDEX extra ON attempts(stamp)', 'schema_error'),
            ('ALTER TABLE attempts ADD COLUMN extra TEXT', 'schema_error'),
            ('DROP TABLE poison; CREATE TABLE poison (reason BLOB)', 'schema_error'),
            ('DROP TABLE poison; CREATE TABLE poison (reason TEXT NOT NULL)', 'schema_error'),
            ('PRAGMA user_version=1', 'schema_error'),
            ('PRAGMA user_version=3', 'schema_error'),
            ("UPDATE attempts SET engine='unknown_engine' WHERE rowid=7", 'schema_error'),
            ("UPDATE attempts SET outcome='invented_success' WHERE rowid=7", 'schema_error'),
            ('UPDATE attempts SET domestic=0 WHERE rowid=7', 'schema_error'),
            ('UPDATE attempts SET stamp=1e999 WHERE rowid=7', 'schema_error'),
            ('UPDATE attempts SET stamp=NULL WHERE rowid=7', 'schema_error'),
            ('UPDATE pauses SET strikes=-1', 'schema_error'),
            ('UPDATE pauses SET strikes=1.5', 'schema_error'),
            ('UPDATE pauses SET until=1e999', 'schema_error'),
            ('INSERT INTO poison VALUES (NULL)', 'schema_error'),
            ('INSERT INTO state SELECT * FROM state', 'identity_error'),
            ("UPDATE state SET root='/synthetic/wrong-root'", 'identity_error'),
            ("UPDATE state SET checkpoint='{}'", 'clock_error'),
        ]
        for number, (sql, reason) in enumerate(mutations):
            with self.subTest(sql=sql):
                root, manifest, _ = self.legacy_fixture(f'legacy-refused-{number}')
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    db.executescript(sql)
                before = (root / 'ledger.sqlite').read_bytes()
                result = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:refusal-case')
                self.assertEqual(getattr(result, 'reason', None), reason)
                self.assertTrue((root / 'ledger.sqlite').read_bytes() == before, 'refusal changed legacy DB')

    def test_migration_authorization_manifest_modes_and_registry_digest_fail_closed(self):
        root, manifest, _ = self.legacy_fixture('legacy-authorization')
        before = (root / 'ledger.sqlite').read_bytes()
        for authorization in [None, False, 1, '', ' ', 'x' * 257, 'line\nreference', '\ud800']:
            with self.subTest(authorization_type=type(authorization).__name__):
                result = self.api.migrate_legacy(root, manifest=manifest, authorization=authorization)
                self.assertEqual(getattr(result, 'reason', None), 'capability_refused')
                self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
        for invalid in [
            {**manifest, 'mode': 'production'},
            {**manifest, 'extra': True},
            {**manifest, 'mode': 'unknown'},
        ]:
            result = self.api.migrate_legacy(root, manifest=invalid, authorization='synthetic:invalid-manifest')
            self.assertEqual(getattr(result, 'reason', None), 'provenance_error')
        manifest_path = Path(self.parent.name) / 'synthetic-migration-artifact.json'
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        migrated = self.api.migrate_legacy(root, manifest=manifest_path, authorization='synthetic:path-manifest')
        self.assertFalse(isinstance(migrated, self.api.Refusal))
        before = (root / 'ledger.sqlite').read_bytes()
        amended = json.loads(json.dumps(self.engines))
        amended[0]['profile']['live_hold'] = True
        changed = fixture_manifest(root, amended)
        result = self.api.migrate_legacy(root, manifest=changed, authorization='synthetic:wrong-v2-digest')
        self.assertEqual(getattr(result, 'reason', None), 'schema_error')
        self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)

    def test_migration_never_initializes_missing_or_repairs_corrupt_state(self):
        missing = Path(self.parent.name) / 'missing-legacy'
        manifest = fixture_manifest(missing, self.engines)
        result = self.api.migrate_legacy(missing, manifest=manifest, authorization='synthetic:missing-state')
        self.assertEqual(getattr(result, 'reason', None), 'identity_error')
        self.assertFalse(missing.exists())
        self.assertFalse(Path(str(missing) + '.identity').exists())
        root, manifest, _ = self.legacy_fixture('legacy-wrong-anchor')
        anchor = Path(str(root) + '.identity')
        token = (root / 'identity').read_bytes()
        anchor.write_bytes(b'2' * 32)  # Only this test's newly created synthetic anchor.
        before = (root / 'ledger.sqlite').read_bytes()
        result = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:wrong-anchor')
        self.assertEqual(getattr(result, 'reason', None), 'identity_error')
        self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
        self.assertTrue((root / 'identity').read_bytes() == token)
        self.assertTrue(anchor.read_bytes() == b'2' * 32)
        root, manifest, _ = self.legacy_fixture('legacy-corrupt-db')
        token = (root / 'identity').read_bytes()
        with (root / 'ledger.sqlite').open('r+b') as file:
            file.write(b'synthetic-not-sqlite')
        before = (root / 'ledger.sqlite').read_bytes()
        result = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:corrupt-db')
        self.assertEqual(getattr(result, 'reason', None), 'storage_error')
        self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
        self.assertTrue((root / 'identity').read_bytes() == token)
        self.assertTrue(Path(str(root) + '.identity').read_bytes() == token)

    def test_migration_uses_original_nonblocking_flock_across_processes(self):
        root, manifest, _ = self.legacy_fixture('legacy-locked')
        inode = (root / 'lock').stat().st_ino
        before = (root / 'ledger.sqlite').read_bytes()
        script = '''
import fcntl
import os
import sys
def deny_socket(event, args):
    if event.startswith('socket.'):
        raise AssertionError('maintenance child denied socket operation')
sys.addaudithook(deny_socket)
fd = os.open(sys.argv[1], os.O_RDWR)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
print('locked', flush=True)
os.read(0, 1)
os.close(fd)
'''
        # The finally block explicitly terminates/reaps this fault-injection child and its pipes.
        process = subprocess.Popen(  # pylint: disable=consider-using-with
            [sys.executable, '-S', '-c', script, str(root / 'lock')],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            import select

            assert process.stdout is not None
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'lock owner did not start')
            self.assertEqual(process.stdout.readline().strip(), 'locked')
            result = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:busy-lock')
            self.assertEqual(getattr(result, 'reason', None), 'lock_busy')
            self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
            self.assertEqual((root / 'lock').stat().st_ino, inode)
        finally:
            _, errors = process.communicate(input='x', timeout=5)
            self.assertEqual(process.returncode, 0, errors)
        result = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:stopped-owner')
        self.assertFalse(isinstance(result, self.api.Refusal))
        self.assertEqual((root / 'lock').stat().st_ino, inode)

    def test_migration_real_commit_crash_and_sqlite_failure_are_atomic(self):
        # Instrument only the real SQLite driver boundary in a disposable child:
        # before/after super().commit(), or SQLite's own authorizer refusal.
        # No fake connection/SQL, product helper patch or simulated process death.
        script = '''
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
def deny_socket(event, args):
    if event.startswith('socket.'):
        raise AssertionError('maintenance child denied socket operation')
sys.addaudithook(deny_socket)
import wag_protection
root = Path(sys.argv[1])
manifest = json.loads(sys.argv[2])
stage = sys.argv[3]
time.time = lambda: 10001.0
time.monotonic = lambda: 8073001.0
class ObservedConnection(sqlite3.Connection):
    def commit(self):
        if stage == 'before':
            print('before', flush=True)
            os.read(0, 1)
        super().commit()
        if stage == 'after':
            print('after', flush=True)
            os.read(0, 1)
original_connect = sqlite3.connect
def connect(database, *args, **kwargs):
    target = str(database).startswith('file:' + str(root / 'ledger.sqlite'))
    if target:
        kwargs['factory'] = ObservedConnection
    db = original_connect(database, *args, **kwargs)
    if target and stage == 'deny':
        def authorize(action, name, *unused):
            if action == sqlite3.SQLITE_DROP_TABLE and name == 'migration_state':
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        db.set_authorizer(authorize)
    return db
sqlite3.connect = connect
result = wag_protection.migrate_legacy(root, manifest=manifest, authorization='synthetic:atomicity-child')
print(json.dumps({'reason': getattr(result, 'reason', None)}), flush=True)
'''
        for stage in ('before', 'after', 'deny'):
            with self.subTest(stage=stage):
                root, manifest, checkpoint = self.legacy_fixture(
                    f'legacy-atomic-{stage}', unfinished=True, poison=('legacy_reason', 'clock_error', 'legacy_reason')
                )
                token = (root / 'identity').read_bytes()
                inode = (root / 'lock').stat().st_ino
                # The finally block explicitly terminates/reaps this fault-injection child and its pipes.
                process = subprocess.Popen(  # pylint: disable=consider-using-with
                    [sys.executable, '-S', '-c', script, str(root), json.dumps(manifest), stage],
                    cwd=WORKSPACE,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    import select

                    assert process.stdout is not None
                    self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'migration boundary was not reached')
                    observed = process.stdout.readline().strip()
                    if stage == 'deny':
                        self.assertEqual(json.loads(observed), {'reason': 'storage_error'})
                        _, errors = process.communicate(timeout=5)
                        self.assertEqual(process.returncode, 0, errors)
                    else:
                        self.assertEqual(observed, stage)
                        # The true transaction is still held at this boundary.
                        refused = self.api.open_store(root, manifest=manifest, mode='synthetic')
                        assert isinstance(refused, self.api.Refusal)
                        self.assertEqual(refused.reason, 'lock_busy')
                        process.kill()
                        process.wait(timeout=5)
                    # A real reopen performs SQLite hot-journal recovery after
                    # precommit death. It must never auto-initialize/migrate.
                    opened = self.api.open_store(root, manifest=manifest, mode='synthetic')
                    self.assertEqual(getattr(opened, 'reason', None), None if stage == 'after' else 'schema_error')
                    with sqlite3.connect(root / 'ledger.sqlite') as db:
                        self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2 if stage == 'after' else 0)
                        self.assertEqual(db.execute('SELECT checkpoint FROM state').fetchone()[0], checkpoint)
                        self.assertEqual(
                            db.execute('SELECT reason FROM poison ORDER BY rowid').fetchall(),
                            [('legacy_reason',), ('clock_error',), ('legacy_reason',)],
                        )
                        if stage == 'after':
                            self.assertEqual(
                                db.execute('SELECT attempt_id,outcome FROM attempts ORDER BY attempt_id').fetchall(),
                                [(7, 'ok'), (19, 'ok'), (41, 'captcha'), (53, None)],
                            )
                        else:
                            self.assertEqual(
                                db.execute(
                                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                                ).fetchall(),
                                [('attempts',), ('pauses',), ('poison',), ('state',)],
                            )
                            self.assertEqual(
                                db.execute('SELECT rowid,outcome FROM attempts ORDER BY rowid').fetchall(),
                                [(7, 'ok'), (19, 'ok'), (41, 'captcha'), (53, None)],
                            )
                    self.assertTrue((root / 'identity').read_bytes() == token)
                    self.assertTrue(Path(str(root) + '.identity').read_bytes() == token)
                    self.assertEqual((root / 'lock').stat().st_ino, inode)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=5)

    def test_recovery_requires_real_sender_stop_and_atomically_preserves_audit_charge_and_pause(self):
        from wag_protection.ledger import _SyntheticMaintenanceSession

        self.assertEqual(self.attempt().outcome, 'empty')
        store = self.open()
        assert not isinstance(store, self.api.Refusal)
        store.claim_release('3' * 32, self.manifest['artifact_digest'], self.manifest['config_digest'], 110.0)
        authorization = 'synthetic:stage9-physical-stop'
        with _SyntheticMaintenanceSession(
            self.root, manifest=self.manifest, authorization=authorization, decision='combined'
        ) as session:
            sender = session.start_sender('quark')
            old_checkpoint = canonical({'wall': 9000.0, 'mono': 80.0, 'boot': 'synthetic-old-boot'}).decode()
            with sqlite3.connect(self.root / 'ledger.sqlite') as db:
                db.row_factory = sqlite3.Row
                db.execute('UPDATE state SET checkpoint=?', (old_checkpoint,))
                db.executemany(
                    'INSERT INTO poison(rowid,reason) VALUES (?,?)',
                    [
                        (5, 'unfinished_attempt'),
                        (8, 'clock_error'),
                        (9, 'clock_error'),
                        (11, 'legacy_reason'),
                    ],
                )
                db.executemany('INSERT INTO pauses VALUES (?,?,?)', [('quark', 1, 1900.0), ('yandex', 1, 800.0)])
                old_attempts = [dict(row) for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')]
                old_release = [tuple(row) for row in db.execute('SELECT * FROM release_checks')]
            proof = session.seal(
                clear_poison=(
                    self.api.PoisonSelection(5, 'unfinished_attempt'),
                    self.api.PoisonSelection(8, 'clock_error'),
                )
            )
            before = (self.root / 'ledger.sqlite').read_bytes()
            refused = self.api.recover(self.root, authorization=authorization, decision='combined', proof=proof)
            assert isinstance(refused, self.api.Refusal)
            self.assertEqual(refused.reason, 'evidence_unknown')
            self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), before)
            session.stop_sender(sender)
            result = self.api.recover(self.root, authorization=authorization, decision='combined', proof=proof)
            self.assertIs(type(result), self.api.RecoveryResult)
            assert isinstance(result, self.api.RecoveryResult)
            self.assertEqual(
                (result.recovery_id, result.decision, result.terminated_count, result.reanchored_count),
                (1, 'combined', 1, 2),
            )
            after = (self.root / 'ledger.sqlite').read_bytes()
            refused = self.api.recover(self.root, authorization=authorization, decision='combined', proof=proof)
            assert isinstance(refused, self.api.Refusal)
            self.assertEqual(
                refused.reason,
                'capability_refused',
            )
            self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), after)
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(
                db.execute(
                    'SELECT authorization,old_checkpoint,old_poison_json,new_boot,wall,mono,decision FROM recoveries'
                ).fetchall(),
                [
                    (
                        authorization,
                        old_checkpoint,
                        '["unfinished_attempt","clock_error","clock_error","legacy_reason"]',
                        self.boot,
                        10000.0,
                        100.0,
                        'combined',
                    )
                ],
            )
            audited = db.execute('SELECT attempt_id,old_row_json FROM recovery_attempts ORDER BY attempt_id').fetchall()
            self.assertEqual([json.loads(row[1]) for row in audited], old_attempts)
            self.assertEqual(
                db.execute('SELECT engine,old_strikes,old_until FROM recovery_pauses ORDER BY engine').fetchall(),
                [('quark', 1, 1900.0), ('yandex', 1, 800.0)],
            )
            self.assertEqual(
                db.execute(
                    'SELECT engine,stamp,outcome,finished_mono,elapsed,connection_attempted,'
                    'http_attempted,account_boot,account_mono FROM attempts ORDER BY attempt_id'
                ).fetchall(),
                [
                    ('bing', 100.0, 'empty', 100.0, 0.0, 0, 0, self.boot, 100.0),
                    ('quark', 100.0, 'unknown_terminated', None, None, 0, 0, self.boot, 100.0),
                ],
            )
            self.assertEqual(
                db.execute('SELECT * FROM pauses ORDER BY engine').fetchall(),
                [('quark', 2, 3700.0), ('yandex', 1, 1900.0)],
            )
            self.assertEqual(
                db.execute('SELECT rowid,reason FROM poison ORDER BY rowid').fetchall(),
                [(9, 'clock_error'), (11, 'legacy_reason')],
            )
            self.assertEqual(db.execute('SELECT * FROM release_checks').fetchall(), old_release)
        self.assertEqual(self.attempt('quark').reason, 'clock_error')

    def test_recovery_rejects_untyped_proof_production_and_seal_mutation_without_writes(self):
        before = (self.root / 'ledger.sqlite').read_bytes()
        for proof in (True, {}, 'proof', None):
            with self.subTest(proof_type=type(proof).__name__):
                result = self.api.recover(
                    self.root, authorization='synthetic:invalid-proof', decision='combined', proof=proof
                )
                assert isinstance(result, self.api.Refusal)
                self.assertEqual(result.reason, 'capability_refused')
                self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), before)
        result = self.api.recover(
            Path('/var/lib/wag-route-probe'),
            authorization='production:looks-valid',
            decision='combined',
            proof={'synthetic': True},
        )
        assert isinstance(result, self.api.Refusal)
        self.assertEqual(result.reason, 'evidence_unknown')
        self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), before)

    # Keep sender coverage, lock ownership and post-refusal assertions in one recovery scenario.
    # pylint: disable-next=too-many-statements
    def test_recovery_rejects_missing_coverage_and_preserves_live_sender(self):
        import select
        from wag_protection.ledger import _SyntheticMaintenanceSession

        authorization = 'synthetic:stage10-coverage'
        with _SyntheticMaintenanceSession(
            self.root, manifest=self.manifest, authorization=authorization, decision='combined'
        ) as session:
            binding = session.start_sender('bing')
            pidfd = os.pidfd_open(binding.pid, 0)
            self.addCleanup(os.close, pidfd)
            with self.assertRaises(TypeError):
                self.api.MaintenanceCapability(
                    authorization, 'combined', self.root, self.boot, 100.0, 200.0, (), session
                )
            proof = session.seal(clear_poison=())
            before = (self.root / 'ledger.sqlite').read_bytes()
            refused = self.api.recover(self.root, authorization=authorization, decision='clock_reanchor', proof=proof)
            assert isinstance(refused, self.api.Refusal)
            self.assertEqual(
                refused.reason,
                'capability_refused',
            )
            refused = self.api.recover(self.root, authorization=authorization, decision='combined', proof=proof)
            assert isinstance(refused, self.api.Refusal)
            self.assertEqual(
                refused.reason,
                'evidence_unknown',
            )
            self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), before)
            self.assertEqual(select.select([pidfd], [], [], 0)[0], [])
            session.stop_sender(binding)
            self.assertEqual(select.select([pidfd], [], [], 0)[0], [pidfd])
            with self.assertRaises(ChildProcessError):
                os.waitpid(binding.pid, os.WNOHANG)
            result = self.api.recover(self.root, authorization=authorization, decision='combined', proof=proof)
            self.assertIs(type(result), self.api.RecoveryResult)
            assert isinstance(result, self.api.RecoveryResult)
            self.assertEqual(result.terminated_count, 1)

        for timing in ('before_seal', 'after_seal'):
            with self.subTest(unregistered_null=timing):
                root = Path(self.parent.name) / f'missing-coverage-{timing}'
                self.api.initialize_fixture(root, registry=self.engines, clock=lambda: dict(self.now))
                manifest = fixture_manifest(root, self.engines)
                with _SyntheticMaintenanceSession(
                    root, manifest=manifest, authorization=authorization, decision='combined'
                ) as session:
                    binding = session.start_sender('bing')
                    pidfd = os.pidfd_open(binding.pid, 0)
                    self.addCleanup(os.close, pidfd)
                    if timing == 'after_seal':
                        proof = session.seal()
                    with sqlite3.connect(root / 'ledger.sqlite') as db:
                        # A valid NULL row from another dispatch is not covered by this sender's birth registration.
                        unregistered_id = db.execute(
                            'INSERT INTO attempts (dispatch_id,engine,domestic,stamp,outcome,'
                            'reserved_mono,finished_mono,'
                            'account_boot,account_mono,caller,phase,connection_attempted,'
                            'http_attempted,elapsed,source) '
                            'SELECT ?,engine,domestic,stamp,outcome,reserved_mono,finished_mono,'
                            'account_boot,account_mono,'
                            'caller,phase,connection_attempted,http_attempted,elapsed,source '
                            'FROM attempts WHERE attempt_id=?',
                            ('stage10-unregistered-dispatch', binding.attempt_ids[0]),
                        ).lastrowid
                    self.assertNotIn(unregistered_id, binding.attempt_ids)
                    before = (root / 'ledger.sqlite').read_bytes()
                    self.assertFalse(
                        isinstance(self.api.open_store(root, manifest=manifest, mode='synthetic'), self.api.Refusal)
                    )
                    for stopped in (False, True):
                        if stopped:
                            session.stop_sender(binding)
                        if timing == 'before_seal':
                            with self.assertRaises(self.api.ProtectionError) as error:
                                session.seal()
                            self.assertEqual(error.exception.reason, 'evidence_unknown')
                        else:
                            refused = self.api.recover(
                                root, authorization=authorization, decision='combined', proof=proof
                            )
                            assert isinstance(refused, self.api.Refusal)
                            self.assertEqual(
                                refused.reason,
                                'evidence_unknown',
                            )
                        self.assertEqual((root / 'ledger.sqlite').read_bytes(), before)
                        self.assertEqual(select.select([pidfd], [], [], 0)[0], [pidfd] if stopped else [])
                        with sqlite3.connect(root / 'ledger.sqlite') as db:
                            self.assertEqual(
                                db.execute('SELECT count(*) FROM attempts WHERE outcome IS NULL').fetchone()[0], 2
                            )
                            for table in ('recoveries', 'recovery_attempts', 'recovery_pauses'):
                                self.assertEqual(db.execute(f'SELECT count(*) FROM {table}').fetchone()[0], 0)

    def test_recovery_audit_failure_rolls_back_without_consuming_proof(self):
        from wag_protection.ledger import _SyntheticMaintenanceSession

        authorization = 'synthetic:stage9-sql-fault'
        with _SyntheticMaintenanceSession(
            self.root, manifest=self.manifest, authorization=authorization, decision='combined'
        ) as session:
            binding = session.start_sender('quark')
            session.stop_sender(binding)
            proof = session.seal()
            before = (self.root / 'ledger.sqlite').read_bytes()
            with patch('wag_protection.ledger._commit', side_effect=sqlite3.OperationalError('synthetic commit fault')):
                result = self.api.recover(self.root, authorization=authorization, decision='combined', proof=proof)
            assert isinstance(result, self.api.Refusal)
            self.assertEqual(result.reason, 'storage_error')
            self.assertEqual((self.root / 'ledger.sqlite').read_bytes(), before)
            # Commit uncertainty consumes the proof; retry is refused rather than guessed.
            refused = self.api.recover(self.root, authorization=authorization, decision='combined', proof=proof)
            assert isinstance(refused, self.api.Refusal)
            self.assertEqual(
                refused.reason,
                'capability_refused',
            )

    def recovery_fixture(self, name):
        root = Path(self.parent.name) / name
        self.api.initialize_fixture(root, registry=self.engines, clock=lambda: dict(self.now))
        manifest = fixture_manifest(root, self.engines)
        store = self.api.open_store(root, manifest=manifest, mode='synthetic')
        assert not isinstance(store, self.api.Refusal)
        outcome = store.run_engine(
            'bing',
            caller='probe',
            deadline_mono=self.now['mono'] + 3,
            build=lambda: None,
            send=lambda context, request: None,
            parse=lambda response: [],
        )
        self.assertEqual(outcome.outcome, 'empty')
        store.claim_release('4' * 32, manifest['artifact_digest'], manifest['config_digest'], 110.0)
        return root, manifest

    # Each SQL mutation boundary is checked against the same complete before/after audit fixture.
    # pylint: disable-next=too-many-locals
    def test_recovery_real_sqlite_faults_rollback_audits_and_mid_mutation(self):
        from wag_protection.ledger import _SyntheticMaintenanceSession

        boundaries = [
            (sqlite3.SQLITE_INSERT, 'recoveries', None, (0, 0, 0)),
            (sqlite3.SQLITE_INSERT, 'recovery_attempts', None, (1, 0, 0)),
            (sqlite3.SQLITE_INSERT, 'recovery_pauses', None, (1, 2, 0)),
            (sqlite3.SQLITE_UPDATE, 'attempts', 'account_boot', (1, 2, 2)),
            (sqlite3.SQLITE_UPDATE, 'attempts', 'outcome', (1, 2, 2)),
            (sqlite3.SQLITE_INSERT, 'pauses', None, (1, 2, 2)),
            (sqlite3.SQLITE_UPDATE, 'state', 'checkpoint', (1, 2, 2)),
            (sqlite3.SQLITE_DELETE, 'poison', None, (1, 2, 2)),
        ]
        original_connect = sqlite3.connect
        for number, (action, table, column, audit_counts) in enumerate(boundaries):
            with self.subTest(table=table, column=column):
                root, manifest = self.recovery_fixture(f'recovery-sql-fault-{number}')
                authorization = f'synthetic:stage11-sql-{number}'
                with _SyntheticMaintenanceSession(
                    root, manifest=manifest, authorization=authorization, decision='combined'
                ) as session:
                    binding = session.start_sender('quark')
                    session.stop_sender(binding)
                    checkpoint = canonical({'wall': 9000.0, 'mono': 80.0, 'boot': 'synthetic-old-boot'}).decode()
                    with original_connect(root / 'ledger.sqlite') as db:
                        db.row_factory = sqlite3.Row
                        db.execute('UPDATE state SET checkpoint=?', (checkpoint,))
                        db.execute('UPDATE attempts SET account_boot=?,account_mono=?', ('synthetic-old-boot', 90.0))
                        db.execute(
                            'UPDATE attempts SET connection_attempted=NULL,http_attempted=NULL WHERE outcome IS NULL'
                        )
                        db.executemany(
                            'INSERT INTO poison(rowid,reason) VALUES (?,?)',
                            [
                                (5, 'clock_error'),
                                (8, 'unfinished_attempt'),
                                (9, 'clock_error'),
                                (11, 'legacy_reason'),
                            ],
                        )
                        db.executemany(
                            'INSERT INTO pauses VALUES (?,?,?)', [('quark', 1, 1900.0), ('yandex', 1, 800.0)]
                        )
                        old_attempts = [dict(row) for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')]
                        old_release = [tuple(row) for row in db.execute('SELECT * FROM release_checks')]
                    proof = session.seal(
                        clear_poison=(
                            self.api.PoisonSelection(5, 'clock_error'),
                            self.api.PoisonSelection(8, 'unfinished_attempt'),
                        )
                    )
                    before = (root / 'ledger.sqlite').read_bytes()
                    reached = []

                    def connect(
                        database,
                        *args,
                        root=root,
                        fault=(action, table, column),
                        record_failure=reached.append,
                        **kwargs,
                    ):
                        db = original_connect(database, *args, **kwargs)
                        if str(database).startswith('file:' + str(root / 'ledger.sqlite')):

                            def authorize(operation, name, field, *_unused):
                                if (operation, name, field) == fault:
                                    record_failure(
                                        {
                                            'counts': tuple(
                                                db.execute(f'SELECT count(*) FROM {audit}').fetchone()[0]
                                                for audit in ('recoveries', 'recovery_attempts', 'recovery_pauses')
                                            ),
                                            'audits': db.execute(
                                                'SELECT old_row_json FROM recovery_attempts ORDER BY attempt_id'
                                            ).fetchall(),
                                            'pauses': db.execute(
                                                'SELECT engine,old_strikes,old_until '
                                                'FROM recovery_pauses ORDER BY engine'
                                            ).fetchall(),
                                            'attempts': [
                                                dict(row)
                                                for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')
                                            ],
                                        }
                                    )
                                    return sqlite3.SQLITE_DENY
                                return sqlite3.SQLITE_OK

                            db.set_authorizer(authorize)
                        return db

                    with patch('sqlite3.connect', side_effect=connect):
                        result = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
                    assert isinstance(result, self.api.Refusal)
                    self.assertEqual(result.reason, 'storage_error')
                    self.assertEqual(len(reached), 1, 'the intended real SQLite operation was not reached exactly once')
                    self.assertEqual(reached[0]['counts'], audit_counts)
                    if audit_counts[1] == 2:
                        self.assertEqual([json.loads(row[0]) for row in reached[0]['audits']], old_attempts)
                    if audit_counts[2] == 2:
                        self.assertEqual(
                            [tuple(row) for row in reached[0]['pauses']], [('quark', 1, 1900.0), ('yandex', 1, 800.0)]
                        )
                    if table == 'attempts' and column == 'outcome':
                        self.assertEqual([row['account_mono'] for row in reached[0]['attempts']], [100.0, 100.0])
                        self.assertIsNone(reached[0]['attempts'][1]['outcome'])
                    if table in ('pauses', 'state', 'poison'):
                        self.assertEqual(reached[0]['attempts'][1]['outcome'], 'unknown_terminated')
                    self.assertTrue(
                        (root / 'ledger.sqlite').read_bytes() == before, 'SQL refusal changed durable ledger bytes'
                    )
                    with original_connect(root / 'ledger.sqlite') as db:
                        db.row_factory = sqlite3.Row
                        self.assertEqual(
                            [dict(row) for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')],
                            old_attempts,
                        )
                        self.assertEqual(
                            [tuple(row) for row in db.execute('SELECT * FROM release_checks')], old_release
                        )
                        for audit in ('recoveries', 'recovery_attempts', 'recovery_pauses'):
                            self.assertEqual(db.execute(f'SELECT count(*) FROM {audit}').fetchone()[0], 0)
                    self.assertFalse(
                        isinstance(self.api.open_store(root, manifest=manifest, mode='synthetic'), self.api.Refusal)
                    )

    # The child death, hot-journal reopen and complete audit assertions form one atomicity check.
    # pylint: disable-next=too-many-statements
    def test_recovery_real_commit_death_keeps_old_or_complete_new_state(self):
        import select

        script = '''
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
def deny_socket(event, args):
    if event.startswith('socket.'):
        raise AssertionError('recovery child denied socket operation')
sys.addaudithook(deny_socket)
import wag_protection
from wag_protection.ledger import _SyntheticMaintenanceSession
root = Path(sys.argv[1])
manifest = json.loads(sys.argv[2])
stage = sys.argv[3]
time.time = lambda: 10000.0
time.monotonic = lambda: 100.0
with _SyntheticMaintenanceSession(root, manifest=manifest, authorization='synthetic:stage11-commit-death',
                                  decision='combined') as session:
    binding = session.start_sender('quark')
    session.stop_sender(binding)
    with sqlite3.connect(root / 'ledger.sqlite') as db:
        db.execute('UPDATE state SET checkpoint=?', (json.dumps({'wall': 9000.0, 'mono': 80.0, 'boot': 'synthetic-old-boot'},
                   sort_keys=True, separators=(',', ':')),))
        db.execute('UPDATE attempts SET account_boot=?,account_mono=?', ('synthetic-old-boot', 90.0))
        db.execute('UPDATE attempts SET connection_attempted=NULL,http_attempted=NULL WHERE outcome IS NULL')
        db.executemany('INSERT INTO poison(rowid,reason) VALUES (?,?)', [
            (5, 'clock_error'), (8, 'unfinished_attempt'), (9, 'clock_error'), (11, 'legacy_reason'),
        ])
        db.executemany('INSERT INTO pauses VALUES (?,?,?)', [('quark', 1, 1900.0), ('yandex', 1, 800.0)])
    proof = session.seal(clear_poison=(wag_protection.PoisonSelection(5, 'clock_error'),
                                      wag_protection.PoisonSelection(8, 'unfinished_attempt')))
    print('sealed', flush=True)
    os.read(0, 1)
    class ObservedConnection(sqlite3.Connection):
        def commit(self):
            if stage == 'before':
                print('before', flush=True)
                os.read(0, 1)
            super().commit()
            if stage == 'after':
                print('after', flush=True)
                os.read(0, 1)
    original_connect = sqlite3.connect
    def connect(database, *args, **kwargs):
        if str(database).startswith('file:' + str(root / 'ledger.sqlite')):
            kwargs['factory'] = ObservedConnection
        return original_connect(database, *args, **kwargs)
    sqlite3.connect = connect
    result = wag_protection.recover(root, authorization='synthetic:stage11-commit-death', decision='combined', proof=proof)
    print(json.dumps({'reason': getattr(result, 'reason', None)}), flush=True)
'''
        for stage in ('before', 'after'):
            with self.subTest(commit=stage):
                root, manifest = self.recovery_fixture(f'recovery-commit-death-{stage}')
                identity = (root / 'identity').read_bytes()
                lock_inode = (root / 'lock').stat().st_ino
                # The finally block explicitly terminates/reaps this fault-injection child and its pipes.
                process = subprocess.Popen(  # pylint: disable=consider-using-with
                    [sys.executable, '-S', '-c', script, str(root), json.dumps(manifest), stage],
                    cwd=WORKSPACE,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    close_fds=True,
                )
                try:
                    assert process.stdout is not None
                    self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'real recovery sender did not seal')
                    self.assertEqual(process.stdout.readline().strip(), 'sealed')
                    before = (root / 'ledger.sqlite').read_bytes()
                    with sqlite3.connect(root / 'ledger.sqlite') as db:
                        db.row_factory = sqlite3.Row
                        old_attempts = [dict(row) for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')]
                        old_release = [tuple(row) for row in db.execute('SELECT * FROM release_checks')]
                        old_checkpoint = db.execute('SELECT checkpoint FROM state').fetchone()[0]
                    assert process.stdin is not None
                    process.stdin.write('x')
                    process.stdin.flush()
                    self.assertTrue(
                        select.select([process.stdout], [], [], 5)[0], 'real commit boundary was not reached'
                    )
                    self.assertEqual(process.stdout.readline().strip(), stage)
                    refused = self.api.open_store(root, manifest=manifest, mode='synthetic')
                    assert isinstance(refused, self.api.Refusal)
                    self.assertEqual(refused.reason, 'lock_busy')
                    process.kill()
                    process.communicate(timeout=5)
                    self.assertEqual(process.returncode, -9)
                    # Reopen the actual database, including SQLite hot-journal rollback after precommit death.
                    self.assertFalse(
                        isinstance(self.api.open_store(root, manifest=manifest, mode='synthetic'), self.api.Refusal)
                    )
                    with sqlite3.connect(root / 'ledger.sqlite') as db:
                        db.row_factory = sqlite3.Row
                        attempts = [dict(row) for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')]
                        self.assertEqual(
                            [tuple(row) for row in db.execute('SELECT * FROM release_checks')], old_release
                        )
                        if stage == 'before':
                            self.assertEqual(attempts, old_attempts)
                            self.assertEqual(db.execute('SELECT checkpoint FROM state').fetchone()[0], old_checkpoint)
                            for audit in ('recoveries', 'recovery_attempts', 'recovery_pauses'):
                                self.assertEqual(db.execute(f'SELECT count(*) FROM {audit}').fetchone()[0], 0)
                            self.assertEqual(
                                [tuple(row) for row in db.execute('SELECT * FROM pauses ORDER BY engine')],
                                [('quark', 1, 1900.0), ('yandex', 1, 800.0)],
                            )
                            self.assertEqual(
                                [tuple(row) for row in db.execute('SELECT rowid,reason FROM poison ORDER BY rowid')],
                                [
                                    (5, 'clock_error'),
                                    (8, 'unfinished_attempt'),
                                    (9, 'clock_error'),
                                    (11, 'legacy_reason'),
                                ],
                            )
                        else:
                            expected = [dict(row, account_boot=self.boot, account_mono=100.0) for row in old_attempts]
                            expected[1]['outcome'] = 'unknown_terminated'
                            self.assertEqual(attempts, expected)
                            self.assertEqual(
                                db.execute('SELECT checkpoint FROM state').fetchone()[0], canonical(self.now).decode()
                            )
                            self.assertEqual(
                                [tuple(row) for row in db.execute('SELECT * FROM recoveries')],
                                [
                                    (
                                        1,
                                        'synthetic:stage11-commit-death',
                                        old_checkpoint,
                                        '["clock_error","unfinished_attempt","clock_error","legacy_reason"]',
                                        self.boot,
                                        10000.0,
                                        100.0,
                                        'combined',
                                    ),
                                ],
                            )
                            audited = db.execute(
                                'SELECT attempt_id,old_row_json FROM recovery_attempts ORDER BY attempt_id'
                            ).fetchall()
                            self.assertEqual(
                                [(row[0], json.loads(row[1])) for row in audited],
                                [(row['attempt_id'], row) for row in old_attempts],
                            )
                            self.assertEqual(
                                [tuple(row) for row in db.execute('SELECT * FROM recovery_pauses ORDER BY engine')],
                                [(1, 'quark', 1, 1900.0), (1, 'yandex', 1, 800.0)],
                            )
                            self.assertEqual(
                                [tuple(row) for row in db.execute('SELECT * FROM pauses ORDER BY engine')],
                                [('quark', 2, 3700.0), ('yandex', 1, 1900.0)],
                            )
                            self.assertEqual(
                                [tuple(row) for row in db.execute('SELECT rowid,reason FROM poison ORDER BY rowid')],
                                [(9, 'clock_error'), (11, 'legacy_reason')],
                            )
                    if stage == 'before':
                        self.assertTrue(
                            (root / 'ledger.sqlite').read_bytes() == before,
                            'precommit death changed durable ledger bytes',
                        )
                    self.assertTrue((root / 'identity').read_bytes() == identity)
                    self.assertTrue(Path(str(root) + '.identity').read_bytes() == identity)
                    self.assertEqual((root / 'lock').stat().st_ino, lock_inode)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=5)

    def test_recovery_postcommit_fsync_uncertainty_refuses_without_rollback_or_retry(self):
        from wag_protection.ledger import _SyntheticMaintenanceSession

        root, manifest = self.recovery_fixture('recovery-fsync-uncertain')
        authorization = 'synthetic:stage11-fsync-uncertain'
        with _SyntheticMaintenanceSession(
            root, manifest=manifest, authorization=authorization, decision='combined'
        ) as session:
            binding = session.start_sender('quark')
            session.stop_sender(binding)
            with sqlite3.connect(root / 'ledger.sqlite') as db:
                db.execute('UPDATE attempts SET connection_attempted=NULL,http_attempted=NULL WHERE outcome IS NULL')
                db.row_factory = sqlite3.Row
                old_attempts = [dict(row) for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')]
                old_release = [tuple(row) for row in db.execute('SELECT * FROM release_checks')]
            proof = session.seal()
            before = (root / 'ledger.sqlite').read_bytes()
            observed = []

            def fail_directory_fsync(descriptor):
                self.assertEqual(os.fstat(descriptor).st_ino, root.stat().st_ino)
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    observed.append(db.execute('SELECT count(*) FROM recoveries').fetchone()[0])
                    self.assertEqual(
                        db.execute('SELECT outcome FROM attempts WHERE engine=?', ('quark',)).fetchone()[0],
                        'unknown_terminated',
                    )
                raise OSError('synthetic postcommit directory fsync fault')

            with patch('os.fsync', side_effect=fail_directory_fsync):
                result = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
            assert isinstance(result, self.api.Refusal)
            self.assertEqual(result.reason, 'storage_error')
            self.assertEqual(observed, [1], 'failure did not occur after a real durable SQLite commit')
            after = (root / 'ledger.sqlite').read_bytes()
            self.assertTrue(after != before, 'test did not exercise postcommit uncertainty')
            with sqlite3.connect(root / 'ledger.sqlite') as db:
                audited = db.execute('SELECT old_row_json FROM recovery_attempts ORDER BY attempt_id').fetchall()
                self.assertEqual([json.loads(row[0]) for row in audited], old_attempts)
                self.assertEqual(
                    db.execute('SELECT engine,old_strikes,old_until FROM recovery_pauses').fetchall(),
                    [('quark', None, None)],
                )
                self.assertEqual(db.execute('SELECT * FROM pauses').fetchall(), [('quark', 1, 1900.0)])
                self.assertEqual(
                    db.execute(
                        'SELECT finished_mono,elapsed,connection_attempted,http_attempted FROM attempts '
                        'WHERE engine=?',
                        ('quark',),
                    ).fetchone(),
                    (None, None, None, None),
                )
                self.assertEqual(db.execute('SELECT * FROM release_checks').fetchall(), old_release)
            refused = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
            assert isinstance(refused, self.api.Refusal)
            self.assertEqual(
                refused.reason,
                'capability_refused',
            )
            self.assertTrue((root / 'ledger.sqlite').read_bytes() == after, 'uncertain recovery was retried')
            self.assertFalse(
                isinstance(self.api.open_store(root, manifest=manifest, mode='synthetic'), self.api.Refusal)
            )

    # Keep ownership and counterfeit-proof checks attached to their original live maintenance session.
    # pylint: disable-next=too-many-locals,too-many-statements
    def test_recovery_owner_thread_fork_and_counterfeit_proofs_refuse_without_callbacks(self):
        import pickle
        import select
        import threading
        from wag_protection.ledger import _SyntheticMaintenanceSession

        root, manifest = self.recovery_fixture('recovery-owner-proof')
        authorization = 'synthetic:stage11-owner-proof'
        with _SyntheticMaintenanceSession(
            root, manifest=manifest, authorization=authorization, decision='combined'
        ) as session:
            binding = session.start_sender('quark')
            session.stop_sender(binding)
            proof = session.seal()
            before = (root / 'ledger.sqlite').read_bytes()
            replies = []
            thread = threading.Thread(
                target=lambda: replies.append(
                    self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
                )
            )
            thread.start()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), 'cross-owner refusal did not finish')
            self.assertEqual([result.reason for result in replies], ['capability_refused'])
            self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)

            read_fd, write_fd = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(read_fd)
                result = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
                assert isinstance(result, self.api.Refusal)
                os.write(write_fd, result.reason.encode('ascii'))
                # A fork child must terminate without running inherited Python cleanups.
                os._exit(0)  # pylint: disable=protected-access
            os.close(write_fd)
            try:
                self.assertTrue(select.select([read_fd], [], [], 5)[0], 'forked proof owner did not refuse')
                self.assertEqual(os.read(read_fd, 256), b'capability_refused')
            finally:
                os.close(read_fd)
                pid, status = _reap_owned_fork(child)
            self.assertEqual(pid, child)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
            for value in (proof, proof.capability, binding):
                with self.assertRaises(TypeError):
                    pickle.dumps(value)

            called = []

            # A single interception hook is the adversarial proof input.
            class Counterfeit(self.api.RecoveryProofV1):  # pylint: disable=too-few-public-methods
                def __getattribute__(self, name):
                    called.append(name)
                    raise AssertionError('proof subclass callback executed')

            # Only attribute interception is needed to detect an unauthorized callback.
            class Callback:  # pylint: disable=too-few-public-methods
                def __getattribute__(self, name):
                    called.append(name)
                    raise AssertionError('untyped proof callback executed')

            copied = self.api.RecoveryProofV1(
                proof.version, proof.capability, proof.approved_manifest, proof.sender_bindings,
                # Deliberately copy the private witness to prove a counterfeit remains rejected.
                proof._witness,  # pylint: disable=protected-access
            )
            for value in (copied, object.__new__(Counterfeit), Callback(), b'serialized-proof', True, {}):
                result = self.api.recover(root, authorization=authorization, decision='combined', proof=value)
                assert isinstance(result, self.api.Refusal)
                self.assertEqual(result.reason, 'capability_refused')
                self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
            self.assertEqual(called, [])
            result = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
            self.assertIs(type(result), self.api.RecoveryResult)

    def test_recovery_expired_or_changed_boot_proof_preserves_state(self):
        from wag_protection.ledger import _SyntheticMaintenanceSession

        root, manifest = self.recovery_fixture('recovery-expiry-boot')
        authorization = 'synthetic:stage11-expiry-boot'
        with _SyntheticMaintenanceSession(
            root, manifest=manifest, authorization=authorization, decision='combined'
        ) as session:
            binding = session.start_sender('quark')
            session.stop_sender(binding)
            proof = session.seal()
            before = (root / 'ledger.sqlite').read_bytes()
            clock: FixtureClock = {
                'wall': self.now['wall'],
                'mono': self.now['mono'],
                'boot': self.now['boot'],
            }
            self.advance(300)
            refused = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
            assert isinstance(refused, self.api.Refusal)
            self.assertEqual(
                refused.reason,
                'evidence_unknown',
            )
            self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
            self.now.update(clock)
            original_read = Path.read_text

            def changed_boot(path, *args, **kwargs):
                if path == Path('/proc/sys/kernel/random/boot_id'):
                    return 'synthetic-changed-observed-boot'
                return original_read(path, *args, **kwargs)

            with patch.object(Path, 'read_text', changed_boot):
                refused = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
                assert isinstance(refused, self.api.Refusal)
                self.assertEqual(
                    refused.reason,
                    'evidence_unknown',
                )
            self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
            result = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
            self.assertIs(type(result), self.api.RecoveryResult)

    def test_recovery_replaced_file_bindings_and_identity_refuse_without_writes(self):
        from wag_protection.ledger import _SyntheticMaintenanceSession

        for target in ('root', 'lock', 'identity', 'anchor', 'ledger', 'identity_content'):
            with self.subTest(binding=target):
                root, manifest = self.recovery_fixture(f'recovery-replaced-{target}')
                authorization = f'synthetic:stage11-binding-{target}'
                with _SyntheticMaintenanceSession(
                    root, manifest=manifest, authorization=authorization, decision='combined'
                ) as session:
                    binding = session.start_sender('quark')
                    session.stop_sender(binding)
                    proof = session.seal()
                    if target == 'root':
                        original_inode = root.stat().st_ino
                        moved = root.with_name(root.name + '-old')
                        root.rename(moved)
                        root.mkdir(mode=0o700)
                        for path in moved.iterdir():
                            path.rename(root / path.name)
                        self.assertNotEqual(root.stat().st_ino, original_inode)
                    elif target == 'identity_content':
                        (root / 'identity').write_bytes(b'5' * 32)
                    else:
                        path = {
                            'lock': root / 'lock',
                            'identity': root / 'identity',
                            'anchor': Path(str(root) + '.identity'),
                            'ledger': root / 'ledger.sqlite',
                        }[target]
                        original_inode = path.stat().st_ino
                        replacement = path.with_name(path.name + '-replacement')
                        with os.fdopen(os.open(replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as file:
                            file.write(path.read_bytes())
                        replacement.replace(path)
                        self.assertNotEqual(path.stat().st_ino, original_inode)
                    before = (root / 'ledger.sqlite').read_bytes()
                    result = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
                    assert isinstance(result, self.api.Refusal)
                    self.assertEqual(result.reason, 'identity_error')
                    self.assertTrue(
                        (root / 'ledger.sqlite').read_bytes() == before, 'binding refusal changed durable ledger bytes'
                    )
                    with sqlite3.connect(root / 'ledger.sqlite') as db:
                        self.assertEqual(
                            db.execute('SELECT count(*) FROM attempts WHERE outcome IS NULL').fetchone()[0], 1
                        )
                        for audit in ('recoveries', 'recovery_attempts', 'recovery_pauses'):
                            self.assertEqual(db.execute(f'SELECT count(*) FROM {audit}').fetchone()[0], 0)
                    if target != 'identity_content':
                        self.assertFalse(
                            isinstance(self.api.open_store(root, manifest=manifest, mode='synthetic'), self.api.Refusal)
                        )

    def test_recovery_manifest_is_deep_frozen_and_proof_replacement_refuses(self):
        from wag_protection.ledger import _SyntheticMaintenanceSession

        root, manifest = self.recovery_fixture('recovery-manifest-binding')
        authorization = 'synthetic:stage11-manifest-binding'
        with _SyntheticMaintenanceSession(
            root, manifest=manifest, authorization=authorization, decision='combined'
        ) as session:
            binding = session.start_sender('quark')
            session.stop_sender(binding)
            proof = session.seal()
            before = (root / 'ledger.sqlite').read_bytes()
            approved = proof.approved_manifest
            assert isinstance(approved, Mapping)
            assert isinstance(approved['registry'], tuple)
            assert isinstance(approved['registry'][0], Mapping)
            assert isinstance(approved['registry'][0]['profile'], Mapping)
            with self.assertRaises(TypeError):
                # Exercise runtime assignment to the read-only Mapping without a misleading mutable cast.
                exec(  # pylint: disable=exec-used
                    "approved['registry'][0]['profile']['live_hold'] = True", {}, {'approved': approved}
                )
            assert isinstance(manifest['registry'], list)
            assert isinstance(manifest['registry'][0], dict)
            assert isinstance(manifest['registry'][0]['profile'], dict)
            manifest['config_digest'] = 'b' * 64
            manifest['registry'][0]['profile']['live_hold'] = True
            self.assertEqual(approved['config_digest'], 'a' * 64)
            self.assertFalse(approved['registry'][0]['profile']['live_hold'])
            object.__setattr__(proof, 'approved_manifest', manifest)
            result = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
            assert isinstance(result, self.api.Refusal)
            self.assertEqual(result.reason, 'provenance_error')
            self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
            object.__setattr__(proof, 'approved_manifest', approved)
            result = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
            self.assertIs(type(result), self.api.RecoveryResult)

    # The decision matrix needs both original audit state and recovery results for each row.
    # pylint: disable-next=too-many-locals
    def test_recovery_decisions_enforce_null_and_clock_requirements(self):
        from wag_protection.ledger import _SyntheticMaintenanceSession

        for decision, invalid in (
            ('clock_reanchor', False),
            ('clock_reanchor', True),
            ('terminated_sender', False),
            ('terminated_sender', True),
        ):
            with self.subTest(decision=decision, invalid=invalid):
                root, manifest = self.recovery_fixture(f'recovery-decision-{decision}-{invalid}')
                authorization = f'synthetic:stage11-decision-{decision}-{invalid}'
                with _SyntheticMaintenanceSession(
                    root, manifest=manifest, authorization=authorization, decision=decision
                ) as session:
                    binding = session.start_sender('quark' if decision == 'terminated_sender' or invalid else None)
                    session.stop_sender(binding)
                    with sqlite3.connect(root / 'ledger.sqlite') as db:
                        db.row_factory = sqlite3.Row
                        if decision == 'clock_reanchor':
                            checkpoint = dict(self.now, wall=9000.0, mono=80.0, boot='synthetic-old-boot')
                            db.execute('UPDATE state SET checkpoint=?', (canonical(checkpoint).decode(),))
                            db.execute(
                                'UPDATE attempts SET account_boot=?,account_mono=?', ('synthetic-old-boot', 90.0)
                            )
                            db.execute('INSERT INTO poison(rowid,reason) VALUES (5,?)', ('clock_error',))
                        elif invalid:
                            db.execute(
                                'UPDATE state SET checkpoint=?', (canonical(dict(self.now, wall=9000.0)).decode(),)
                            )
                        old_attempts = [dict(row) for row in db.execute('SELECT * FROM attempts ORDER BY attempt_id')]
                    selection = (self.api.PoisonSelection(5, 'clock_error'),) if decision == 'clock_reanchor' else ()
                    proof = session.seal(clear_poison=selection)
                    before = (root / 'ledger.sqlite').read_bytes()
                    result = self.api.recover(root, authorization=authorization, decision=decision, proof=proof)
                    if invalid:
                        assert isinstance(result, self.api.Refusal)
                        self.assertEqual(
                            result.reason, 'evidence_unknown' if decision == 'clock_reanchor' else 'clock_error'
                        )
                        self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
                        with sqlite3.connect(root / 'ledger.sqlite') as db:
                            for audit in ('recoveries', 'recovery_attempts', 'recovery_pauses'):
                                self.assertEqual(db.execute(f'SELECT count(*) FROM {audit}').fetchone()[0], 0)
                    else:
                        self.assertIs(type(result), self.api.RecoveryResult)
                        assert isinstance(result, self.api.RecoveryResult)
                        self.assertEqual(
                            (result.terminated_count, result.reanchored_count),
                            (0, 1) if decision == 'clock_reanchor' else (1, 0),
                        )
                        with sqlite3.connect(root / 'ledger.sqlite') as db:
                            db.row_factory = sqlite3.Row
                            changed = old_attempts if decision == 'clock_reanchor' else old_attempts[1:]
                            audited = db.execute(
                                'SELECT attempt_id,old_row_json FROM recovery_attempts ORDER BY attempt_id'
                            ).fetchall()
                            self.assertEqual(
                                [(row[0], json.loads(row[1])) for row in audited],
                                [(row['attempt_id'], row) for row in changed],
                            )
                            bing = dict(db.execute('SELECT * FROM attempts WHERE engine=?', ('bing',)).fetchone())
                            expected_bing = (
                                dict(old_attempts[0], account_boot=self.boot, account_mono=100.0)
                                if decision == 'clock_reanchor'
                                else old_attempts[0]
                            )
                            self.assertEqual(bing, expected_bing)
                            if decision == 'clock_reanchor':
                                self.assertEqual(db.execute('SELECT count(*) FROM poison').fetchone()[0], 0)
                                self.assertEqual(db.execute('SELECT count(*) FROM pauses').fetchone()[0], 0)
                            else:
                                self.assertEqual(
                                    db.execute('SELECT outcome FROM attempts WHERE engine=?', ('quark',)).fetchone()[0],
                                    'unknown_terminated',
                                )
                                self.assertEqual(
                                    [tuple(row) for row in db.execute('SELECT * FROM pauses')], [('quark', 1, 1900.0)]
                                )

    def test_recovery_unknown_legacy_null_cannot_be_claimed_by_empty_sender_binding(self):
        import select
        from wag_protection.ledger import _SyntheticMaintenanceSession

        root, manifest, _ = self.legacy_fixture(
            'recovery-unknown-legacy', unfinished=True, poison=('unfinished_attempt',)
        )
        migrated = self.api.migrate_legacy(root, manifest=manifest, authorization='synthetic:stage11-legacy-migration')
        self.assertFalse(isinstance(migrated, self.api.Refusal))
        authorization = 'synthetic:stage11-legacy-unknown'
        with _SyntheticMaintenanceSession(
            root, manifest=manifest, authorization=authorization, decision='combined'
        ) as session:
            binding = session.start_sender()
            self.assertEqual(binding.attempt_ids, ())
            pidfd = os.pidfd_open(binding.pid, 0)
            self.addCleanup(os.close, pidfd)
            before = (root / 'ledger.sqlite').read_bytes()
            for stopped in (False, True):
                if stopped:
                    session.stop_sender(binding)
                with self.assertRaises(self.api.ProtectionError) as error:
                    session.seal(clear_poison=())
                self.assertEqual(error.exception.reason, 'evidence_unknown')
                self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
                self.assertEqual(select.select([pidfd], [], [], 0)[0], [pidfd] if stopped else [])
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    self.assertEqual(
                        db.execute('SELECT attempt_id,outcome,source FROM attempts WHERE outcome IS NULL').fetchall(),
                        [(53, None, 'legacy')],
                    )
                    for audit in ('recoveries', 'recovery_attempts', 'recovery_pauses'):
                        self.assertEqual(db.execute(f'SELECT count(*) FROM {audit}').fetchone()[0], 0)

    def test_recovery_production_rejects_real_synthetic_proof_before_storage_or_process_access(self):
        from wag_protection.ledger import _SyntheticMaintenanceSession

        root, manifest = self.recovery_fixture('recovery-production-proof-refusal')
        authorization = 'synthetic:stage11-production-refusal'
        with _SyntheticMaintenanceSession(
            root, manifest=manifest, authorization=authorization, decision='combined'
        ) as session:
            binding = session.start_sender('quark')
            session.stop_sender(binding)
            proof = session.seal()
            before = (root / 'ledger.sqlite').read_bytes()
            with (
                patch('sqlite3.connect', side_effect=AssertionError('production proof opened SQLite')),
                patch('subprocess.Popen', side_effect=AssertionError('production proof started a process')),
                patch.object(Path, 'read_bytes', side_effect=AssertionError('production proof read file contents')),
                patch.object(Path, 'write_bytes', side_effect=AssertionError('production proof wrote a file')),
                patch.object(Path, 'write_text', side_effect=AssertionError('production proof wrote a file')),
            ):
                for target in (Path('/var/lib/wag-route-probe'), Path('/var/lib/wag-route-probe/unapproved-child')):
                    result = self.api.recover(target, authorization=authorization, decision='combined', proof=proof)
                    assert isinstance(result, self.api.Refusal)
                    self.assertEqual(result.reason, 'evidence_unknown')
            self.assertTrue((root / 'ledger.sqlite').read_bytes() == before)
            result = self.api.recover(root, authorization=authorization, decision='combined', proof=proof)
            self.assertIs(type(result), self.api.RecoveryResult)

    def test_malformed_recovery_audit_refuses_before_callbacks(self):
        mutations = [
            ('wall', -1.0),
            ('mono', float('inf')),
            ('decision', 'reset_budget'),
            ('new_boot', ''),
            ('old_checkpoint', '{"mono":100}'),
            ('old_poison_json', '{}'),
            ('old_poison_json', '[null]'),
        ]
        for number, (field, value) in enumerate(mutations):
            with self.subTest(field=field, value=value):
                root = Path(self.parent.name) / f'invalid-recovery-audit-{number}'
                self.api.initialize_fixture(root, registry=self.engines, clock=lambda: dict(self.now))
                manifest = fixture_manifest(root, self.engines)
                store = self.api.open_store(root, manifest=manifest, mode='synthetic')
                assert not isinstance(store, self.api.Refusal)
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    db.execute(
                        'INSERT INTO recoveries VALUES (1,?,?,?,?,?,?,?)',
                        (
                            'synthetic-test-authorization',
                            canonical(self.now).decode(),
                            '["clock_error"]',
                            self.boot,
                            10000.0,
                            100.0,
                            'clock_reanchor',
                        ),
                    )
                    db.execute(f'UPDATE recoveries SET {field}=?', (value,))
                calls = []
                reopened = self.api.open_store(root, manifest=manifest, mode='synthetic')
                outcome = store.run_engine(
                    'bing',
                    caller='probe',
                    deadline_mono=103.0,
                    build=lambda calls=calls: calls.append('build'),
                    send=lambda context, request, calls=calls: calls.append('send'),
                    parse=lambda response, calls=calls: calls.append('parse') or [],
                )
                self.assertEqual(
                    (getattr(reopened, 'reason', None), getattr(outcome, 'reason', None), calls),
                    ('schema_error', 'schema_error', []),
                )

    def test_valid_recovery_audit_is_preserved_and_does_not_deny_normal_dispatch(self):
        old_checkpoint = '{"wall":9000.0, "mono":80.0, "boot":"synthetic-old-boot"}'
        old_poison = '["clock_error","legacy_reason","clock_error"]'
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            db.execute(
                'INSERT INTO recoveries VALUES (1,?,?,?,?,?,?,?)',
                (
                    'synthetic-test-authorization',
                    old_checkpoint,
                    old_poison,
                    self.boot,
                    10000.0,
                    100.0,
                    'combined',
                ),
            )
        self.assertEqual(self.attempt().outcome, 'empty')
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(
                db.execute('SELECT old_checkpoint,old_poison_json FROM recoveries').fetchall(),
                [(old_checkpoint, old_poison)],
            )
            self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [])
            self.assertEqual(db.execute('SELECT count(*) FROM attempts').fetchone()[0], 1)

    def test_unknown_attempt_column_refuses_before_callbacks(self):
        store = self.open()
        assert not isinstance(store, self.api.Refusal)
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            db.execute('ALTER TABLE attempts ADD COLUMN unreviewed_schema TEXT')
        calls = []
        result = self.api.open_store(self.root, manifest=self.manifest, mode='synthetic')
        outcome = store.run_engine(
            'bing',
            caller='probe',
            deadline_mono=self.now['mono'] + 3,
            build=lambda: calls.append('build'),
            send=lambda context, request: calls.append('send'),
            parse=lambda response: calls.append('parse') or [],
        )
        self.assertEqual(
            (getattr(result, 'reason', None), getattr(outcome, 'reason', None), calls),
            ('schema_error', 'schema_error', []),
        )

    def test_fixed_schema_rejects_changed_objects_types_constraints_and_indices(self):
        mutations = [
            'CREATE TABLE unreviewed (value TEXT)',
            'CREATE VIEW unreviewed AS SELECT * FROM attempts',
            'CREATE TRIGGER unreviewed AFTER INSERT ON attempts BEGIN DELETE FROM poison; END',
            'CREATE INDEX unreviewed ON attempts(stamp)',
            'DROP INDEX attempts_dispatch',
            'DROP INDEX attempts_engine_account; CREATE INDEX attempts_engine_account ON attempts(engine,account_mono)',
            'DROP TABLE poison; CREATE TABLE poison (reason BLOB NOT NULL)',
            'DROP TABLE poison; CREATE TABLE poison (reason TEXT)',
            'DROP TABLE pauses; CREATE TABLE pauses (engine TEXT PRIMARY KEY REFERENCES engine_identities(engine), '
            'strikes INTEGER NOT NULL, until REAL NOT NULL)',
            'DROP TABLE pauses; CREATE TABLE pauses (engine TEXT PRIMARY KEY, '
            'strikes INTEGER NOT NULL CHECK(strikes>=0), until REAL NOT NULL)',
            'DROP TABLE poison; CREATE TABLE poison (reason TEXT NOT NULL DEFAULT \'unknown\')',
        ]
        for number, sql in enumerate(mutations):
            with self.subTest(sql=sql):
                root = Path(self.parent.name) / f'mutated-{number}'
                self.api.initialize_fixture(root, registry=self.engines, clock=lambda: dict(self.now))
                manifest = fixture_manifest(root, self.engines)
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    db.executescript(sql)
                result = self.api.open_store(root, manifest=manifest, mode='synthetic')
                self.assertEqual(getattr(result, 'reason', None), 'schema_error')

    def test_build_failure_is_charged_durably_before_callback(self):
        def build():
            # A nested public read must see the parser/dispatch lock, not a permit.
            snapshot_store = self.open()
            assert not isinstance(snapshot_store, self.api.Refusal)
            nested = snapshot_store.public_snapshot(self.manifest['artifact_digest'], self.manifest['config_digest'])
            assert isinstance(nested, self.api.Refusal)
            self.assertEqual(nested.reason, 'lock_busy')
            raise ValueError('synthetic request failure')

        store = self.open()
        assert not isinstance(store, self.api.Refusal)
        for _ in range(6):
            result = store.run_engine(
                'bing',
                caller='native_search',
                deadline_mono=103.0,
                build=build,
                send=lambda context, request: None,
                parse=lambda response: [],
            )
            self.assertEqual(result.outcome, 'request_refused')
            self.assertEqual(result.reservations, 1)
        reopened = self.open()
        assert not isinstance(reopened, self.api.Refusal)
        seventh = reopened.run_engine(
            'bing',
            caller='native_search',
            deadline_mono=103.0,
            build=build,
            send=lambda context, request: None,
            parse=lambda response: [],
        )
        self.assertEqual(seventh.reason, 'engine_rate')

    def attempt(
        self, engine='bing', *, build=lambda: None, parse=lambda response: [], send=lambda context, request: None
    ):
        store = self.open()
        assert not isinstance(store, self.api.Refusal)
        return store.run_engine(
            engine, caller='native_search', deadline_mono=self.now['mono'] + 3, build=build, send=send, parse=parse
        )

    def advance(self, seconds):
        self.now['wall'] += seconds
        self.now['mono'] += seconds

    def test_clock_poison_persists_even_when_wall_is_later_corrected(self):
        self.now['wall'] += 10
        self.assertEqual(self.attempt().reason, 'clock_error')
        self.now['wall'] -= 10
        self.assertEqual(self.attempt().reason, 'clock_error')

    def test_unknown_engine_and_deadline_refuse_before_callbacks(self):
        def forbidden():
            self.fail('refused attempt called build')

        self.assertEqual(self.attempt('unreviewed', build=forbidden).reason, 'capability_refused')
        store = self.open()
        assert not isinstance(store, self.api.Refusal)
        result = store.run_engine(
            'bing',
            caller='native_search',
            deadline_mono=self.now['mono'],
            build=forbidden,
            send=lambda context, request: None,
            parse=lambda response: [],
        )
        self.assertEqual(result.reason, 'deadline_exceeded')

    def test_finished_accounting_keeps_delayed_failure_in_window(self):
        for _ in range(5):
            self.assertEqual(self.attempt().outcome, 'empty')

        def delayed():
            self.advance(60)

        last = self.attempt(build=delayed)
        self.assertEqual(last.outcome, 'timeout')
        self.assertEqual(last.elapsed_s, 60)
        # Five earlier rows expire, but the just-finished failure still costs one.
        for _ in range(5):
            self.assertEqual(self.attempt().outcome, 'empty')
        self.advance(59.999)
        self.assertEqual(self.attempt().reason, 'engine_rate')
        self.advance(0.001)
        self.assertEqual(self.attempt().outcome, 'empty')

    def test_domestic_thirty_thirtyfirst_and_exact_window_across_aliases(self):
        root = Path(self.parent.name) / 'domestic-matrix'
        base = next(entry for entry in self.engines if entry['engine'] == 'chinaso news')
        engines = []
        for number in range(6):
            name = f'fixture-domestic-{number}'
            engines.append({**base, 'engine': name, 'aliases': [name, f'{name}-alias']})
        self.api.initialize_fixture(root, registry=engines, clock=lambda: dict(self.now))
        manifest = fixture_manifest(root, engines)
        calls = []

        def attempt(name, caller='probe'):
            store = self.api.open_store(root, manifest=manifest, mode='synthetic')
            assert not isinstance(store, self.api.Refusal)
            return store.run_engine(
                name,
                caller=caller,
                deadline_mono=self.now['mono'] + 3,
                build=lambda: calls.append(name),
                send=lambda context, request: None,
                parse=lambda response: [],
            )

        for number in range(5):
            for ordinal in range(6):
                name = f'fixture-domestic-{number}' + ('-alias' if ordinal % 2 else '')
                self.assertEqual(attempt(name, 'probe' if ordinal % 2 else 'native_search').outcome, 'empty')
        self.assertEqual(len(calls), 30)
        self.assertEqual(attempt('fixture-domestic-0-alias').reason, 'engine_rate')
        self.assertEqual(attempt('fixture-domestic-5-alias').reason, 'domestic_rate')
        self.assertEqual(len(calls), 30)
        self.advance(59.999)
        self.assertEqual(attempt('fixture-domestic-5').reason, 'domestic_rate')
        self.assertEqual(len(calls), 30)
        self.advance(0.001)
        self.assertEqual(attempt('fixture-domestic-5-alias').outcome, 'empty')
        self.assertEqual(len(calls), 31)
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM attempts').fetchone()[0], 31)
            self.assertEqual(
                db.execute(
                    'SELECT engine,stamp,account_mono FROM attempts ORDER BY attempt_id DESC LIMIT 1'
                ).fetchone(),
                ('fixture-domestic-5', 160.0, 160.0),
            )

    def test_invalid_current_clock_persists_poison_before_any_callback(self):
        invalid = [
            ('wall', float('nan')),
            ('wall', float('inf')),
            ('wall', -1.0),
            ('wall', True),
            ('mono', float('nan')),
            ('mono', float('inf')),
            ('mono', -1.0),
            ('mono', True),
            ('wall', 9999.0),
            ('mono', 99.0),
            ('wall', 10002.001),
            ('mono', 102.001),
        ]
        for number, (field, value) in enumerate(invalid):
            with self.subTest(field=field, value=value):
                self.now.update(wall=10000.0, mono=100.0)
                root = Path(self.parent.name) / f'invalid-clock-{number}'
                self.api.initialize_fixture(root, registry=self.engines, clock=lambda: dict(self.now))
                manifest = fixture_manifest(root, self.engines)
                store = self.api.open_store(root, manifest=manifest, mode='synthetic')
                assert not isinstance(store, self.api.Refusal)
                calls = []
                self.now[field] = value
                result = store.run_engine(
                    'bing',
                    caller='probe',
                    deadline_mono=103.0,
                    build=lambda calls=calls: calls.append('build'),
                    send=lambda context, request, calls=calls: calls.append('send'),
                    parse=lambda response, calls=calls: calls.append('parse') or [],
                )
                self.assertEqual(getattr(result, 'reason', None), 'clock_error')
                self.assertEqual(calls, [])
                self.now.update(wall=10000.0, mono=100.0)
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [('clock_error',)])
                    self.assertEqual(db.execute('SELECT count(*) FROM attempts').fetchone()[0], 0)
                snapshot_store = self.api.open_store(root, manifest=manifest, mode='synthetic')
                assert not isinstance(snapshot_store, self.api.Refusal)
                snapshot = snapshot_store.public_snapshot(manifest['artifact_digest'], manifest['config_digest'])
                assert isinstance(snapshot, self.api.Refusal)
                self.assertEqual(snapshot.reason, 'clock_error')

    def test_changed_boot_poison_does_not_expire_or_refund_charge(self):
        self.assertEqual(self.attempt().outcome, 'empty')
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            previous = dict(self.now, boot='synthetic-previous-boot')
            db.execute('UPDATE state SET checkpoint=?', (canonical(previous).decode(),))
        calls = []
        self.assertEqual(self.attempt('quark', build=lambda: calls.append('build')).reason, 'clock_error')
        self.assertEqual(calls, [])
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [('clock_error',)])
            self.assertEqual(
                db.execute('SELECT engine,outcome,account_mono FROM attempts').fetchall(), [('bing', 'empty', 100.0)]
            )
            # Repairing the raw checkpoint cannot silently clear the poison.
            db.execute('UPDATE state SET checkpoint=?', (canonical(self.now).decode(),))
        self.advance(3600)
        self.assertEqual(self.attempt('quark', build=lambda: calls.append('build')).reason, 'clock_error')
        self.assertEqual(calls, [])

    def test_parser_failure_and_empty_keep_captcha_strikes_across_reopen(self):
        def challenged(response):
            raise self.api.EngineFailure('captcha', suspension_s=900)

        for strikes, pause in [(1, 1800), (2, 3600), (3, 7200)]:
            result = self.attempt('quark', parse=challenged)
            self.assertEqual(result.outcome, 'captcha')
            self.assertEqual(self.attempt('quark').reason, 'cooldown')
            self.advance(pause)
            self.assertEqual(self.attempt('quark').outcome, 'empty')

            def broken(response):
                raise ValueError('synthetic parser error')

            self.assertEqual(self.attempt('quark', parse=broken).outcome, 'parser_error')
            with sqlite3.connect(self.root / 'ledger.sqlite') as db:
                self.assertEqual(
                    db.execute('SELECT strikes FROM pauses WHERE engine=?', ('quark',)).fetchone()[0], strikes
                )
        self.assertEqual(self.attempt('quark', parse=lambda response: [{'title': 'synthetic'}]).outcome, 'ok')
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM pauses').fetchone()[0], 0)

    def test_unfinished_row_blocks_other_engine_without_refund(self):
        self.assertEqual(self.attempt().outcome, 'empty')
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            db.execute('UPDATE attempts SET outcome=NULL,finished_mono=NULL')
        self.assertEqual(self.attempt('yandex').reason, 'unfinished_attempt')
        self.advance(3600)
        self.assertEqual(self.attempt('yandex').reason, 'unfinished_attempt')

    def test_inherited_dispatch_refuses_without_writing_or_closing_reused_fd(self):
        script = '''
import json
import os
from pathlib import Path
import sys
import time
def deny_socket(event, args):
    if event.startswith('socket.'):
        raise AssertionError('core child denied socket operation')
sys.addaudithook(deny_socket)
import wag_protection
root = Path(sys.argv[1])
manifest = json.loads(sys.argv[2])
time.time = lambda: 10000.0
time.monotonic = lambda: 100.0
owner = os.getpid()
store = wag_protection.open_store(root, manifest=manifest, mode='synthetic')
reused = None
def build():
    global reused
    child = os.fork()
    if child == 0:
        reused = os.open(os.devnull, os.O_RDONLY)
        return
    _, status = os.waitpid(child, 0)
    assert status == 0
result = store.run_engine('bing', caller='probe', deadline_mono=103.0,
                          build=build, send=lambda context, request: None, parse=lambda response: [])
if os.getpid() != owner:
    os.fstat(reused)
    fresh = wag_protection.open_store(root, manifest=manifest, mode='synthetic')
    print(json.dumps({'child_reason': getattr(result, 'reason', None),
                      'fresh_reason': getattr(fresh, 'reason', None), 'reused_fd_open': True}), flush=True)
    os._exit(0)
print(json.dumps({'parent_outcome': result.outcome}), flush=True)
'''
        process = subprocess.run(
            [sys.executable, '-S', '-c', script, str(self.root), json.dumps(self.manifest)],
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        records = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(
            records,
            [
                {'child_reason': 'capability_refused', 'fresh_reason': 'lock_busy', 'reused_fd_open': True},
                {'parent_outcome': 'empty'},
            ],
        )
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT engine,outcome FROM attempts').fetchall(), [('bing', 'empty')])
            self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [])

    def test_owner_death_does_not_leave_flock_in_forked_child(self):
        script = '''
import json
import os
from pathlib import Path
import sys
import time
def deny_socket(event, args):
    if event.startswith('socket.'):
        raise AssertionError('core child denied socket operation')
sys.addaudithook(deny_socket)
import wag_protection
root = Path(sys.argv[1])
manifest = json.loads(sys.argv[2])
time.time = lambda: 10000.0
time.monotonic = lambda: 100.0
store = wag_protection.open_store(root, manifest=manifest, mode='synthetic')
def build():
    child = os.fork()
    if child == 0:
        os.read(0, 1)
        os._exit(0)
    print(child, flush=True)
    os.read(0, 1)
store.run_engine('bing', caller='probe', deadline_mono=103.0,
                 build=build, send=lambda context, request: None, parse=lambda response: [])
'''
        # The finally block explicitly terminates/reaps this fault-injection child and its pipes.
        process = subprocess.Popen(  # pylint: disable=consider-using-with
            [sys.executable, '-S', '-c', script, str(self.root), json.dumps(self.manifest)],
            cwd=WORKSPACE,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        child = None
        try:
            import select

            assert process.stdout is not None
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'owner never entered build')
            child = int(process.stdout.readline())
            self.assertEqual(getattr(self.open(), 'reason', None), 'lock_busy')
            process.kill()
            process.wait(timeout=5)
            # Child still exists and has not been told to exit. The old lock FD
            # must already be revoked, while the parent's committed NULL survives.
            os.kill(child, 0)
            self.assertNotEqual(getattr(self.open(), 'reason', None), 'lock_busy')
            calls = []
            self.assertEqual(self.attempt('quark', build=lambda: calls.append('build')).reason, 'unfinished_attempt')
            self.assertEqual(calls, [])
            with sqlite3.connect(self.root / 'ledger.sqlite') as db:
                self.assertEqual(db.execute('SELECT engine,outcome FROM attempts').fetchall(), [('bing', None)])
        finally:
            if child is not None:
                try:
                    os.kill(child, 9)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_release_receipt_unlocks_before_one_ingress_and_cannot_replay(self):
        store = self.open()
        assert not isinstance(store, self.api.Refusal)
        release_id = '1' * 32
        artifact, config = self.manifest['artifact_digest'], self.manifest['config_digest']
        receipt = store.claim_release(release_id, artifact, config, self.now['mono'] + 10)
        calls = []

        def operation():
            calls.append('operation')
            ingress_store = self.open()
            assert not isinstance(ingress_store, self.api.Refusal)
            self.assertEqual(ingress_store.consume_release_ingress(release_id, artifact, config), True)
            ingress_store = self.open()
            assert not isinstance(ingress_store, self.api.Refusal)
            refused = ingress_store.consume_release_ingress(release_id, artifact, config)
            assert isinstance(refused, self.api.Refusal)
            self.assertEqual(refused.reason, 'release_consumed')
            return {
                'version': 2,
                'release_id': release_id,
                'artifact_digest': artifact,
                'config_digest': config,
                'checked_at': '1970-01-01T02:46:40+00:00',
                'age_s': 0,
                'search': {
                    'status': 'passed',
                    'result_count': 2,
                    'responsive_engine_count': 2,
                    'protection_status': 'complete',
                    'quality_evidence_digest': 'b' * 64,
                    'reason': None,
                },
                'egress': {'status': 'passed', 'reason': None},
            }

        evidence = store.run_release_check(receipt, operation)
        self.assertEqual(evidence['search']['status'], 'passed')
        refused = store.run_release_check(receipt, operation)
        assert isinstance(refused, self.api.Refusal)
        self.assertEqual(refused.reason, 'release_consumed')
        release_store = self.open()
        assert not isinstance(release_store, self.api.Refusal)
        refused = release_store.claim_release(release_id, artifact, config, self.now['mono'] + 10)
        assert isinstance(refused, self.api.Refusal)
        self.assertEqual(refused.reason, 'release_consumed')
        self.assertEqual(calls, ['operation'])
        snapshot_store = self.open()
        assert not isinstance(snapshot_store, self.api.Refusal)
        snapshot = snapshot_store.public_snapshot(artifact, config)
        assert not isinstance(snapshot, self.api.Refusal)
        self.assertEqual(snapshot['age_s'], 0)
        self.advance(60.001)
        snapshot_store = self.open()
        assert not isinstance(snapshot_store, self.api.Refusal)
        snapshot = snapshot_store.public_snapshot(artifact, config)
        assert isinstance(snapshot, self.api.Refusal)
        self.assertEqual(snapshot.reason, 'evidence_unknown')

    def test_release_operation_crash_consumes_claim_permanently(self):
        store = self.open()
        assert not isinstance(store, self.api.Refusal)
        artifact, config = self.manifest['artifact_digest'], self.manifest['config_digest']
        release_id = '2' * 32
        receipt = store.claim_release(release_id, artifact, config, self.now['mono'] + 10)

        def operation():
            ingress_store = self.open()
            assert not isinstance(ingress_store, self.api.Refusal)
            self.assertEqual(ingress_store.consume_release_ingress(release_id, artifact, config), True)
            raise ValueError('synthetic operation failure')

        refused = store.run_release_check(receipt, operation)
        assert isinstance(refused, self.api.Refusal)
        self.assertEqual(refused.reason, 'evidence_unknown')
        ingress_store = self.open()
        assert not isinstance(ingress_store, self.api.Refusal)
        refused = ingress_store.consume_release_ingress(release_id, artifact, config)
        assert isinstance(refused, self.api.Refusal)
        self.assertEqual(refused.reason, 'release_consumed')
        snapshot_store = self.open()
        assert not isinstance(snapshot_store, self.api.Refusal)
        snapshot = snapshot_store.public_snapshot(artifact, config)
        assert isinstance(snapshot, self.api.Refusal)
        self.assertEqual(snapshot.reason, 'evidence_unknown')
        ingress_store = self.open()
        assert not isinstance(ingress_store, self.api.Refusal)
        refused = ingress_store.consume_release_ingress('3' * 32, artifact, config)
        assert isinstance(refused, self.api.Refusal)
        self.assertEqual(refused.reason, 'release_consumed')

    def test_missing_store_never_creates_state(self):
        root = Path(self.parent.name) / 'missing'
        manifest = {**self.manifest, 'root': str(root)}
        result = self.api.open_store(root, manifest=manifest, mode='synthetic')
        assert isinstance(result, self.api.Refusal)
        self.assertEqual(result.reason, 'identity_error')
        self.assertFalse(root.exists())

    def test_raw_enabled_is_strict_before_coercion(self):
        self.assertEqual(self.api.validate_settings({'enabled': False}), {'enabled': False})
        for value in ['false', 'true', 0, 1, None, [], {}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.api.validate_settings({'enabled': value})
        with self.assertRaises(ValueError):
            self.api.validate_settings({'enabled': False, 'enable': True})

    def test_manifest_missing_native_artifact_refuses_before_storage(self):
        from wag_protection.contract import ARTIFACT_FIELDS

        for missing in ('searx/network/network.py', 'searx/data/engine_traits.json'):
            with self.subTest(missing=missing):
                manifest = {**self.manifest, 'files': dict(self.manifest['files'])}
                del manifest['files'][missing]
                manifest['artifact_digest'] = digest({key: manifest[key] for key in ARTIFACT_FIELDS})
                before = {path.name: path.read_bytes() for path in self.root.iterdir() if path.is_file()}
                refused = self.api.open_store(self.root, manifest=manifest, mode='synthetic')
                self.assertIsInstance(refused, self.api.Refusal)
                self.assertEqual(refused.reason, 'provenance_error')
                self.assertEqual(
                    before, {path.name: path.read_bytes() for path in self.root.iterdir() if path.is_file()}
                )

    def test_manifest_unbacked_wheel_hash_refuses_before_storage(self):
        manifest = {**self.manifest, 'wheels': {'httpx-0.28.1-py3-none-any.whl': 'a' * 64}}
        from wag_protection.contract import ARTIFACT_FIELDS

        manifest['artifact_digest'] = digest({key: manifest[key] for key in ARTIFACT_FIELDS})
        before = {path.name: path.read_bytes() for path in self.root.iterdir() if path.is_file()}
        refused = self.api.open_store(self.root, manifest=manifest, mode='synthetic')
        self.assertIsInstance(refused, self.api.Refusal)
        self.assertEqual(refused.reason, 'provenance_error')
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.root.iterdir() if path.is_file()})

    def test_manifest_unknown_field_and_shadow_file_refuse_before_build(self):
        assert isinstance(self.manifest['files'], Mapping)
        for manifest in [
            {**self.manifest, 'surprise': True},
            {**self.manifest, 'files': {**self.manifest['files'], '../shadow.py': 'b' * 64}},
            {**self.manifest, 'python_digest': '0' * 64},
        ]:
            with self.subTest(manifest=list(manifest)):
                refused = self.api.open_store(self.root, manifest=manifest, mode='synthetic')
                assert isinstance(refused, self.api.Refusal)
                self.assertEqual(refused.reason, 'provenance_error')


def _install_offline_test_guard():
    import atexit
    import ipaddress
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    original_socket = socket.socket
    original_resolve = socket.getaddrinfo

    def loopback(host):
        try:
            return host == 'localhost' or ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def permitted(address, family):
        if family == socket.AF_UNIX and isinstance(address, str):
            return Path(address).resolve().is_relative_to(Path(os.environ['TMPDIR']).resolve())
        return isinstance(address, tuple) and loopback(address[0])

    # Inference cannot follow this captured real socket type after the constructor is patched.
    class LoopbackSocket(original_socket):
        def connect(self, address):
            if not permitted(address, self.family):
                raise AssertionError('offline test denied nonloopback connect')
            return super().connect(address)  # pylint: disable=no-member

        def connect_ex(self, address):
            if not permitted(address, self.family):
                raise AssertionError('offline test denied nonloopback connect')
            return super().connect_ex(address)  # pylint: disable=no-member

    def resolve(host, *args, **kwargs):
        if not loopback(host):
            raise AssertionError('offline test denied external DNS')
        return original_resolve(host, *args, **kwargs)

    def unexpected_skip(self, test, reason):
        raise AssertionError(f'unexpected offline test skip: {test.id()}: {reason}')

    socket.socket = LoopbackSocket
    socket.getaddrinfo = resolve
    unittest.TestResult.addSkip = unexpected_skip
    os.environ['SEARXNG_SETTINGS_PATH'] = str(WORKSPACE / 'tests/unit/settings/test_settings.yml')
    os.environ['SEARXNG_DISABLE_ETC_SETTINGS'] = '1'

    from searx.data.tracker_patterns import TrackerPatternsDB

    class RulesHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"providers":{}}'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # Preserve BaseHTTPRequestHandler's override contract, including its parameter name.
        def log_message(self, format, *args):  # pylint: disable=redefined-builtin
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), RulesHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    previous_urls = TrackerPatternsDB.CLEAR_LIST_URL
    TrackerPatternsDB.CLEAR_LIST_URL = [f'http://127.0.0.1:{server.server_port}/synthetic-rules']

    def close():
        TrackerPatternsDB.CLEAR_LIST_URL = previous_urls
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    atexit.register(close)


def _offline_test_main(arguments):
    # The namespace also blocks non-Python descendants; the socket guard gives
    # immediate, readable refusals rather than waiting on unreachable hosts.
    if {name for _, name in socket.if_nameindex()} != {'lo'}:
        raise RuntimeError('offline test entry requires a loopback-only network namespace')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    tmp = Path(os.environ['TMPDIR']).resolve()
    if tmp != WORKSPACE / 'local/tmp':
        raise RuntimeError('offline tests require the owning local/tmp')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=WORKSPACE, text=True).strip()
    expected = os.environ.get('WAG_EXPECTED_HEAD')
    if expected is not None:
        if head != expected:
            raise RuntimeError('offline gate checkout does not match expected HEAD')
        subprocess.run(['git', 'diff', '--exit-code', 'HEAD'], cwd=WORKSPACE, check=True)
    print(f'offline_head={head}', flush=True)

    if arguments[0] == '--make':
        allowed = {
            'test.unit',
            'ci.test',
            'test.pylint',
            'test.rst',
            'test.pybabel',
            'test.shell',
            'test.shfmt',
            'test.pyright_modified',
        }
        if len(arguments) != 2 or arguments[1] not in allowed:
            raise ValueError('unsupported offline Make target')
        with tempfile.TemporaryDirectory(dir=tmp) as directory:
            Path(directory, 'sitecustomize.py').symlink_to(Path(__file__).resolve())
            env = {
                **os.environ,
                'WAG_TEST_OFFLINE': '1',
                'PYTHONPATH': os.pathsep.join((directory, str(WORKSPACE))),
                'PY_ENV': str(Path(sys.executable).parent.parent),
                'PY_ENV_REQ': 'requirements.txt requirements-dev.txt',
            }
            return subprocess.run(['make', 'V=1', arguments[1]], cwd=WORKSPACE, env=env, check=False).returncode

    if arguments != ['--offline']:
        raise ValueError('unsupported offline test arguments')
    _install_offline_test_guard()
    import importlib.metadata

    paths = subprocess.check_output(
        [
            'git',
            'ls-files',
            '-z',
            'wag_protection',
            'searx',
            'tests',
            'setup.py',
            'requirements*',
            '.github/workflows/integration.yml',
        ],
        cwd=WORKSPACE,
    )
    source = {
        name: hashlib.sha256((WORKSPACE / name).read_bytes()).hexdigest()
        for name in paths.decode().split('\0')
        if name and (WORKSPACE / name).is_file()
    }
    dependencies = {}
    for distribution in importlib.metadata.distributions():
        files = {}
        for file in distribution.files or ():
            path = Path(str(distribution.locate_file(file)))
            if path.is_file() and path.suffix != '.pyc':
                files[str(file)] = hashlib.sha256(path.read_bytes()).hexdigest()
        dependencies[distribution.metadata['Name']] = {'version': distribution.version, 'files_digest': digest(files)}
    print(
        'offline_artifact=' + canonical({'head': head, 'source': source, 'dependencies': dependencies}).decode(),
        flush=True,
    )

    positive = (
        'tests.unit.network.test_protected.ProtectedTransportTest.'
        'test_native_search_two_engines_same_query_complete_nonempty'
    )

    class OfflineResult(unittest.TextTestResult):
        native_headers = 0

        def addSuccess(self, test):
            super().addSuccess(test)
            if test.id() == positive:
                self.native_headers += test.tls_server.headers

    names = [
        'tests.unit.test_wag_protection',
        'tests.unit.network.test_protected',
        'tests.unit.network.test_network',
        'tests.unit.test_search',
        'tests.unit.test_results',
        'tests.unit.test_webutils',
        'tests.unit.test_webapp',
    ]
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    result = unittest.TextTestRunner(verbosity=2, resultclass=OfflineResult).run(suite)
    print(
        f'offline_tests={result.testsRun} native_positive_headers={result.native_headers} '
        f'unexpected_skips={len(result.skipped)}',
        flush=True,
    )
    return (
        0 if result.wasSuccessful() and result.testsRun > 0 and result.native_headers > 0 and not result.skipped else 1
    )


if __name__ == 'sitecustomize' and os.environ.get('WAG_TEST_OFFLINE') == '1':
    _install_offline_test_guard()
elif __name__ == '__main__':
    if sys.argv[1:2] in (['--offline'], ['--make']):
        sys.exit(_offline_test_main(sys.argv[1:]))
    unittest.main()
