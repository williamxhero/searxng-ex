# SPDX-License-Identifier: AGPL-3.0-or-later
# Match the repository test convention without renaming externally selected test IDs.
# pylint: disable=missing-class-docstring,invalid-name
# Lazy imports keep native settings/network side effects inside prepared fixtures.
# pylint: disable=import-outside-toplevel
"""Real native transport/parser components, on explicit synthetic loopback state."""

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.unit.test_wag_protection import fixture_manifest, registry, WORKSPACE


QUARK_RESULT = (
    '<script type="application/json" id="s-data-fixture" data-used-by="hydrate">'
    + json.dumps(
        {
            'data': {
                'initialData': {
                    'title': {'content': 'Synthetic source'},
                    'source': {'url': 'https://fixture.invalid/source'},
                    'summary': {'content': 'Offline parser result'},
                }
            },
            'extraData': {'sc': 'addition'},
        }
    )
    + '</script>'
).encode()


BING_RESULT = (
    b'<ol id="b_results"><li class="b_algo"><h2>'
    b'<a href="https://bing-fixture.invalid/source">Bing synthetic</a></h2>'
    b'<p>Offline source</p></li></ol>'
)
YANDEX_RESULT = (
    b'<li class="serp-item"><h3 class="b-serp-item__title">'
    b'<a class="b-serp-item__title-link" href="https://yandex-fixture.invalid/source">'
    b'<span>Yandex synthetic</span></a></h3><div class="b-serp-item__content">'
    b'<div class="b-serp-item__text">Offline source</div></div></li>'
)
CHINASO_RESULT = json.dumps(
    {
        'data': {
            'data': [
                {
                    'title': 'ChinaSo synthetic',
                    'url': 'https://chinaso-fixture.invalid/source',
                    'snippet': 'Offline source',
                }
            ]
        }
    }
).encode()
HOSTS = ('quark.sm.cn', 'www.chinaso.com', 'www.bing.com', 'yandex.com')


class CountedServer(ThreadingHTTPServer):
    """Loopback server exposing actual accepted connections and request headers."""

    daemon_threads = True
    tunnel_port: int | None

    def __init__(self):
        super().__init__(('127.0.0.1', 0), FixtureHandler)
        self.accepts = 0
        self.headers = 0
        self.connect_headers = 0
        self.responses = {}
        self.tunnel_port = None
        self.request_entered = threading.Event()
        self.body_release = threading.Event()
        self.body_release.set()

    def get_request(self):
        connection = super().get_request()
        self.accepts += 1
        return connection


class FixtureHandler(BaseHTTPRequestHandler):
    """Real HTTP GET and CONNECT framing for the counted loopback fixture."""

    server: CountedServer
    close_connection: bool  # Initialized by BaseHTTPRequestHandler, also used for CONNECT.
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.server.headers += 1
        self.server.request_entered.set()
        if not self.server.body_release.wait(10):
            return
        host = self.headers.get('Host', '').split(':')[0]
        content = {'www.bing.com': BING_RESULT, 'www.chinaso.com': CHINASO_RESULT, 'yandex.com': YANDEX_RESULT}.get(
            host, QUARK_RESULT
        )
        status, headers, content = self.server.responses.get(host, (200, {}, content))
        # Do not prepend BaseHTTPServer's Server header to a native CF fixture.
        self.send_response_only(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_CONNECT(self):
        self.server.connect_headers += 1
        if self.path.split(':')[0] not in HOSTS or self.server.tunnel_port is None:
            self.send_error(403)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.flush()
        upstream = socket.create_connection(('127.0.0.1', self.server.tunnel_port))
        try:
            while True:
                ready, _, _ = select.select([self.connection, upstream], [], [], 3)
                if not ready:
                    return
                for sender in ready:
                    data = sender.recv(65536)
                    if not data:
                        return
                    (upstream if sender is self.connection else self.connection).sendall(data)
        finally:
            upstream.close()
            self.close_connection = True

    # Preserve BaseHTTPRequestHandler's override contract, including its parameter name.
    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        pass


# One loopback/socket-safety fixture serves all native transport contract tests.
class ProtectedTransportTest(unittest.TestCase):  # pylint: disable=too-many-public-methods
    tls_server: CountedServer

    def setUp(self):
        original_socket = socket.socket
        original_resolve = socket.getaddrinfo
        self.client_sockets = []

        client_sockets = self.client_sockets

        class OnlyLoopbackSocket(original_socket):
            """Retain real socket operations while rejecting nonloopback destinations."""

            def connect(self, address):
                if isinstance(address, tuple) and not ipaddress.ip_address(address[0]).is_loopback:
                    raise AssertionError('nonloopback socket denied')
                client_sockets.append((self, address))
                return super().connect(address)

            def connect_ex(self, address):
                if isinstance(address, tuple) and not ipaddress.ip_address(address[0]).is_loopback:
                    raise AssertionError('nonloopback socket denied')
                client_sockets.append((self, address))
                return super().connect_ex(address)

        def only_loopback_resolve(host, *args, **kwargs):
            if host in HOSTS and hasattr(self, 'tls_server'):
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        socket.IPPROTO_TCP,
                        '',
                        ('127.0.0.1', self.tls_server.server_port),
                    )
                ]
            if not ipaddress.ip_address(host).is_loopback:
                raise AssertionError('nonloopback DNS denied')
            return original_resolve(host, *args, **kwargs)

        for target, replacement in [
            ('socket.socket', OnlyLoopbackSocket),
            ('socket.getaddrinfo', only_loopback_resolve),
        ]:
            guard = patch(target, replacement)
            guard.start()
            self.addCleanup(guard.stop)
        settings = patch.dict(
            os.environ,
            {
                'SEARXNG_SETTINGS_PATH': str(WORKSPACE / 'tests/unit/settings/test_settings.yml'),
                'SEARXNG_DISABLE_ETC_SETTINGS': '1',
            },
        )
        settings.start()
        self.addCleanup(settings.stop)
        # addCleanup owns this directory even if the rest of setUp fails.
        self.parent = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])  # pylint: disable=consider-using-with
        self.addCleanup(self.parent.cleanup)
        self.root = Path(self.parent.name) / 'native-synthetic'
        import wag_protection

        self.api = wag_protection
        self.api.initialize_fixture(
            self.root,
            registry=registry(),
            clock=lambda: {
                'wall': time.time(),
                'mono': time.monotonic(),
                'boot': Path('/proc/sys/kernel/random/boot_id').read_text(encoding='utf-8').strip(),
            },
        )
        self.manifest = fixture_manifest(self.root, registry())
        self.store = self.api.open_store(self.root, manifest=self.manifest, mode='synthetic')
        self.server = CountedServer()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def test_validated_store_uses_approved_production_mode(self):
        from searx.network import protected

        manifest_path = Path(self.parent.name) / 'production-artifact.json'
        manifest_path.write_text(json.dumps({'mode': 'production'}), encoding='utf-8')
        store = SimpleNamespace(manifest={'config_digest': 'resolved'})
        config = {'artifact_manifest': str(manifest_path), 'root': str(self.root)}
        with (
            patch.object(protected, 'open_store', return_value=store) as open_store,
            patch.object(protected, 'resolved_config_digest', return_value='resolved'),
        ):
            self.assertIs(protected._validated_store(config, {}), store)
        open_store.assert_called_once_with(str(self.root), manifest={'mode': 'production'}, mode='production')

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def tls_fixture(self):
        parent = Path(self.parent.name)
        cert, key = parent / 'synthetic-cert.pem', parent / 'synthetic-key.pem'
        subprocess.run(
            [
                'openssl',
                'req',
                '-x509',
                '-newkey',
                'rsa:2048',
                '-nodes',
                '-keyout',
                str(key),
                '-out',
                str(cert),
                '-days',
                '1',
                '-subj',
                '/CN=quark.sm.cn',
                '-addext',
                'subjectAltName=' + ','.join('DNS:' + name for name in HOSTS) + ',IP:127.0.0.1',
            ],
            capture_output=True,
            check=True,
        )
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        self.tls_server = CountedServer()
        self.tls_server.socket = server_context.wrap_socket(self.tls_server.socket, server_side=True)
        thread = threading.Thread(target=self.tls_server.serve_forever, daemon=True)
        thread.start()

        def stop():
            self.tls_server.shutdown()
            self.tls_server.server_close()
            thread.join()

        self.addCleanup(stop)
        return ssl.create_default_context(cafile=str(cert))

    def engine_request(self, name):
        from searx.engines import load_engine

        engines = {
            'quark': {'quark_category': 'general', 'categories': ['general']},
            'chinaso news': {'chinaso_news_source': 'all', 'categories': ['news']},
            'bing': {'language_support': True, 'categories': ['general']},
            'yandex': {'search_type': 'web', 'categories': ['general']},
        }
        module = next(entry['module'] for entry in registry() if entry['engine'] == name)
        engine = load_engine({'name': name, 'engine': module, **engines[name]})
        self.assertIsNotNone(engine)
        params = {
            'pageno': 1,
            'time_range': None,
            'searxng_locale': 'en-US',
            'language': 'en-US',
            'safesearch': 0,
            'headers': {},
            'cookies': {},
        }
        engine.request('offline synthetic query', params)
        self.assertTrue(params['url'])
        return engine, params

    def parsed_request(self, name, *, verify, proxy=None):
        import httpx
        from searx.network.client import get_loop
        from searx.network.protected import GuardedTransport

        engine, params = self.engine_request(name)

        async def request():
            async with httpx.AsyncClient(
                transport=GuardedTransport(verify=verify, proxy=proxy), trust_env=False
            ) as client:
                response = await client.get(
                    params['url'], headers=params['headers'], cookies=params['cookies'], follow_redirects=False
                )
                response.search_params = params
                return response

        return self.store.run_engine(
            name,
            caller='native_search',
            deadline_mono=time.monotonic() + 3,
            build=lambda: params,
            send=lambda context, request_params: context.run_async(request, get_loop()),
            parse=engine.response,
        )

    # Settings, artifact provenance and loopback trust must be prepared and restored as one fixture.
    # pylint: disable-next=too-many-locals
    def native_search_fixture(self, *, include_yandex=False):
        from copy import deepcopy
        from searx import settings
        import searx.search
        from searx.network import THREADLOCAL
        from searx.network.network import NETWORKS, done
        from searx.search.models import EngineRef, SearchQuery
        from searx.network.protected import resolved_config_digest

        previous_networks = dict(NETWORKS)
        previous_thread_context = dict(THREADLOCAL.__dict__)

        def restore_network_context():
            NETWORKS.clear()
            NETWORKS.update(previous_networks)
            THREADLOCAL.__dict__.clear()
            THREADLOCAL.__dict__.update(previous_thread_context)

        self.addCleanup(restore_network_context)
        self.tls_fixture()
        engine_settings = [
            {
                'name': 'bing',
                'engine': 'bing',
                'categories': ['general'],
                'shortcut': 'bi',
                'timeout': 3.0,
                'language_support': True,
            },
            {
                'name': 'quark',
                'engine': 'quark',
                'categories': ['general'],
                'shortcut': 'qk',
                'timeout': 3.0,
                'quark_category': 'general',
            },
        ]
        if include_yandex:
            engine_settings.append(
                {
                    'name': 'yandex',
                    'engine': 'yandex',
                    'categories': ['general'],
                    'shortcut': 'ya',
                    'timeout': 3.0,
                    'search_type': 'web',
                }
            )
        approved = registry()
        for entry in approved:
            configured = next((engine for engine in engine_settings if engine['name'] == entry['engine']), None)
            if configured:
                entry['profile']['settings'] = {
                    key: value for key, value in configured.items() if key not in ('name', 'engine')
                }
        root = Path(self.parent.name) / 'same-query-native'
        self.api.initialize_fixture(
            root,
            registry=approved,
            clock=lambda: {
                'wall': time.time(),
                'mono': time.monotonic(),
                'boot': Path('/proc/sys/kernel/random/boot_id').read_text(encoding='utf-8').strip(),
            },
        )
        outgoing = deepcopy(settings['outgoing'])
        outgoing.update(
            {
                'verify': str(Path(self.parent.name) / 'synthetic-cert.pem'),
                'proxies': {},
                'source_ips': [],
                'using_tor_proxy': False,
                'request_timeout': 3.0,
                'max_request_timeout': 3.0,
            }
        )
        manifest = fixture_manifest(root, approved)
        manifest['config_digest'] = resolved_config_digest(engine_settings, outgoing)
        manifest_path = Path(self.parent.name) / 'native-artifact.json'
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        outgoing['wag_protection'] = {'enabled': True, 'root': str(root), 'artifact_manifest': str(manifest_path)}
        config = patch.dict(settings, {'engines': engine_settings, 'outgoing': outgoing})
        config.start()
        self.addCleanup(config.stop)
        self.addCleanup(done)
        searx.search.initialize(engine_settings, enable_metrics=False)
        query = SearchQuery(
            'offline synthetic query',
            [EngineRef('quark', 'general'), EngineRef('bing', 'general')],
            'en-US',
            0,
            1,
            None,
            3.0,
        )
        return searx.search.Search(query), root, manifest

    def test_missing_dependency_metadata_refuses_config_without_send(self):
        from searx import settings
        from tests.unit.test_wag_protection import digest
        import searx.webapp

        _, root, manifest = self.native_search_fixture()
        manifest['distributions']['wag-spec103-nonexistent-fixture'] = '0.0.0'
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
        Path(settings['outgoing']['wag_protection']['artifact_manifest']).write_text(
            json.dumps(manifest), encoding='utf-8'
        )
        before = (root / 'ledger.sqlite').read_bytes()
        self.assertEqual(self.api.open_store(root, manifest=manifest, mode='synthetic').reason, 'provenance_error')
        response = searx.webapp.app.test_client().get('/config')
        self.assertEqual(response.status_code, 200)
        descriptor = response.get_json()['outbound_protection']
        self.assertEqual((descriptor['admission'], descriptor['reason']), ('blocked', 'provenance_error'))
        self.assertEqual((root / 'ledger.sqlite').read_bytes(), before)
        self.assertEqual(self.tls_server.headers, 0)

    def test_transport_rejects_incompatible_dependency_versions_before_connect(self):
        import httpcore
        import httpx
        from searx.network.protected import GuardedTransport

        for module, version in ((httpcore, '1.0.8'), (httpx, '0.27.2')):
            with self.subTest(module=module.__name__), patch.object(module, '__version__', version):
                with self.assertRaises(self.api.ProtectionError) as error:
                    GuardedTransport()
                self.assertEqual(error.exception.reason, 'import_error')
        self.assertEqual(self.server.accepts, 0)
        self.assertEqual(self.server.headers, 0)

    def test_native_finalrefs_unsupported_skip_and_native_suspension(self):
        from flask import Flask
        from searx.search import Search
        from searx.search.processors import PROCESSORS

        search, _, _ = self.native_search_fixture()
        search.search_query.pageno = 100000
        with Flask('protected-skips').test_request_context('/search'):
            search.search()
        snapshot = search.outbound_protection
        self.assertEqual((snapshot['status'], snapshot['retryable']), ('complete', True))
        self.assertEqual([ref['status'] for ref in snapshot['engines']], ['skipped', 'admitted'])
        self.assertIsNone(snapshot['engines'][0]['reason'])
        self.assertEqual(snapshot['engines'][0]['reservations'], 0)
        self.assertEqual(self.tls_server.headers, 1)
        search.search_query.pageno = 1
        processor = PROCESSORS['quark']
        processor.suspended_status.suspend(60, 'synthetic native suspension')
        self.addCleanup(processor.suspended_status.resume)
        next_search = Search(search.search_query)
        with Flask('protected-suspended').test_request_context('/search'):
            next_search.search()
        snapshot = next_search.outbound_protection
        self.assertEqual(snapshot['status'], 'partial')
        self.assertEqual((snapshot['engines'][1]['status'], snapshot['engines'][1]['reason']), ('refused', 'cooldown'))
        self.assertEqual(snapshot['engines'][1]['reservations'], 0)
        self.assertEqual(self.tls_server.headers, 2)

    def test_search_json_endpoint_current_config_refusal_without_send(self):
        from searx import settings
        from searx.network.protected import resolved_config_digest
        import searx.webapp

        _, _, manifest = self.native_search_fixture()
        client = searx.webapp.app.test_client()
        with patch.dict(settings['outgoing'], {'max_request_timeout': 2.5}):
            response = client.get(
                '/search', query_string={'q': 'offline synthetic query', 'format': 'json', 'engines': 'bing,quark'}
            )
            self.assertEqual(response.status_code, 200)
            summary = response.get_json()['outbound_protection']
            self.assertEqual((summary['status'], summary['retryable']), ('refused', False))
            self.assertEqual(summary['artifact_digest'], manifest['artifact_digest'])
            self.assertEqual(summary['registry_digest'], manifest['registry_digest'])
            self.assertEqual(
                summary['config_digest'], resolved_config_digest(settings['engines'], settings['outgoing'])
            )
            self.assertTrue(summary['engines'])
            self.assertTrue(all(ref['reason'] == 'provenance_error' for ref in summary['engines']))
        self.assertEqual(self.tls_server.headers, 0)

    def test_native_json_finalrefs_duplicates_and_missing_processor(self):
        import sqlite3
        from flask import Flask
        from searx.search.models import EngineRef
        from searx.webutils import get_json_response

        search, root, _ = self.native_search_fixture()
        search.search_query.engineref_list = [EngineRef('bing', 'general') for _ in range(7)] + [
            EngineRef('missing synthetic processor', 'general')
        ]
        with Flask('protected-finalrefs').test_request_context('/search'):
            container = search.search()
            summary = json.loads(get_json_response(search.search_query, container))['outbound_protection']
        self.assertEqual((summary['status'], summary['retryable']), ('partial', False))
        self.assertEqual(len(summary['engines']), 8)
        self.assertEqual([ref['status'] for ref in summary['engines']], ['admitted'] * 6 + ['refused'] * 2)
        self.assertEqual([ref['reason'] for ref in summary['engines'][-2:]], ['engine_rate', 'capability_refused'])
        self.assertEqual(self.tls_server.headers, 6)
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM attempts').fetchone()[0], 6)

    def test_config_endpoint_readonly_admission_and_current_digest(self):
        import sqlite3
        from searx import settings
        from searx.network.protected import resolved_config_digest
        import searx.webapp
        import searx.search

        _, root, manifest = self.native_search_fixture()
        before = (root / 'ledger.sqlite').read_bytes()
        with (
            patch.object(searx.search, 'initialize', side_effect=AssertionError('config initialized engines')),
            patch.object(searx.search.Search, 'search', side_effect=AssertionError('config searched')),
        ):
            response = searx.webapp.app.test_client().get('/config')
        self.assertEqual(response.status_code, 200)
        descriptor = response.get_json()['outbound_protection']
        self.assertEqual(
            set(descriptor),
            {
                'version',
                'enabled',
                'contract',
                'artifact_digest',
                'registry_digest',
                'config_digest',
                'admission',
                'reason',
            },
        )
        self.assertEqual((descriptor['admission'], descriptor['reason']), ('available', None))
        for key in ('artifact_digest', 'registry_digest', 'config_digest'):
            self.assertEqual(descriptor[key], manifest[key])
        self.assertEqual(self.tls_server.headers, 0)
        self.assertEqual((root / 'ledger.sqlite').read_bytes(), before)
        with patch.dict(settings['outgoing'], {'max_request_timeout': 2.5}):
            changed = searx.webapp.app.test_client().get('/config').get_json()['outbound_protection']
            self.assertEqual((changed['admission'], changed['reason']), ('blocked', 'provenance_error'))
            self.assertEqual(
                changed['config_digest'], resolved_config_digest(settings['engines'], settings['outgoing'])
            )
            self.assertNotEqual(changed['config_digest'], manifest['config_digest'])
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            db.execute("INSERT INTO poison VALUES ('clock_error')")
        before = (root / 'ledger.sqlite').read_bytes()
        poisoned = searx.webapp.app.test_client().get('/config').get_json()['outbound_protection']
        self.assertEqual((poisoned['admission'], poisoned['reason']), ('blocked', 'clock_error'))
        self.assertEqual((root / 'ledger.sqlite').read_bytes(), before)
        with patch.dict(settings['outgoing'], {'wag_protection': {'enabled': False}}):
            off = searx.webapp.app.test_client().get('/config').get_json()['outbound_protection']
            self.assertEqual(off, {'version': 2, 'enabled': False, 'contract': 'wag.outbound.v2'})
        self.assertEqual(self.tls_server.headers, 0)

    def test_native_search_json_reports_complete_machine_snapshot(self):
        from flask import Flask
        from searx.webutils import get_json_response

        search, _, manifest = self.native_search_fixture()
        with Flask('protected-json-test').test_request_context('/search?format=json'):
            container = search.search()
            payload = json.loads(get_json_response(search.search_query, container))
        summary = payload['outbound_protection']
        self.assertEqual(
            set(summary),
            {
                'version',
                'enabled',
                'contract',
                'artifact_digest',
                'registry_digest',
                'config_digest',
                'status',
                'engines',
                'retryable',
            },
        )
        self.assertEqual((summary['version'], summary['enabled'], summary['contract']), (2, True, 'wag.outbound.v2'))
        self.assertEqual(summary['artifact_digest'], manifest['artifact_digest'])
        self.assertEqual(summary['registry_digest'], manifest['registry_digest'])
        self.assertEqual(summary['config_digest'], manifest['config_digest'])
        self.assertEqual((summary['status'], summary['retryable']), ('complete', True))
        self.assertEqual([ref['engine'] for ref in summary['engines']], ['bing', 'quark'])
        for ref in summary['engines']:
            self.assertEqual(
                set(ref),
                {
                    'engine',
                    'category',
                    'status',
                    'reason',
                    'outcome',
                    'reservations',
                    'connection_attempts',
                    'http_attempts',
                    'result_count',
                    'elapsed_s',
                    'deadline_exceeded',
                },
            )
            self.assertEqual((ref['status'], ref['reason'], ref['outcome']), ('admitted', None, 'ok'))
            self.assertEqual(
                (ref['reservations'], ref['connection_attempts'], ref['http_attempts'], ref['result_count']),
                (1, 1, 1, 1),
            )
            self.assertIs(type(ref['deadline_exceeded']), bool)
        self.assertEqual(len(payload['results']), 2)
        summary['engines'][0]['status'] = 'refused'
        self.assertEqual(
            json.loads(get_json_response(search.search_query, container))['outbound_protection']['engines'][0][
                'status'
            ],
            'admitted',
        )

    def test_native_search_two_engines_same_query_complete_nonempty(self):
        import sqlite3
        from flask import Flask

        search, root, _ = self.native_search_fixture()
        with Flask('protected-native-test').test_request_context('/search'):
            container = search.search()
        summary = search.outbound_protection
        self.assertEqual(summary['status'], 'complete')
        self.assertEqual(search.actual_timeout, 3.0)
        self.assertLessEqual(time.monotonic() - search.start_time, 3.0)
        self.assertEqual([ref['engine'] for ref in summary['engines']], ['bing', 'quark'])
        for ref in summary['engines']:
            self.assertEqual((ref['status'], ref['outcome'], ref['result_count']), ('admitted', 'ok', 1))
            self.assertEqual((ref['reservations'], ref['connection_attempts'], ref['http_attempts']), (1, 1, 1))
            self.assertFalse(ref['deadline_exceeded'])
        results = container.get_ordered_results()
        self.assertEqual(len(results), 2)
        self.assertEqual({result['title'] for result in results}, {'Bing synthetic', 'Synthetic source'})
        self.assertEqual((self.tls_server.accepts, self.tls_server.headers), (2, 2))
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            rows = db.execute(
                'SELECT engine,outcome,reserved_mono,finished_mono,connection_attempted,http_attempted '
                'FROM attempts ORDER BY attempt_id'
            ).fetchall()
        self.assertEqual([row[:2] for row in rows], [('bing', 'ok'), ('quark', 'ok')])
        for _, _, reserved, finished, connections, headers in rows:
            self.assertGreaterEqual(reserved, search.start_time)
            self.assertLessEqual(finished, search.start_time + 3.0)
            self.assertEqual((connections, headers), (1, 1))

    # Keep the blocked parser, second sender and post-unlock poison observations in one deadline scenario.
    # pylint: disable-next=too-many-locals
    def test_search_deadline_keeps_late_parser_null_and_poisoned_after_unlock(self):
        import sqlite3
        import sys
        from flask import Flask
        from searx.search.processors import PROCESSORS

        search, root, manifest = self.native_search_fixture()
        entered, release, parser_exited = threading.Event(), threading.Event(), threading.Event()
        engine = PROCESSORS['bing'].engine
        actual_parser = engine.response

        def blocked_parser(response):
            entered.set()
            try:
                if not release.wait(10):
                    raise AssertionError('fixture release was not delivered')
                return actual_parser(response)
            finally:
                parser_exited.set()

        with patch.object(engine, 'response', blocked_parser):
            try:
                with Flask('late-parser-test').test_request_context('/search'):
                    container = search.search()
                self.assertTrue(entered.is_set())
                self.assertEqual(search.actual_timeout, 3.0)
                snapshot = json.loads(json.dumps(search.outbound_protection))
                self.assertEqual(snapshot['status'], 'unfinished')
                self.assertIs(type(snapshot['engines'][0]['reservations']), int)
                self.assertEqual(snapshot['engines'][0]['reservations'], 1)
                self.assertEqual(snapshot['engines'][1]['reason'], 'deadline_exceeded')
                self.assertEqual(self.api.open_store(root, manifest=manifest, mode='synthetic').reason, 'lock_busy')
                with sqlite3.connect(root / 'ledger.sqlite') as db:
                    self.assertEqual(db.execute('SELECT engine,outcome FROM attempts').fetchall(), [('bing', None)])
                self.assertEqual(self.tls_server.headers, 1)
                self.assertEqual(len(container.get_ordered_results()), 0)
            finally:
                release.set()
                self.assertTrue(parser_exited.wait(3), 'real parser did not stop after fixture release')
            stop_deadline = time.monotonic() + 3
            while time.monotonic() < stop_deadline:
                reopened = self.api.open_store(root, manifest=manifest, mode='synthetic')
                if getattr(reopened, 'reason', None) != 'lock_busy':
                    break
                parser_exited.wait(0.01)
            self.assertNotEqual(getattr(reopened, 'reason', None), 'lock_busy')
            with sqlite3.connect(root / 'ledger.sqlite') as db:
                poison = [row[0] for row in db.execute('SELECT reason FROM poison')]
                rows = db.execute('SELECT engine,outcome FROM attempts').fetchall()
            script = '''
import json, socket, sys
from pathlib import Path
def denied(*args, **kwargs):
    raise AssertionError('child attempted network')
socket.socket = denied
import wag_protection
manifest = json.loads(Path(sys.argv[2]).read_text())
store = wag_protection.open_store(sys.argv[1], manifest=manifest, mode='synthetic')
calls = []
import time
result = store.run_engine('quark', caller='probe', deadline_mono=time.monotonic()+3,
    build=lambda: calls.append('build'), send=lambda context, request: calls.append('send'),
    parse=lambda response: [])
print(json.dumps({'reason': getattr(result, 'reason', None), 'calls': calls}))
'''
            child = subprocess.run(
                [sys.executable, '-S', '-c', script, str(root), str(Path(self.parent.name) / 'native-artifact.json')],
                cwd=WORKSPACE,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
            independent = json.loads(child.stdout)
            self.assertEqual(
                (poison, rows, independent),
                (['unfinished_attempt'], [('bing', None)], {'reason': 'unfinished_attempt', 'calls': []}),
            )
            self.assertEqual(search.outbound_protection, snapshot)
            self.assertEqual(len(container.get_ordered_results()), 0)

    def test_handler_cancel_confirms_real_async_stop_within_shared_deadline(self):
        import sqlite3
        from flask import Flask

        search, root, manifest = self.native_search_fixture()
        self.tls_server.body_release.clear()
        cancelled, controller_errors = threading.Event(), []

        def cancel_handler():
            try:
                if not self.tls_server.request_entered.wait(3):
                    raise AssertionError('native request did not reach TLS fixture')
                search.cancel()
                cancelled.set()
            except BaseException as error:
                controller_errors.append(error)

        controller = threading.Thread(target=cancel_handler, daemon=True)
        controller.start()
        try:
            with Flask('handler-cancel-test').test_request_context('/search'):
                container = search.search()
        finally:
            self.tls_server.body_release.set()
            controller.join(3)
        self.assertEqual(controller_errors, [])
        self.assertTrue(cancelled.is_set())
        self.assertLess(time.monotonic() - search.start_time, 3.0)
        self.assertEqual(search.outbound_protection['engines'][0]['outcome'], 'cancelled')
        self.assertEqual(self.tls_server.headers, 1)
        self.assertEqual(len(container.get_ordered_results()), 0)
        with sqlite3.connect(root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT engine,outcome FROM attempts').fetchall(), [('bing', 'cancelled')])
            self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [])
        reopened = self.api.open_store(root, manifest=manifest, mode='synthetic')
        self.assertNotEqual(getattr(reopened, 'reason', None), 'lock_busy')

    def test_held_tls_peer_cancel_closes_socket_and_task_before_return(self):
        import sqlite3
        from flask import Flask
        from searx.network.client import get_loop

        search, root, manifest = self.native_search_fixture()
        self.tls_server.body_release.clear()
        sender_tasks, controller_errors = [], []

        async def capture_senders():
            return [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]

        def cancel_handler():
            try:
                if not self.tls_server.request_entered.wait(3):
                    raise AssertionError('native request did not reach TLS fixture')
                sender_tasks.extend(asyncio.run_coroutine_threadsafe(capture_senders(), get_loop()).result(1))
                search.cancel()
            except BaseException as error:
                controller_errors.append(error)

        controller = threading.Thread(target=cancel_handler, daemon=True)
        controller.start()
        try:
            with Flask('held-peer-stop-test').test_request_context('/search'):
                container = search.search()
            self.assertLess(time.monotonic() - search.start_time, 3.0)
            self.assertFalse(self.tls_server.body_release.is_set(), 'peer was released before stop proof')
            self.assertEqual(controller_errors, [])
            self.assertTrue(sender_tasks)
            self.assertTrue(all(task.done() for task in sender_tasks), 'sender Task is still pending')
            self.assertTrue(any(task.cancelled() for task in sender_tasks))
            sockets = [sock for sock, address in self.client_sockets if address[1] == self.tls_server.server_port]
            self.assertTrue(sockets)
            self.assertTrue(all(sock.fileno() == -1 for sock in sockets), 'actual client socket remains open')
            self.assertEqual(search.outbound_protection['engines'][0]['outcome'], 'cancelled')
            self.assertEqual(self.tls_server.headers, 1)
            self.assertEqual(len(container.get_ordered_results()), 0)
            with sqlite3.connect(root / 'ledger.sqlite') as db:
                self.assertEqual(db.execute('SELECT engine,outcome FROM attempts').fetchall(), [('bing', 'cancelled')])
                self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [])
            self.assertNotEqual(
                getattr(self.api.open_store(root, manifest=manifest, mode='synthetic'), 'reason', None), 'lock_busy'
            )
            pending = asyncio.run_coroutine_threadsafe(capture_senders(), get_loop()).result(1)
            self.assertEqual(pending, [], 'residual async work after native Search return')
        finally:
            self.tls_server.body_release.set()
            controller.join(3)

    def test_real_async_unconfirmed_cancel_retains_lock_null_and_poison(self):
        import httpx
        import sqlite3
        from searx.network.client import get_loop
        from searx.network.protected import GuardedTransport

        entered, cancel_seen, released, finished = (threading.Event() for _ in range(4))
        release_async = asyncio.Event()
        results = []

        async def operation():
            async with httpx.AsyncClient(transport=GuardedTransport(), trust_env=False) as client:
                response = await client.get(f'http://127.0.0.1:{self.server.server_port}/')
                entered.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    cancel_seen.set()
                    await release_async.wait()
                    released.set()
                return response

        def worker():
            try:
                results.append(
                    self.store.run_engine(
                        'quark',
                        caller='native_search',
                        deadline_mono=time.monotonic() + 3,
                        build=lambda: None,
                        send=lambda context, request: context.run_async(operation, get_loop()),
                        parse=lambda response: [],
                    )
                )
            finally:
                finished.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertTrue(cancel_seen.wait(3))
            self.assertFalse(finished.is_set(), 'cancellation request was mistaken for stop confirmation')
            self.assertEqual(
                self.api.open_store(self.root, manifest=self.manifest, mode='synthetic').reason, 'lock_busy'
            )
            with sqlite3.connect(self.root / 'ledger.sqlite') as db:
                self.assertEqual(db.execute('SELECT outcome FROM attempts').fetchall(), [(None,)])
        finally:
            get_loop().call_soon_threadsafe(release_async.set)
            self.assertTrue(finished.wait(3))
            thread.join(0)
        self.assertTrue(released.is_set())
        self.assertEqual(results[0].reason, 'unfinished_attempt')
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(db.execute('SELECT outcome FROM attempts').fetchall(), [(None,)])
            self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [('unfinished_attempt',)])
        self.assertEqual((self.server.accepts, self.server.headers), (1, 1))

    def test_four_real_request_and_response_modules_direct_https_nonempty(self):
        trust = self.tls_fixture()
        for name in ('quark', 'chinaso news', 'bing', 'yandex'):
            with self.subTest(engine=name):
                result = self.parsed_request(name, verify=trust)
                self.assertEqual(result.outcome, 'ok')
                self.assertEqual(result.result_count, 1)
                self.assertEqual((result.reservations, result.connection_attempts, result.http_attempts), (1, 1, 1))
        self.assertEqual((self.tls_server.accepts, self.tls_server.headers), (4, 4))

    def test_http_connect_origin_tls_has_two_charges_not_two_connections(self):
        trust = self.tls_fixture()
        self.server.tunnel_port = self.tls_server.server_port
        result = self.parsed_request('quark', verify=trust, proxy=f'http://127.0.0.1:{self.server.server_port}')
        self.assertEqual(result.outcome, 'ok')
        self.assertEqual(result.result_count, 1)
        self.assertEqual((result.reservations, result.connection_attempts, result.http_attempts), (2, 1, 2))
        self.assertEqual((self.server.connect_headers, self.tls_server.headers), (1, 1))

    def test_https_proxy_connect_and_origin_tls_are_real_and_charged(self):
        import httpx

        trust = self.tls_fixture()
        self.server.tunnel_port = self.tls_server.server_port
        # Use another TLS fixture as the proxy, preserving its certificate verification.
        parent = Path(self.parent.name)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(parent / 'synthetic-cert.pem', parent / 'synthetic-key.pem')
        proxy_server = CountedServer()
        proxy_server.tunnel_port = self.tls_server.server_port
        proxy_server.socket = server_context.wrap_socket(proxy_server.socket, server_side=True)
        proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
        proxy_thread.start()

        def stop_proxy():
            proxy_server.shutdown()
            proxy_server.server_close()
            proxy_thread.join()

        self.addCleanup(stop_proxy)
        proxy = httpx.Proxy(f'https://127.0.0.1:{proxy_server.server_port}', ssl_context=trust)
        result = self.parsed_request('quark', verify=trust, proxy=proxy)
        self.assertEqual(result.outcome, 'ok')
        self.assertEqual((result.reservations, result.connection_attempts, result.http_attempts), (2, 1, 2))
        self.assertEqual((proxy_server.connect_headers, self.tls_server.headers), (1, 1))

    def test_explicit_native_thread_to_async_bridge_keeps_parser_lock(self):
        import httpx
        from searx.engines import quark
        from searx.network.client import get_loop
        from searx.network.protected import GuardedTransport

        async def request():
            async with httpx.AsyncClient(transport=GuardedTransport(verify=True), trust_env=False) as client:
                return await client.get(f'http://127.0.0.1:{self.server.server_port}/')

        def parse(response):
            self.assertEqual(
                self.api.open_store(self.root, manifest=self.manifest, mode='synthetic').reason, 'lock_busy'
            )
            return quark.response(response)

        result = self.store.run_engine(
            'quark',
            caller='native_search',
            deadline_mono=time.monotonic() + 3,
            build=lambda: None,
            send=lambda context, request_params: context.run_async(request, get_loop()),
            parse=parse,
        )
        self.assertEqual(result.outcome, 'ok')
        self.assertEqual(result.result_count, 1)
        self.assertEqual((result.reservations, result.connection_attempts, result.http_attempts), (1, 1, 1))

    def test_copied_context_child_task_refuses_before_real_socket_send(self):
        import httpx
        import sqlite3
        from searx.engines import quark
        from searx.network.client import get_loop
        from searx.network.protected import GuardedTransport

        async def operation():
            async def unintended_child():
                async with httpx.AsyncClient(transport=GuardedTransport(), trust_env=False) as client:
                    return await client.get(f'http://127.0.0.1:{self.server.server_port}/')

            return await asyncio.create_task(unintended_child())

        result = self.store.run_engine(
            'quark',
            caller='native_search',
            deadline_mono=time.monotonic() + 3,
            build=lambda: None,
            send=lambda context, request: context.run_async(operation, get_loop()),
            parse=quark.response,
        )
        self.assertEqual((self.server.accepts, self.server.headers), (0, 0))
        self.assertEqual(result.outcome, 'runtime_error')
        self.assertEqual((result.reservations, result.connection_attempts, result.http_attempts), (1, 0, 0))
        with sqlite3.connect(self.root / 'ledger.sqlite') as db:
            self.assertEqual(
                db.execute('SELECT outcome,connection_attempted,http_attempted FROM attempts').fetchall(),
                [('runtime_error', 0, 0)],
            )
            self.assertEqual(db.execute('SELECT reason FROM poison').fetchall(), [])

    def test_missing_header_trace_refuses_before_socket_creation(self):
        import httpx
        from searx.engines import quark
        from searx.network.client import get_loop
        from searx.network.protected import GuardedTransport

        async def request():
            transport = GuardedTransport(verify=True)
            transport.trace = None
            async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
                return await client.get(f'http://127.0.0.1:{self.server.server_port}/')

        result = self.store.run_engine(
            'quark',
            caller='native_search',
            deadline_mono=time.monotonic() + 3,
            build=lambda: None,
            send=lambda context, request_params: context.run_async(request, get_loop()),
            parse=quark.response,
        )
        self.assertNotEqual(result.outcome, 'ok')
        self.assertEqual((self.server.accepts, self.server.headers), (0, 0))

    def test_raw_native_settings_reject_non_boolean_before_schema_coercion(self):
        from searx.settings_defaults import SCHEMA, apply_schema

        for raw in ['false', 'true', 0, 1, None]:
            with self.subTest(raw=raw):
                self.assertTrue(apply_schema({'wag_protection': {'enabled': raw}}, SCHEMA['outgoing'], ['outgoing']))

    # This one vertical matrix retains real native dispatch, reopened state and every zero-send assertion.
    # pylint: disable-next=too-many-locals,too-many-statements
    def test_native_challenge_denial_matrix_persists_pause_before_second_sender(self):
        """AC-A4: real native classification must durably gate the next sender."""
        from searx import settings
        from searx.network.protected import get_store
        from searx.search.processors import PROCESSORS

        search, _, manifest = self.native_search_fixture(include_yandex=True)
        # These are native parser/HTTP contracts, not EngineFailure substitutes.
        # Quark's HTTP-200 X5SEC page raises its real 900-second exception;
        # the durable protection floor must still be 1800 seconds.
        malformed_quark = b'<script type="application/json" id="s-data-fixture" data-used-by="hydrate">{</script>'
        cases = [
            (
                'quark-200-captcha',
                'quark',
                200,
                {},
                b'<script>{"action":"captcha","url":"https://fixture.invalid/x5sec"}</script>',
                'captcha',
                1800,
            ),
            ('yandex-header', 'yandex', 200, {'x-yandex-captcha': 'captcha'}, YANDEX_RESULT, 'captcha', 3600),
            (
                # The real parser's known CAPTCHA must win over a generic CF
                # challenge fallback, including its longer suspension request.
                'yandex-200-captcha-with-cf',
                'yandex',
                200,
                {'x-yandex-captcha': 'captcha', 'Server': 'cloudflare', 'cf-mitigated': 'challenge'},
                YANDEX_RESULT,
                'captcha',
                3600,
            ),
            (
                # Quark's real 900-second CAPTCHA must retain its classification
                # even though both it and unknown challenges have an 1800 floor.
                'quark-200-captcha-with-cf',
                'quark',
                200,
                {'Server': 'cloudflare', 'cf-mitigated': 'challenge'},
                b'<script>{"action":"captcha","url":"https://fixture.invalid/x5sec"}</script>',
                'captcha',
                1800,
            ),
            (
                'cloudflare-js',
                'quark',
                503,
                {'Server': 'cloudflare'},
                b'<html>__cf_chl_jschl_tk__=synthetic</html>',
                'captcha',
                1296000,
            ),
            (
                'cloudflare-captcha',
                'quark',
                403,
                {'Server': 'cloudflare'},
                b'<html>__cf_chl_captcha_tk__=synthetic</html>',
                'captcha',
                1296000,
            ),
            (
                'cloudflare-firewall',
                'quark',
                403,
                {'Server': 'cloudflare'},
                b'<html><span class="cf-error-code">1020</span></html>',
                'access_denied',
                86400,
            ),
            (
                'recaptcha',
                'quark',
                503,
                {},
                b'<html><script src="https://www.google.com/recaptcha/api.js"></script></html>',
                'captcha',
                604800,
            ),
            ('http-403', 'quark', 403, {}, b'<html>Forbidden</html>', 'access_denied', 1800),
            ('http-429', 'quark', 429, {}, b'<html>Too many requests</html>', 'rate_limited', 1800),
            (
                # Recognizably a challenge, but not either legacy CF signature.
                # It must not silently become an ordinary HTTP error with no pause.
                'cloudflare-unknown',
                'quark',
                503,
                {'Server': 'cloudflare', 'cf-mitigated': 'challenge'},
                b'<html><script src="/cdn-cgi/challenge-platform/unknown/v2"></script></html>',
                'challenge_unknown',
                1800,
            ),
            (
                # Even a normally parseable result must not override the
                # origin's explicit challenge signal on an HTTP-200 response.
                'cloudflare-200-unknown',
                'quark',
                200,
                {'Server': 'cloudflare', 'cf-mitigated': 'challenge'},
                QUARK_RESULT,
                'challenge_unknown',
                1800,
            ),
            (
                'cloudflare-200-empty',
                'quark',
                200,
                {'Server': 'cloudflare', 'cf-mitigated': 'challenge'},
                b'<html>No results</html>',
                'challenge_unknown',
                1800,
            ),
            (
                'cloudflare-200-parser-error',
                'quark',
                200,
                {'Server': 'cloudflare', 'cf-mitigated': 'challenge'},
                malformed_quark,
                'challenge_unknown',
                1800,
            ),
            (
                # The same real JSON parser failure without a challenge signal
                # must stay a parser error, with no invented CAPTCHA pause.
                'http-200-parser-error-unmarked',
                'quark',
                200,
                {'Server': 'cloudflare'},
                malformed_quark,
                'parser_error',
                None,
            ),
            (
                # Server branding/status alone are not a challenge signal.
                'http-503-unmarked',
                'quark',
                503,
                {'Server': 'cloudflare'},
                b'<html>Service unavailable</html>',
                'error',
                None,
            ),
        ]
        # cf-mitigated is authoritative even when a proxy removes/replaces Server.
        explicit_cases = [
            case
            for case in cases
            if case[0]
            in {
                'cloudflare-unknown',
                'cloudflare-200-unknown',
                'cloudflare-200-empty',
                'cloudflare-200-parser-error',
            }
        ]
        for label, name, status, headers, body, outcome, floor in explicit_cases:
            for server in (None, 'nginx'):
                variant_headers = dict(headers)
                variant_headers.pop('Server', None)
                if server is not None:
                    variant_headers['Server'] = server
                cases.append(
                    (f'{label}-server-{server or "missing"}', name, status, variant_headers, body, outcome, floor)
                )
        hosts = {'quark': 'quark.sm.cn', 'yandex': 'yandex.com'}
        healthy = {'quark': QUARK_RESULT, 'yandex': YANDEX_RESULT}
        boot = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='utf-8').strip()
        for label, name, status, headers, body, outcome, floor in cases:
            with self.subTest(case=label):
                # Each case gets independent, explicitly synthetic state; never
                # reset a live ledger or let earlier cases mask one another.
                root = Path(self.parent.name) / label
                now = {'wall': time.time(), 'mono': time.monotonic(), 'boot': boot}
                # Control only the ledger's clock boundary. Asyncio, native TLS,
                # sockets and engine request/response implementations stay real.
                clock = SimpleNamespace(time=lambda now=now: now['wall'], monotonic=lambda now=now: now['mono'])
                with patch('wag_protection.ledger.time', clock):
                    self.api.initialize_fixture(root, registry=manifest['registry'], clock=lambda now=now: dict(now))
                    case_manifest = fixture_manifest(root, manifest['registry'])
                    case_manifest['config_digest'] = manifest['config_digest']
                    manifest_path = Path(self.parent.name) / (label + '-artifact.json')
                    manifest_path.write_text(json.dumps(case_manifest), encoding='utf-8')
                    config = {'enabled': True, 'root': str(root), 'artifact_manifest': str(manifest_path)}
                    with patch.dict(settings['outgoing'], {'wag_protection': config}):
                        processor = PROCESSORS[name]

                        def dispatch(processor=processor, monotonic=clock.monotonic):
                            # A new validated handle for every attempt: the pause
                            # must survive reopen, not just native memory state.
                            store = get_store()
                            self.assertNotIsInstance(store, self.api.Refusal)
                            params = processor.get_params(search.search_query, 'general')
                            self.assertIsNotNone(params)
                            return processor.search_protected(
                                search.search_query.query, params, store, monotonic(), 3.0
                            )

                        # Independent matrix fixtures must not reuse a socket
                        # armed by an earlier dispatch/store identity.
                        self.tls_server.responses = {hosts[name]: (status, {'Connection': 'close', **headers}, body)}
                        before = (self.tls_server.accepts, self.tls_server.headers)
                        result = dispatch()
                        self.assertIsInstance(result, self.api.EngineOutcome)
                        self.assertEqual(
                            (self.tls_server.accepts, self.tls_server.headers), (before[0] + 1, before[1] + 1)
                        )
                        self.assertEqual(
                            (result.reservations, result.connection_attempts, result.http_attempts), (1, 1, 1)
                        )
                        with self.subTest(stage='classification'):
                            self.assertEqual(result.outcome, outcome)

                        # A genuinely useful response is available for the next
                        # sender. Only durable admission may prevent its send.
                        self.tls_server.responses = {hosts[name]: (200, {'Connection': 'close'}, healthy[name])}
                        if floor is None:
                            with self.subTest(stage='unmarked-error-does-not-pause'):
                                before = (self.tls_server.accepts, self.tls_server.headers)
                                recovered = dispatch()
                                self.assertIsInstance(recovered, self.api.EngineOutcome)
                                self.assertEqual((recovered.outcome, recovered.result_count), ('ok', 1))
                                self.assertEqual(
                                    (recovered.reservations, recovered.connection_attempts, recovered.http_attempts),
                                    (1, 1, 1),
                                )
                                self.assertEqual(
                                    (self.tls_server.accepts, self.tls_server.headers), (before[0] + 1, before[1] + 1)
                                )
                                self.assertEqual(recovered.results[0]['title'], 'Synthetic source')
                            continue
                        for elapsed in (0, floor - 0.001):
                            now['wall'] += elapsed
                            now['mono'] += elapsed
                            with self.subTest(stage='durable-cooldown', elapsed=elapsed):
                                counts = (self.tls_server.accepts, self.tls_server.headers, len(self.client_sockets))
                                denied = dispatch()
                                self.assertEqual(
                                    (self.tls_server.accepts, self.tls_server.headers, len(self.client_sockets)),
                                    counts,
                                    'a reopened sender must not connect or send headers during the durable pause',
                                )
                                self.assertIsInstance(denied, self.api.Refusal)
                                self.assertEqual(denied.reason, 'cooldown')

    def test_direct_http_charges_one_connect_and_header_and_real_quark_parser(self):
        import httpx
        from searx.engines import quark
        from searx.network.client import get_loop
        from searx.network.protected import GuardedTransport

        async def request():
            async with httpx.AsyncClient(transport=GuardedTransport(verify=True), trust_env=False) as client:
                return await client.get(f'http://127.0.0.1:{self.server.server_port}/', follow_redirects=False)

        result = self.store.run_engine(
            'quark',
            caller='native_search',
            deadline_mono=time.monotonic() + 3,
            build=lambda: None,
            send=lambda context, request_params: context.run_async(request, get_loop()),
            parse=quark.response,
        )
        self.assertEqual(result.outcome, 'ok')
        self.assertEqual(result.result_count, 1)
        self.assertEqual((result.reservations, result.connection_attempts, result.http_attempts), (1, 1, 1))
        self.assertEqual((self.server.accepts, self.server.headers), (1, 1))
        self.assertEqual(result.results[0]['title'], 'Synthetic source')


if __name__ == '__main__':
    unittest.main()
