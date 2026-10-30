# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pinned native HTTP/1.1 transport with adjacent durable connect/header gates."""

import asyncio
from collections.abc import AsyncIterator, Iterable, Iterator, Mapping
from contextlib import contextmanager
import hashlib
import ipaddress
from importlib.metadata import PackageNotFoundError
from pathlib import Path
import select
import socket
import ssl
from typing import Protocol, TypedDict, cast

import httpcore
from httpcore._backends.base import SOCKET_OPTION
import httpx

from wag_protection import ProtectionError, Refusal, open_store, validate_settings
from wag_protection.contract import canonical_path, json_digest, load_json, validate_manifest
from wag_protection.ledger import CURRENT_DISPATCH, _commit


ENGINE_CONFIG_FIELDS = frozenset(
    (
        'name',
        'engine',
        'categories',
        'shortcut',
        'timeout',
        'disabled',
        'inactive',
        'weight',
        'language_support',
        'quark_category',
        'chinaso_news_source',
        'search_type',
    )
)
NETWORK_CONFIG_FIELDS = (
    'enable_http',
    'verify',
    'enable_http2',
    'pool_connections',
    'pool_maxsize',
    'keepalive_expiry',
    'source_ips',
    'local_addresses',
    'using_tor_proxy',
    'max_redirects',
    'retries',
    'retry_on_http_error',
    'request_timeout',
    'max_request_timeout',
)


def resolved_config_digest(engine_settings, outgoing):
    """Hash only current resolved, nonsecret settings, never the manifest's assertion."""

    def network_projection(value):
        result = {key: value[key] for key in NETWORK_CONFIG_FIELDS if key in value}
        proxies = value.get('proxies') or {}
        if isinstance(proxies, str):
            proxies = {'all://': proxies}
        result['proxies'] = {}
        for pattern, addresses in sorted(proxies.items()):
            addresses = [addresses] if isinstance(addresses, str) else addresses
            result['proxies'][pattern] = []
            for address in addresses:
                url = httpx.URL(address)
                result['proxies'][pattern].append({'scheme': url.scheme, 'host': url.host, 'port': url.port})
        return result

    projection = {
        'engines': [
            {key: engine[key] for key in sorted(ENGINE_CONFIG_FIELDS) if key in engine}
            for engine in sorted(engine_settings, key=lambda item: item['name'])
        ],
        'outgoing': network_projection(outgoing),
        'networks': {name: network_projection(value) for name, value in sorted(outgoing.get('networks', {}).items())},
    }
    return json_digest(projection)


def get_store():
    from searx import settings  # pylint: disable=import-outside-toplevel

    try:
        config = validate_settings(settings['outgoing'].get('wag_protection', {'enabled': False}))
        if config['enabled'] is False:
            return Refusal('operator_hold')
        return _validated_store(config, settings)
    except (OSError, ValueError, TypeError, KeyError):
        return Refusal('provenance_error')


def _validated_store(config, runtime_settings):
    """Validate artifact and current config without opening a disabled store."""
    with Path(config['artifact_manifest']).open('rb') as file:
        raw = file.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        return Refusal('provenance_error')
    manifest = load_json(raw.decode('utf-8'))
    # This partial native slice has no production acceptance. Keep it held
    # until the remaining lifecycle, migration, recovery and CI gates pass.
    if manifest['mode'] != 'synthetic':
        return Refusal('operator_hold')
    store = open_store(config['root'], manifest=manifest, mode='synthetic')
    if isinstance(store, Refusal):
        return store
    if store.manifest['config_digest'] != resolved_config_digest(
        runtime_settings['engines'], runtime_settings['outgoing']
    ):
        return Refusal('provenance_error')
    return store


def protection_descriptor():
    """Current config/storage diagnostics only; never call an engine or send."""
    from searx import settings  # pylint: disable=import-outside-toplevel

    descriptor = {'version': 2, 'enabled': False, 'contract': 'wag.outbound.v2'}
    try:
        config = validate_settings(settings['outgoing'].get('wag_protection', {'enabled': False}))
        if config['enabled'] is False:
            return descriptor
        descriptor.update(
            enabled=True,
            artifact_digest=None,
            registry_digest=None,
            config_digest=resolved_config_digest(settings['engines'], settings['outgoing']),
            admission='blocked',
            reason='provenance_error',
        )
        with Path(config['artifact_manifest']).open('rb') as file:
            raw = file.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            return descriptor
        manifest = load_json(raw.decode('utf-8'))
        manifest = validate_manifest(manifest, Path(config['root']), manifest['mode'])
        descriptor.update(artifact_digest=manifest['artifact_digest'], registry_digest=manifest['registry_digest'])
        if descriptor['config_digest'] != manifest['config_digest']:
            return descriptor
        # Retain the production acceptance hold; this descriptor is no permit.
        if manifest['mode'] != 'synthetic':
            descriptor['reason'] = 'operator_hold'
            return descriptor
        store = open_store(config['root'], manifest=manifest, mode=manifest['mode'], readonly=True)
        refusal = store if isinstance(store, Refusal) else store.check_admission()
        descriptor.update(admission='blocked' if refusal else 'available', reason=refusal.reason if refusal else None)
    except (OSError, ValueError, TypeError, KeyError, PackageNotFoundError):
        descriptor.update(enabled=True, admission='blocked', reason='provenance_error')
    return descriptor


def validate_engine_settings(engine_data):
    store = get_store()
    if isinstance(store, Refusal):
        raise ProtectionError(store.reason)
    approved = next((entry for entry in store.manifest['registry'] if entry['engine'] == engine_data.get('name')), None)
    if (
        approved is None
        or approved['module'] != engine_data.get('engine')
        or approved['profile']['live_hold']
        or set(engine_data) - ENGINE_CONFIG_FIELDS
        or {key: value for key, value in engine_data.items() if key not in ('name', 'engine')}
        != approved['profile'].get('settings')
    ):
        raise ProtectionError('capability_refused')
    return approved


def validate_engine_source(engine_data, engine_dir, approved=None):
    """Preflight a dynamic engine source before the loader executes it."""
    store = get_store()
    if isinstance(store, Refusal):
        raise ProtectionError(store.reason)
    if approved is None:
        approved = validate_engine_settings(engine_data)
    module = approved['module']
    relative = f'searx/engines/{module}.py'
    try:
        expected = canonical_path(Path(store.manifest['module_root']) / relative)
        actual = canonical_path(Path(engine_dir) / f'{module}.py')
        if actual != expected or not actual.is_file():
            raise ProtectionError('provenance_error')
        if hashlib.sha256(actual.read_bytes()).hexdigest() != store.manifest['files'].get(relative):
            raise ProtectionError('provenance_error')
    except (OSError, ValueError) as error:
        raise ProtectionError('provenance_error') from error
    return expected


def validate_loaded_engine_source(module, expected, approved, manifest):
    """Recheck the module object after the dynamic loader returns."""
    origin = getattr(module, '__file__', None)
    spec_origin = getattr(getattr(module, '__spec__', None), 'origin', None)
    try:
        valid_origin = (
            isinstance(origin, str)
            and isinstance(spec_origin, str)
            and canonical_path(origin) == expected
            and canonical_path(spec_origin) == expected
        )
        digest_matches = hashlib.sha256(expected.read_bytes()).hexdigest() == manifest['files'].get(
            f"searx/engines/{approved['module']}.py"
        )
    except (OSError, ValueError) as error:
        raise ProtectionError('provenance_error') from error
    if not valid_origin or not digest_matches:
        raise ProtectionError('provenance_error')


def _dispatch():
    context = CURRENT_DISPATCH.get()
    if context is None or context.phase != 'send':
        raise ProtectionError('helper_refused')
    try:
        task = asyncio.current_task()
    except RuntimeError:  # synchronous owner entering the explicit bridge
        task = None
    if task is not None and task is not context.async_task:
        raise ProtectionError('capability_refused')
    context.check_deadline()
    return context


def _remaining(timeout: float | None = None) -> float:
    context = _dispatch()
    remaining = context.deadline - asyncio.get_running_loop().time()
    return remaining if timeout is None else min(remaining, timeout)


@contextmanager
def _map_errors() -> Iterator[None]:
    try:
        yield
    except (httpcore.TimeoutException, httpcore.NetworkError, httpcore.ProtocolError, httpcore.ProxyError) as error:
        for core, native in (
            (httpcore.ConnectTimeout, httpx.ConnectTimeout),
            (httpcore.ReadTimeout, httpx.ReadTimeout),
            (httpcore.WriteTimeout, httpx.WriteTimeout),
            (httpcore.PoolTimeout, httpx.PoolTimeout),
            (httpcore.ConnectError, httpx.ConnectError),
            (httpcore.ReadError, httpx.ReadError),
            (httpcore.WriteError, httpx.WriteError),
            (httpcore.RemoteProtocolError, httpx.RemoteProtocolError),
            (httpcore.LocalProtocolError, httpx.LocalProtocolError),
            (httpcore.ProxyError, httpx.ProxyError),
        ):
            if isinstance(error, core):
                raise native('protected transport failure') from None
        raise httpx.TransportError('protected transport failure') from None


class GuardedStream(httpcore.AsyncNetworkStream):
    """Actual asyncio stream bound to the current durable dispatch."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, root: Path) -> None:
        self.reader = reader
        self.writer = writer
        self.root = root

    def context(self):
        context = _dispatch()
        if context.store.root != self.root:
            raise ProtectionError('provenance_error')
        return context

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        self.context()
        try:
            async with asyncio.timeout(_remaining(timeout)):
                return await self.reader.read(max_bytes)
        except TimeoutError:
            raise httpcore.ReadTimeout() from None
        except OSError:
            raise httpcore.ReadError() from None

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        context = self.context()
        if context.armed_row is None:
            raise ProtectionError('capability_refused')
        try:
            async with asyncio.timeout(_remaining(timeout)):
                self.writer.write(buffer)
                await self.writer.drain()
        except TimeoutError:
            raise httpcore.WriteTimeout() from None
        except OSError:
            raise httpcore.WriteError() from None

    async def aclose(self) -> None:
        # This connection is terminal, not reusable. Graceful TLS shutdown can
        # wait for a peer beyond the shared deadline; abort closes the socket
        # locally, and wait_closed still proves connection_lost before Task done.
        self.writer.transport.abort()
        await self.writer.wait_closed()

    async def start_tls(
        self, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float | None = None
    ) -> 'GuardedStream':
        self.context()
        try:
            async with asyncio.timeout(_remaining(timeout)):
                await self.writer.start_tls(
                    ssl_context, server_hostname=server_hostname, ssl_handshake_timeout=_remaining(timeout)
                )
            return self
        except TimeoutError:
            await self.aclose()
            raise httpcore.ConnectTimeout() from None
        except (OSError, ssl.SSLError):
            await self.aclose()
            raise httpcore.ConnectError() from None
        except BaseException:
            await self.aclose()
            raise

    def get_extra_info(self, info: str) -> object:
        if info == 'is_readable':
            sock = self.writer.get_extra_info('socket')
            return self.writer.is_closing() or bool(select.select([sock], [], [], 0)[0])
        return self.writer.get_extra_info({'client_addr': 'sockname', 'server_addr': 'peername'}.get(info, info))


def _configure_socket(sock, local_address, socket_options):
    """Apply the existing bind/options to the single guarded socket."""
    sock.setblocking(False)
    if local_address is not None:
        sock.bind((local_address, 0))
    for option in socket_options or ():
        if len(option) == 4:
            level, name, value, length = option
            sock.setsockopt(level, name, value, length)
        else:
            level, name, value = option
            sock.setsockopt(level, name, value)


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """Pinned httpcore backend with exactly one numeric OS connect."""

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> GuardedStream:
        context = _dispatch()
        if context.connections:
            raise ProtectionError('protocol_retry_refused')
        loop = asyncio.get_running_loop()
        family = socket.AF_UNSPEC
        if local_address is not None:
            family = socket.AF_INET6 if ipaddress.ip_address(local_address).version == 6 else socket.AF_INET
        sock = None
        try:
            async with asyncio.timeout(_remaining(timeout)):
                addresses = await loop.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
                context.check_deadline()
                compatible = next((entry for entry in addresses if entry[0] in (socket.AF_INET, socket.AF_INET6)), None)
                if compatible is None:
                    raise httpcore.ConnectError()
                address_family, kind, protocol, _, address = compatible
                sock = socket.socket(address_family, kind, protocol)
                _configure_socket(sock, local_address, socket_options)
                context.check_deadline()
                context.db.execute('UPDATE attempts SET connection_attempted=1 WHERE attempt_id=?', (context.rows[0],))
                _commit(context.db, context.store.root)
                context.connections += 1
                # Numeric sockaddr: precisely one OS connect, no address fallback.
                await loop.sock_connect(sock, address)
                reader, writer = await asyncio.open_connection(sock=sock)
                sock = None
                return GuardedStream(reader, writer, context.store.root)
        except TimeoutError:
            raise httpcore.ConnectTimeout() from None
        except OSError:
            raise httpcore.ConnectError() from None
        finally:
            if sock is not None:
                sock.close()

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Iterable[SOCKET_OPTION] | None = None
    ) -> httpcore.AsyncNetworkStream:
        raise ProtectionError('route_unsupported')

    async def sleep(self, seconds: float) -> None:
        raise ProtectionError('protocol_retry_refused')


class CoreResponseStream(Protocol):
    """Streaming interface returned by the pinned async httpcore pool."""

    def __aiter__(self) -> AsyncIterator[bytes]: ...

    async def aclose(self) -> None: ...


class PoolOptions(TypedDict):
    """Shared constructor keywords supported by both pinned async pool types."""

    ssl_context: ssl.SSLContext
    max_connections: int | None
    max_keepalive_connections: int | None
    keepalive_expiry: float | None
    http1: bool
    http2: bool
    retries: int
    local_address: str | None
    network_backend: httpcore.AsyncNetworkBackend


class ResponseStream(httpx.AsyncByteStream):
    """Map errors without replacing the actual httpcore body stream."""

    def __init__(self, stream: CoreResponseStream) -> None:
        self.stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        with _map_errors():
            async for chunk in self.stream:
                yield chunk

    async def aclose(self) -> None:
        with _map_errors():
            await self.stream.aclose()


class GuardedTransport(httpx.AsyncBaseTransport):
    """Original pinned HTTP/1 pool with durable before-header accounting."""

    def __init__(
        self,
        *,
        verify: ssl.SSLContext | str | bool = True,
        proxy: httpx.Proxy | httpx.URL | str | None = None,
        local_address: str | None = None,
        limits: httpx.Limits | None = None,
    ) -> None:
        if httpx.__version__ != '0.28.1' or httpcore.__version__ != '1.0.9':
            raise ProtectionError('import_error')
        limits = limits or httpx.Limits()
        ssl_context = httpx.create_ssl_context(verify=verify, trust_env=False)
        options: PoolOptions = {
            'ssl_context': ssl_context,
            'max_connections': limits.max_connections,
            'max_keepalive_connections': limits.max_keepalive_connections,
            'keepalive_expiry': limits.keepalive_expiry,
            'http1': True,
            'http2': False,
            'retries': 0,
            'local_address': local_address,
            'network_backend': GuardedBackend(),
        }
        if proxy is None:
            self.pool = httpcore.AsyncConnectionPool(**options)
        else:
            proxy = httpx.Proxy(proxy) if not isinstance(proxy, httpx.Proxy) else proxy
            if proxy.url.scheme not in ('http', 'https'):
                raise ProtectionError('route_unsupported')
            self.pool = httpcore.AsyncHTTPProxy(
                proxy_url=httpcore.URL(
                    scheme=proxy.url.raw_scheme, host=proxy.url.raw_host, port=proxy.url.port, target=proxy.url.raw_path
                ),
                proxy_auth=proxy.raw_auth,
                proxy_headers=proxy.headers.raw,
                proxy_ssl_context=proxy.ssl_context,
                **options,
            )

    async def trace(self, event: str, info: Mapping[str, object]) -> None:
        if event != 'http11.send_request_headers.started':
            return
        context = _dispatch()
        method = cast(httpcore.Request, info['request']).method
        if context.headers:
            if context.headers != 1 or not context.proxy_connect or method == b'CONNECT':
                raise ProtectionError('protocol_retry_refused')
            context.reserve('engine_http')
        elif method == b'CONNECT':
            context.proxy_connect = True
            context.db.execute('UPDATE attempts SET phase=? WHERE attempt_id=?', ('proxy_connect', context.rows[0]))
        context.check_deadline()
        context.armed_row = context.rows[-1]
        context.db.execute('UPDATE attempts SET http_attempted=1 WHERE attempt_id=?', (context.armed_row,))
        _commit(context.db, context.store.root)
        context.headers += 1

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        context = _dispatch()
        if not callable(self.trace) or not isinstance(
            self.pool._network_backend, GuardedBackend  # pylint: disable=protected-access
        ):
            raise ProtectionError('import_error')
        if context.main_calls:
            raise ProtectionError('redirect_refused')
        context.main_calls += 1
        if not isinstance(request.stream, httpx.AsyncByteStream):
            raise ProtectionError('import_error')
        request.extensions['trace'] = self.trace
        timeout = _remaining()
        request.extensions['timeout'] = {name: timeout for name in ('connect', 'read', 'write', 'pool')}
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with _map_errors():
            response = await self.pool.handle_async_request(core_request)
        return httpx.Response(
            response.status,
            headers=response.headers,
            stream=ResponseStream(cast(CoreResponseStream, response.stream)),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        with _map_errors():
            await self.pool.aclose()
