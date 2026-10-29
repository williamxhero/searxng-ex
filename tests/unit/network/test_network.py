# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import asyncio
import copy
from contextlib import asynccontextmanager

import httpx
from mock import patch

from searx import settings
from searx.network.network import Network, NETWORKS
from searx.network.network import initialize
from tests import SearxTestCase


class TestNetworkLifecycle(SearxTestCase):
    # pylint: disable=protected-access

    async def test_aclose_waits_for_inflight_request_before_closing_generation(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def request(*args, **kwargs):  # pylint: disable=unused-argument
            started.set()
            await release.wait()
            return httpx.Response(200)

        network = Network(enable_http=True)
        with patch.object(httpx.AsyncClient, 'request', new=request):
            request_task = asyncio.create_task(network.request('GET', 'https://example.com/'))
            await started.wait()
            client = next(iter(network._clients.values()))
            close_task = asyncio.create_task(network.aclose())
            await asyncio.sleep(0)
            self.assertFalse(client.is_closed)
            release.set()
            await request_task
            await close_task

        self.assertTrue(client.is_closed)
        self.assertEqual(network._clients, {})
        with self.assertRaises(RuntimeError):
            await network.get_client()

    async def test_aclose_keeps_stream_open_until_context_exits(self):
        @asynccontextmanager
        async def stream(client, *args, **kwargs):  # pylint: disable=unused-argument
            yield httpx.Response(200, text='stream')

        network = Network()
        close_task = None
        try:
            with patch.object(httpx.AsyncClient, 'stream', new=stream):
                async with await network.stream('GET', 'https://example.com/') as response:
                    close_task = asyncio.create_task(network.aclose())
                    await asyncio.wait({close_task}, timeout=0.05)
                    self.assertEqual(response.text, 'stream')
                    self.assertFalse(close_task.done(), 'close crossed a live stream context')
            await close_task
        finally:
            if close_task is not None:
                await close_task

    async def test_failed_close_refuses_reuse_of_uncertain_clients(self):
        network = Network()
        client = await network.get_client()
        with patch.object(httpx.AsyncClient, 'aclose', side_effect=RuntimeError('synthetic close fault')):
            with self.assertRaises(RuntimeError):
                await network.aclose()
        try:
            with self.assertRaises(RuntimeError):
                await network.get_client()
        finally:
            await client.aclose()

    async def test_group_close_drains_all_networks_before_closing_any_client(self):
        first, second = Network(), Network()
        first_client = await first.get_client()
        started, release = asyncio.Event(), asyncio.Event()

        async def request(client, *args, **kwargs):  # pylint: disable=unused-argument
            started.set()
            await release.wait()
            return httpx.Response(200, text='complete')

        with patch.object(httpx.AsyncClient, 'request', new=request):
            request_task = asyncio.create_task(second.request('GET', 'https://example.com/'))
            await started.wait()
            close_task = asyncio.create_task(Network.aclose_all([first, second]))
            try:
                await asyncio.wait({close_task}, timeout=0.05)
                self.assertFalse(first_client.is_closed, 'close crossed the generation drain barrier')
            finally:
                release.set()
                await request_task
                await close_task
        self.assertTrue(first_client.is_closed)

    async def test_close_waits_for_pending_tor_client_validation(self):
        started, release = asyncio.Event(), asyncio.Event()

        async def tor_response(client, *args, **kwargs):  # pylint: disable=unused-argument
            started.set()
            await release.wait()
            return httpx.Response(200, json={'IsTor': True})

        network = Network(using_tor_proxy=True)
        with (
            patch.dict(Network._TOR_CHECK_RESULT, {}, clear=True),
            patch.object(httpx.AsyncClient, 'get', new=tor_response),
        ):
            create_task = asyncio.create_task(network.get_client())
            await started.wait()
            close_task = asyncio.create_task(network.aclose())
            try:
                await asyncio.wait({close_task}, timeout=0.05)
                self.assertFalse(close_task.done(), 'close crossed pending client construction')
            finally:
                release.set()
                client = await create_task
                await close_task
                await client.aclose()
            self.assertTrue(client.is_closed)
            with self.assertRaises(RuntimeError):
                await network.get_client()

    async def test_cancelled_client_validation_closes_unpublished_client(self):
        started = asyncio.Event()
        client = httpx.AsyncClient()

        async def tor_response(*args, **kwargs):  # pylint: disable=unused-argument
            started.set()
            await asyncio.Event().wait()

        network = Network(using_tor_proxy=True)
        try:
            with (
                patch.dict(Network._TOR_CHECK_RESULT, {}, clear=True),
                patch('searx.network.network.new_client', return_value=client),
                patch.object(httpx.AsyncClient, 'get', new=tor_response),
            ):
                create_task = asyncio.create_task(network.get_client())
                await started.wait()
                create_task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await create_task
            await network.aclose()
            self.assertTrue(client.is_closed, 'unpublished client leaked after cancellation')
        finally:
            await client.aclose()

    async def test_partial_group_close_failure_quarantines_every_old_network(self):
        first, second = Network(), Network()
        clients = [await first.get_client(), await second.get_client()]
        original_close = httpx.AsyncClient.aclose

        async def close(client):
            if client is clients[1]:
                raise httpx.CloseError('synthetic close fault')
            await original_close(client)

        try:
            with patch.object(httpx.AsyncClient, 'aclose', new=close):
                with self.assertRaises(httpx.CloseError):
                    await Network.aclose_all([first, second])
            self.assertTrue(clients[0].is_closed)
            for network in (first, second):
                with self.assertRaises(RuntimeError):
                    await network.get_client()
        finally:
            for client in clients:
                await original_close(client)

    async def test_cancelled_drain_does_not_reopen_old_generation(self):
        network = Network()
        started, release = asyncio.Event(), asyncio.Event()

        async def request(client, *args, **kwargs):  # pylint: disable=unused-argument
            started.set()
            await release.wait()
            return httpx.Response(200, text='complete')

        with patch.object(httpx.AsyncClient, 'request', new=request):
            request_task = asyncio.create_task(network.request('GET', 'https://example.com/'))
            await started.wait()
            close_task = asyncio.create_task(network.aclose())
            await asyncio.sleep(0)
            close_task.cancel()
            try:
                with self.assertRaises(asyncio.CancelledError):
                    await close_task
                with self.assertRaises(RuntimeError):
                    await network.get_client()
            finally:
                release.set()
                await request_task
                await network.aclose()

    async def test_concurrent_tor_client_validation_keeps_one_owned_client(self):
        started, release = asyncio.Event(), asyncio.Event()
        clients = []

        async def tor_response(client, *args, **kwargs):  # pylint: disable=unused-argument
            clients.append(client)
            started.set()
            await release.wait()
            return httpx.Response(200, json={'IsTor': True})

        network = Network(using_tor_proxy=True)
        with (
            patch.dict(Network._TOR_CHECK_RESULT, {}, clear=True),
            patch.object(httpx.AsyncClient, 'get', new=tor_response),
        ):
            first = asyncio.create_task(network.get_client())
            await started.wait()
            second = asyncio.create_task(network.get_client())
            await asyncio.sleep(0)
            release.set()
            first_client, second_client = await asyncio.gather(first, second)
        try:
            self.assertIs(first_client, second_client, 'concurrent validation replaced an owned client')
            self.assertEqual(len(clients), 1)
        finally:
            await network.aclose()
            for client in clients:
                await client.aclose()

    async def test_aclose_clears_client_pool(self):
        network = Network()
        client = await network.get_client()

        await network.aclose()

        self.assertTrue(client.is_closed)
        self.assertEqual(network._clients, {})


class TestNetwork(SearxTestCase):
    # pylint: disable=protected-access

    def test_simple(self):
        network = Network()

        self.assertEqual(next(network._local_addresses_cycle), None)
        self.assertEqual(next(network._proxies_cycle), ())

    def test_initialize_keeps_active_networks_when_generation_close_fails(self):
        old_default = NETWORKS['__DEFAULT__']
        with patch.object(Network, 'aclose', side_effect=RuntimeError('synthetic close fault')):
            with self.assertRaises(RuntimeError):
                initialize(
                    settings_engines=list(settings['engines']), settings_outgoing=copy.deepcopy(settings['outgoing'])
                )
        self.assertIs(NETWORKS['__DEFAULT__'], old_default)

    def test_initialize_keeps_active_networks_when_candidate_validation_fails(self):
        old_default = NETWORKS['__DEFAULT__']
        outgoing = copy.deepcopy(settings['outgoing'])
        outgoing['source_ips'] = ['not-an-ip']

        with self.assertRaises(ValueError):
            initialize(settings_engines=list(settings['engines']), settings_outgoing=outgoing)

        self.assertIs(NETWORKS['__DEFAULT__'], old_default)

    def test_ipaddress_cycle(self):
        network = NETWORKS['ipv6']
        self.assertEqual(next(network._local_addresses_cycle), '::')
        self.assertEqual(next(network._local_addresses_cycle), '::')

        network = NETWORKS['ipv4']
        self.assertEqual(next(network._local_addresses_cycle), '0.0.0.0')
        self.assertEqual(next(network._local_addresses_cycle), '0.0.0.0')

        network = Network(local_addresses=['192.168.0.1', '192.168.0.2'])
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.1')
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.2')
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.1')

        network = Network(local_addresses=['192.168.0.0/30'])
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.1')
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.2')
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.1')
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.2')

        network = Network(local_addresses=['fe80::/10'])
        self.assertEqual(next(network._local_addresses_cycle), 'fe80::1')
        self.assertEqual(next(network._local_addresses_cycle), 'fe80::2')
        self.assertEqual(next(network._local_addresses_cycle), 'fe80::3')

        with self.assertRaises(ValueError):
            Network(local_addresses=['not_an_ip_address'])

    def test_proxy_cycles(self):
        network = Network(proxies='http://localhost:1337')
        self.assertEqual(next(network._proxies_cycle), (('all://', 'http://localhost:1337'),))

        network = Network(proxies={'https': 'http://localhost:1337', 'http': 'http://localhost:1338'})
        self.assertEqual(
            next(network._proxies_cycle), (('https://', 'http://localhost:1337'), ('http://', 'http://localhost:1338'))
        )
        self.assertEqual(
            next(network._proxies_cycle), (('https://', 'http://localhost:1337'), ('http://', 'http://localhost:1338'))
        )

        network = Network(
            proxies={'https': ['http://localhost:1337', 'http://localhost:1339'], 'http': 'http://localhost:1338'}
        )
        self.assertEqual(
            next(network._proxies_cycle), (('https://', 'http://localhost:1337'), ('http://', 'http://localhost:1338'))
        )
        self.assertEqual(
            next(network._proxies_cycle), (('https://', 'http://localhost:1339'), ('http://', 'http://localhost:1338'))
        )

        with self.assertRaises(ValueError):
            Network(proxies=1)

    def test_get_kwargs_clients(self):
        kwargs = {
            'verify': True,
            'max_redirects': 5,
            'timeout': 2,
            'allow_redirects': True,
        }
        kwargs_client = Network.extract_kwargs_clients(kwargs)

        self.assertEqual(len(kwargs_client), 2)
        self.assertEqual(len(kwargs), 2)

        self.assertEqual(kwargs['timeout'], 2)
        self.assertEqual(kwargs['follow_redirects'], True)

        self.assertTrue(kwargs_client['verify'])
        self.assertEqual(kwargs_client['max_redirects'], 5)

    async def test_get_client(self):
        network = Network(verify=True)
        client1 = await network.get_client()
        client2 = await network.get_client(verify=True)
        client3 = await network.get_client(max_redirects=10)
        client4 = await network.get_client(verify=True)
        client5 = await network.get_client(verify=False)
        client6 = await network.get_client(max_redirects=10)

        self.assertEqual(client1, client2)
        self.assertEqual(client1, client4)
        self.assertNotEqual(client1, client3)
        self.assertNotEqual(client1, client5)
        self.assertEqual(client3, client6)

        await network.aclose()

    async def test_protected_tor_refused_before_client_side_effects(self):
        from wag_protection import ProtectionError  # pylint: disable=import-outside-toplevel

        network = Network(
            protected=True,
            local_addresses=['127.0.0.1', '127.0.0.2'],
            proxies={'https': ['http://localhost:1337', 'http://localhost:1339']},
        )
        # The public attributes may change after constructor validation.
        network.using_tor_proxy = True
        with (
            patch('searx.network.network.new_client') as create_client,
            patch.object(Network, 'check_tor_proxy', return_value=True) as check_tor,
            patch('asyncio.run_coroutine_threadsafe') as schedule,
        ):
            with self.assertRaises(ProtectionError) as refusal:
                await network.get_client()
            create_client.assert_not_called()
            check_tor.assert_not_called()
            schedule.assert_not_called()
            self.assertEqual(next(network._local_addresses_cycle), '127.0.0.1')
            self.assertEqual(next(network._proxies_cycle), (('https://', 'http://localhost:1337'),))
            self.assertEqual(refusal.exception.reason, 'route_unsupported')

    async def test_off_mode_tor_check_and_client_cache_unchanged(self):
        for is_tor in (True, False):
            with self.subTest(is_tor=is_tor), patch.dict(Network._TOR_CHECK_RESULT, {}, clear=True):
                tor_requests = []

                def tor_response(request, result=is_tor, record=tor_requests.append):
                    record(str(request.url))
                    return httpx.Response(200, json={'IsTor': result})

                # Exercise the real Tor check without opening any sockets.
                async with httpx.AsyncClient(transport=httpx.MockTransport(tor_response), trust_env=False) as client:
                    network = Network(using_tor_proxy=True, proxies='http://localhost:1337', protected=False)
                    with patch('searx.network.network.new_client', return_value=client) as create_client:
                        if is_tor:
                            self.assertIs(await network.get_client(), client)
                            self.assertIs(await network.get_client(), client)
                            self.assertFalse(client.is_closed)
                        else:
                            with self.assertRaisesRegex(
                                httpx.ProxyError, 'Network configuration problem: not using Tor'
                            ):
                                await network.get_client()
                            self.assertTrue(client.is_closed)
                        create_client.assert_called_once()
                        self.assertEqual(tor_requests, ['https://check.torproject.org/api/ip'])

    async def test_aclose(self):
        network = Network(verify=True)
        await network.get_client()
        await network.aclose()

    async def test_request(self):
        a_text = 'Lorem Ipsum'
        response = httpx.Response(status_code=200, text=a_text)
        with patch.object(httpx.AsyncClient, 'request', return_value=response):
            network = Network(enable_http=True)
            response = await network.request('GET', 'https://example.com/')
            self.assertEqual(response.text, a_text)
            await network.aclose()


class TestNetworkRequestRetries(SearxTestCase):

    TEXT = 'Lorem Ipsum'

    def setUp(self):
        self.init_test_settings()

    @classmethod
    def get_response_404_then_200(cls):
        first = True

        async def get_response(*args, **kwargs):  # pylint: disable=unused-argument
            nonlocal first
            if first:
                first = False
                return httpx.Response(status_code=403, text=TestNetworkRequestRetries.TEXT)
            return httpx.Response(status_code=200, text=TestNetworkRequestRetries.TEXT)

        return get_response

    async def test_retries_ok(self):
        with patch.object(httpx.AsyncClient, 'request', new=TestNetworkRequestRetries.get_response_404_then_200()):
            network = Network(enable_http=True, retries=1, retry_on_http_error=403)
            response = await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.text, TestNetworkRequestRetries.TEXT)
            await network.aclose()

    async def test_retries_fail_int(self):
        with patch.object(httpx.AsyncClient, 'request', new=TestNetworkRequestRetries.get_response_404_then_200()):
            network = Network(enable_http=True, retries=0, retry_on_http_error=403)
            response = await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.status_code, 403)
            await network.aclose()

    async def test_retries_fail_list(self):
        with patch.object(httpx.AsyncClient, 'request', new=TestNetworkRequestRetries.get_response_404_then_200()):
            network = Network(enable_http=True, retries=0, retry_on_http_error=[403, 429])
            response = await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.status_code, 403)
            await network.aclose()

    async def test_retries_fail_bool(self):
        with patch.object(httpx.AsyncClient, 'request', new=TestNetworkRequestRetries.get_response_404_then_200()):
            network = Network(enable_http=True, retries=0, retry_on_http_error=True)
            response = await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.status_code, 403)
            await network.aclose()

    async def test_retries_exception_then_200(self):
        request_count = 0

        async def get_response(*args, **kwargs):  # pylint: disable=unused-argument
            nonlocal request_count
            request_count += 1
            if request_count < 3:
                raise httpx.RequestError('fake exception', request=None)
            return httpx.Response(status_code=200, text=TestNetworkRequestRetries.TEXT)

        with patch.object(httpx.AsyncClient, 'request', new=get_response):
            network = Network(enable_http=True, retries=2)
            response = await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.text, TestNetworkRequestRetries.TEXT)
            await network.aclose()

    async def test_retries_exception(self):
        async def get_response(*args, **kwargs):
            raise httpx.RequestError('fake exception', request=None)

        with patch.object(httpx.AsyncClient, 'request', new=get_response):
            network = Network(enable_http=True, retries=0)
            with self.assertRaises(httpx.RequestError):
                await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            await network.aclose()


class TestNetworkStreamRetries(SearxTestCase):

    TEXT = 'Lorem Ipsum'

    @staticmethod
    @asynccontextmanager
    async def response_context(response):
        yield response

    def setUp(self):
        self.init_test_settings()

    @classmethod
    def get_response_exception_then_200(cls):
        first = True

        def stream(*args, **kwargs):  # pylint: disable=unused-argument
            nonlocal first
            if first:
                first = False
                raise httpx.RequestError('fake exception', request=None)
            return cls.response_context(httpx.Response(status_code=200, text=cls.TEXT))

        return stream

    async def test_retries_ok(self):
        with patch.object(httpx.AsyncClient, 'stream', new=TestNetworkStreamRetries.get_response_exception_then_200()):
            network = Network(enable_http=True, retries=1, retry_on_http_error=403)
            async with await network.stream('GET', 'https://example.com/') as response:
                self.assertEqual(response.text, TestNetworkStreamRetries.TEXT)
            await network.aclose()

    async def test_retries_fail(self):
        with patch.object(httpx.AsyncClient, 'stream', new=TestNetworkStreamRetries.get_response_exception_then_200()):
            network = Network(enable_http=True, retries=0, retry_on_http_error=403)
            with self.assertRaises(httpx.RequestError):
                async with await network.stream('GET', 'https://example.com/'):
                    self.fail('stream unexpectedly opened')
            await network.aclose()

    async def test_retries_exception(self):
        first = True

        def stream(*args, **kwargs):  # pylint: disable=unused-argument
            nonlocal first
            if first:
                first = False
                return self.response_context(httpx.Response(status_code=403, text=self.TEXT))
            return self.response_context(httpx.Response(status_code=200, text=self.TEXT))

        with patch.object(httpx.AsyncClient, 'stream', new=stream):
            network = Network(enable_http=True, retries=0, retry_on_http_error=403)
            async with await network.stream('GET', 'https://example.com/', raise_for_httperror=False) as response:
                self.assertEqual(response.status_code, 403)
            await network.aclose()
