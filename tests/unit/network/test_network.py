# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import copy

import httpx
from mock import patch

from searx import settings
from searx.network.network import Network, NETWORKS
from searx.network.network import initialize
from tests import SearxTestCase


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

    async def test_aclose_waits_for_inflight_request_before_closing_generation(self):
        import asyncio

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

    async def test_aclose_clears_client_pool(self):
        network = Network()
        client = await network.get_client()

        await network.aclose()

        self.assertTrue(client.is_closed)
        self.assertEqual(network._clients, {})

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
            return httpx.Response(status_code=200, text=TestNetworkStreamRetries.TEXT)

        return stream

    async def test_retries_ok(self):
        with patch.object(httpx.AsyncClient, 'stream', new=TestNetworkStreamRetries.get_response_exception_then_200()):
            network = Network(enable_http=True, retries=1, retry_on_http_error=403)
            response = await network.stream('GET', 'https://example.com/')
            self.assertEqual(response.text, TestNetworkStreamRetries.TEXT)
            await network.aclose()

    async def test_retries_fail(self):
        with patch.object(httpx.AsyncClient, 'stream', new=TestNetworkStreamRetries.get_response_exception_then_200()):
            network = Network(enable_http=True, retries=0, retry_on_http_error=403)
            with self.assertRaises(httpx.RequestError):
                await network.stream('GET', 'https://example.com/')
            await network.aclose()

    async def test_retries_exception(self):
        first = True

        def stream(*args, **kwargs):  # pylint: disable=unused-argument
            nonlocal first
            if first:
                first = False
                return httpx.Response(status_code=403, text=TestNetworkRequestRetries.TEXT)
            return httpx.Response(status_code=200, text=TestNetworkRequestRetries.TEXT)

        with patch.object(httpx.AsyncClient, 'stream', new=stream):
            network = Network(enable_http=True, retries=0, retry_on_http_error=403)
            response = await network.stream('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.status_code, 403)
            await network.aclose()
