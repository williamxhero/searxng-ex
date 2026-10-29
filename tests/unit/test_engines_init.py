# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from searx import settings, engines
from wag_protection import ProtectionError
from tests import SearxTestCase


class TestEnginesInit(SearxTestCase):

    def test_initialize_engines_default(self):
        engine_list = [
            {'engine': 'dummy', 'name': 'engine1', 'shortcut': 'e1'},
            {'engine': 'dummy', 'name': 'engine2', 'shortcut': 'e2'},
        ]

        engines.load_engines(engine_list)
        self.assertEqual(len(engines.engines), 2)
        self.assertIn('engine1', engines.engines)
        self.assertIn('engine2', engines.engines)

    def test_load_engine_refuses_shadow_source_before_loader(self):
        approved = {'module': 'bing'}
        with (
            patch.dict(settings['outgoing'], {'wag_protection': {'enabled': True}}),
            patch('searx.network.protected.validate_engine_settings', return_value=approved),
            patch(
                'searx.network.protected.validate_engine_source',
                side_effect=ProtectionError('provenance_error'),
            ),
            patch('searx.engines.load_module') as load_module,
        ):
            with self.assertRaises(ProtectionError):
                engines.load_engine({'name': 'bing', 'engine': 'bing'})

        load_module.assert_not_called()

    def test_load_engine_rechecks_loaded_source_after_loader(self):
        approved = {'module': 'bing'}
        store = SimpleNamespace(manifest={})
        loaded = SimpleNamespace()
        with (
            patch.dict(settings['outgoing'], {'wag_protection': {'enabled': True}}),
            patch('searx.network.protected.validate_engine_settings', return_value=approved),
            patch('searx.network.protected.validate_engine_source', return_value=Path('/approved/bing.py')),
            patch('searx.network.protected.get_store', return_value=store),
            patch(
                'searx.network.protected.validate_loaded_engine_source',
                side_effect=ProtectionError('provenance_error'),
            ) as validate_loaded,
            patch('searx.engines.load_module', return_value=loaded) as load_module,
        ):
            result = engines.load_engine({'name': 'bing', 'engine': 'bing'})

        self.assertIsNone(result)
        load_module.assert_called_once_with('bing.py', engines.ENGINE_DIR)
        validate_loaded.assert_called_once_with(loaded, Path('/approved/bing.py'), approved, {})

    def test_initialize_engines_exclude_onions(self):
        settings['outgoing']['using_tor_proxy'] = False
        engine_list = [
            {'engine': 'dummy', 'name': 'engine1', 'shortcut': 'e1', 'categories': 'general'},
            {'engine': 'dummy', 'name': 'engine2', 'shortcut': 'e2', 'categories': 'onions'},
        ]

        engines.load_engines(engine_list)
        self.assertEqual(len(engines.engines), 1)
        self.assertIn('engine1', engines.engines)
        self.assertNotIn('onions', engines.categories)

    def test_initialize_engines_include_onions(self):
        settings['outgoing']['using_tor_proxy'] = True
        settings['outgoing']['extra_proxy_timeout'] = 100.0
        engine_list = [
            {
                'engine': 'dummy',
                'name': 'engine1',
                'shortcut': 'e1',
                'categories': 'general',
                'timeout': 20.0,
                'onion_url': 'http://engine1.onion',
            },
            {'engine': 'dummy', 'name': 'engine2', 'shortcut': 'e2', 'categories': 'onions'},
        ]

        engines.load_engines(engine_list)
        self.assertEqual(len(engines.engines), 2)
        self.assertIn('engine1', engines.engines)
        self.assertIn('engine2', engines.engines)
        self.assertIn('onions', engines.categories)
        self.assertIn('http://engine1.onion', engines.engines['engine1'].search_url)
        self.assertEqual(engines.engines['engine1'].timeout, 120.0)

    def test_missing_name_field(self):
        settings['outgoing']['using_tor_proxy'] = False
        engine_list = [
            {'engine': 'dummy', 'shortcut': 'e1', 'categories': 'general'},
        ]
        with self.assertLogs('searx.engines', level='ERROR') as cm:  # pylint: disable=invalid-name
            engines.load_engines(engine_list)
            self.assertEqual(len(engines.engines), 0)
            self.assertEqual(cm.output[0], 'ERROR:searx.engines:An engine does not have a "name" field')

    def test_missing_engine_field(self):
        settings['outgoing']['using_tor_proxy'] = False
        engine_list = [
            {'name': 'engine2', 'shortcut': 'e2', 'categories': 'onions'},
        ]
        with self.assertLogs('searx.engines', level='ERROR') as cm:  # pylint: disable=invalid-name
            engines.load_engines(engine_list)
            self.assertEqual(len(engines.engines), 0)
            self.assertEqual(
                cm.output[0], 'ERROR:searx.engines:The "engine" field is missing for the engine named "engine2"'
            )
