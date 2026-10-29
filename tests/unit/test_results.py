# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name


import threading

from searx.result_types import LegacyResult
from searx.results import ResultContainer
from tests import SearxTestCase


class ResultContainerTestCase(SearxTestCase):
    # pylint: disable=use-dict-literal

    TEST_SETTINGS = "test_result_container.yml"

    def test_close_waits_for_inflight_extension_and_seals_evidence(self):
        container = ResultContainer()
        entered, release, closed = threading.Event(), threading.Event(), threading.Event()

        def on_result(_):
            entered.set()
            release.wait(3)
            return True

        container.on_result = on_result
        snapshot = {'status': 'unfinished', 'engines': [{'engine': 'bing', 'status': 'unfinished'}]}
        container.set_outbound_protection(snapshot)
        snapshot['engines'][0]['status'] = 'admitted'
        worker = threading.Thread(
            target=container.extend,
            args=('google', [dict(url='https://fixture.invalid/first', title='First', content='Synthetic')]),
        )

        def close():
            container.close()
            closed.set()

        closer = threading.Thread(target=close)
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            closer.start()
            self.assertFalse(closed.wait(0.05), 'close raced past an in-flight extension')
        finally:
            release.set()
            worker.join(3)
            if closer.ident is not None:
                closer.join(3)
        self.assertFalse(worker.is_alive())
        self.assertFalse(closer.is_alive())
        self.assertEqual(len(container.get_ordered_results()), 1)
        container.extend('google', [dict(url='https://fixture.invalid/late', title='Late')])
        self.assertEqual(len(container.get_ordered_results()), 1)
        self.assertEqual(container.outbound_protection['engines'][0]['status'], 'unfinished')
        detached = container.outbound_protection
        detached['status'] = 'complete'
        self.assertEqual(container.outbound_protection['status'], 'unfinished')
        with self.assertRaises(RuntimeError):
            container.set_outbound_protection({'status': 'complete'})

    def test_empty(self):
        container = ResultContainer()
        self.assertEqual(container.get_ordered_results(), [])

    def test_one_result(self):
        result = dict(url="https://example.org", title="title ..", content="Lorem ..")

        container = ResultContainer()
        container.extend("google", [result])
        container.close()

        self.assertEqual(len(container.get_ordered_results()), 1)

        res = LegacyResult(result)
        res.normalize_result_fields()
        self.assertIn(res, container.get_ordered_results())

    def test_one_suggestion(self):
        result = dict(suggestion="lorem ipsum ..")

        container = ResultContainer()
        container.extend("duckduckgo", [result])
        container.close()

        self.assertEqual(len(container.get_ordered_results()), 0)
        self.assertEqual(len(container.suggestions), 1)
        self.assertIn(result["suggestion"], container.suggestions)

    def test_merge_url_result(self):
        # from the merge of eng1 and eng2 we expect this result
        result = LegacyResult(
            url="https://example.org", title="very long title, lorem ipsum", content="Lorem ipsum dolor sit amet .."
        )
        result.normalize_result_fields()
        eng1 = dict(url=result.url, title="short title", content=result.content, engine="google")
        eng2 = dict(url="http://example.org", title=result.title, content="lorem ipsum", engine="duckduckgo")

        container = ResultContainer()
        container.extend(None, [eng1, eng2])
        container.close()

        result_list = container.get_ordered_results()
        self.assertEqual(len(container.get_ordered_results()), 1)
        self.assertIn(result, result_list)
        self.assertEqual(result_list[0].title, result.title)
        self.assertEqual(result_list[0].content, result.content)
