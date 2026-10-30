# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring, too-few-public-methods

__all__ = ["SearchWithPlugins"]

import typing as t

import threading
from timeit import default_timer
from uuid import uuid4

from flask import copy_current_request_context

from searx import logger
from searx import settings
import searx.answerers
import searx.plugins
from searx.engines import load_engines
from searx.external_bang import get_bang_url
from searx.metrics import initialize as initialize_metrics, counter_inc
from searx.network import initialize as initialize_network, check_network_configuration
from searx.results import ResultContainer
from searx.search.processors import PROCESSORS
from searx.search.processors.abstract import RequestParams

if t.TYPE_CHECKING:
    from .models import SearchQuery
    from searx.extended_types import SXNG_Request

logger = logger.getChild('search')


def initialize(
    settings_engines: list[dict[str, t.Any]] = None,  # pyright: ignore[reportArgumentType]
    check_network: bool = False,
    enable_metrics: bool = True,
):
    settings_engines = settings_engines or settings['engines']
    if settings['outgoing'].get('wag_protection', {}).get('enabled', False) is not False:
        from searx.network.protected import validate_engine_settings  # pylint: disable=import-outside-toplevel

        for engine_data in settings_engines:
            if not engine_data.get('inactive', False):
                validate_engine_settings(engine_data)
    load_engines(settings_engines)
    initialize_network(settings_engines, settings['outgoing'])
    if check_network:
        check_network_configuration()
    initialize_metrics([engine['name'] for engine in settings_engines], enable_metrics)
    PROCESSORS.init(settings_engines)


class Search:
    """Search information container"""

    def __init__(self, search_query: "SearchQuery"):
        """Initialize the Search"""
        # init vars
        super().__init__()
        self.search_query: "SearchQuery" = search_query
        self.result_container: ResultContainer = ResultContainer()
        self.start_time: float | None = None
        self.actual_timeout: float | None = None
        self._protection_lock = threading.Lock()
        self._protection_cancelled = False
        self._protection_observer = None

    @property
    def outbound_protection(self):
        return self.result_container.outbound_protection

    def cancel(self):
        """Notify this Search's protected worker; never touch its ledger or lock."""
        with self._protection_lock:
            self._protection_cancelled = True
            if self._protection_observer is not None:
                self._protection_observer.cancel()

    def search_external_bang(self) -> bool:
        """Check if there is a external bang.  If yes, update
        self.result_container and return True."""
        if self.search_query.external_bang:
            self.result_container.redirect_url = get_bang_url(self.search_query)

            # This means there was a valid bang and the rest of the search does
            # not need to be continued
            if isinstance(self.result_container.redirect_url, str):
                return True
        return False

    def search_answerers(self):

        results = searx.answerers.STORAGE.ask(self.search_query.query)
        self.result_container.extend(None, results)  # pyright: ignore[reportArgumentType]
        return bool(results)

    # do search-request
    def _get_requests(self) -> tuple[list[tuple[str, str, RequestParams]], float]:
        # init vars
        requests: list[tuple[str, str, RequestParams]] = []

        # max of all selected engine timeout
        default_timeout = 0

        # start search-request for all selected engines
        for engineref in self.search_query.engineref_list:
            processor = PROCESSORS.get(engineref.name)
            if not processor:
                # engine does not exists; not yet or the 'init' method of the
                # engine has been failed and the engine has not been registered.
                continue

            # stop the request now if the engine is suspend
            if processor.extend_container_if_suspended(self.result_container):
                continue

            # set default request parameters
            request_params = processor.get_params(self.search_query, engineref.category)
            if request_params is None:
                continue

            counter_inc('engine', engineref.name, 'search', 'count', 'sent')

            # append request to list
            requests.append((engineref.name, self.search_query.query, request_params))

            # update default_timeout
            default_timeout = max(default_timeout, processor.engine.timeout)

        # adjust timeout
        max_request_timeout = settings['outgoing']['max_request_timeout']
        actual_timeout = default_timeout
        query_timeout = self.search_query.timeout_limit

        if max_request_timeout is None and query_timeout is None:
            # No max, no user query: default_timeout
            pass
        elif max_request_timeout is None and query_timeout is not None:
            # No max, but user query: From user query except if above default
            actual_timeout = min(default_timeout, query_timeout)
        elif max_request_timeout is not None and query_timeout is None:
            # Max, no user query: Default except if above max
            actual_timeout = min(default_timeout, max_request_timeout)
        elif max_request_timeout is not None and query_timeout is not None:
            # Max & user query: From user query except if above max
            actual_timeout = min(query_timeout, max_request_timeout)

        logger.debug(
            "actual_timeout={0} (default_timeout={1}, ?timeout_limit={2}, max_request_timeout={3})".format(
                actual_timeout, default_timeout, query_timeout, max_request_timeout
            )
        )

        return requests, actual_timeout

    def search_multiple_requests(self, requests: list[tuple[str, str, RequestParams]]):
        # pylint: disable=protected-access
        search_id = str(uuid4())

        for engine_name, query, request_params in requests:
            _search = copy_current_request_context(PROCESSORS[engine_name].search)
            th = threading.Thread(  # pylint: disable=invalid-name
                target=_search,
                args=(query, request_params, self.result_container, self.start_time, self.actual_timeout),
                name=search_id,
            )
            th._timeout = False
            th._engine_name = engine_name
            th.start()

        for th in threading.enumerate():  # pylint: disable=invalid-name
            if th.name == search_id:
                remaining_time = max(0.0, self.actual_timeout - (default_timer() - self.start_time))
                th.join(remaining_time)
                if th.is_alive():
                    th._timeout = True
                    self.result_container.add_unresponsive_engine(th._engine_name, 'timeout')
                    PROCESSORS[th._engine_name].logger.error('engine timeout')

    def _search_protected(self, store, requests):
        from wag_protection import Refusal  # pylint: disable=import-outside-toplevel

        aliases = (
            {}
            if isinstance(store, Refusal)
            else {alias: entry['engine'] for entry in store.manifest['registry'] for alias in entry['aliases']}
        )
        refs = []
        for engineref in sorted(
            self.search_query.engineref_list, key=lambda ref: (aliases.get(ref.name, ref.name), ref.category)
        ):
            ref = {
                'engine': aliases.get(engineref.name, engineref.name),
                'category': engineref.category,
                'status': 'refused',
                'reason': None,
                'outcome': None,
                'reservations': 0,
                'connection_attempts': None,
                'http_attempts': None,
                'result_count': None,
                'elapsed_s': None,
                'deadline_exceeded': False,
            }
            refs.append(ref)
            if isinstance(store, Refusal):
                ref['reason'] = store.reason
                continue
            processor = PROCESSORS.get(engineref.name)
            params = next(
                (
                    params
                    for name, _, params in requests
                    if name == engineref.name and params['category'] == engineref.category
                ),
                None,
            )
            if processor is None or not hasattr(processor, 'search_protected'):
                ref['reason'] = 'capability_refused'
                continue
            if processor.suspended_status.is_suspended:
                ref['reason'] = 'cooldown'
                continue
            if params is None:
                ref.update(status='skipped')
                continue
            remaining = self.start_time + self.actual_timeout - default_timer()
            if remaining <= 0:
                ref.update(reason='deadline_exceeded', deadline_exceeded=True)
                continue
            outcome, observer = self._run_protected_request(store, processor, params)
            if observer is None:
                ref.update(reason='cancelled')
                continue
            if outcome is None:
                ref.update(
                    status='unfinished',
                    reason='unfinished_attempt',
                    reservations=observer.reservations,
                    deadline_exceeded=True,
                )
                continue
            if isinstance(outcome, Refusal):
                ref['reason'] = outcome.reason
                if outcome.reason == 'unfinished_attempt':
                    ref.update(status='unfinished', reservations=observer.reservations, deadline_exceeded=True)
                continue
            ref.update(
                status='admitted',
                outcome=outcome.outcome,
                reservations=outcome.reservations,
                connection_attempts=outcome.connection_attempts,
                http_attempts=outcome.http_attempts,
                result_count=outcome.result_count,
                elapsed_s=outcome.elapsed_s,
                deadline_exceeded=outcome.deadline_exceeded,
            )
            if outcome.outcome in ('ok', 'empty'):
                processor.extend_container(self.result_container, self.start_time, outcome.results)
            else:
                self.result_container.add_unresponsive_engine(engineref.name, outcome.outcome)
        self._publish_protected_snapshot(store, refs)

    def _run_protected_request(self, store, processor, params):
        """Own one observer/thread lifecycle without releasing its worker's lock."""
        from wag_protection import DispatchNotification, Refusal  # pylint: disable=import-outside-toplevel

        completed = []
        observer = DispatchNotification()
        with self._protection_lock:
            if self._protection_cancelled:
                # No dispatch was scheduled; retain the existing ref-level reason.
                return None, None
            self._protection_observer = observer

        def work(processor, params, completed, observer):
            try:
                completed.append(
                    processor.search_protected(
                        self.search_query.query,
                        params,
                        store,
                        self.start_time,
                        self.actual_timeout,
                        observer=observer,
                    )
                )
            # Keep arbitrary engine exception text out of machine evidence.
            except Exception:  # pylint: disable=broad-exception-caught
                completed.append(Refusal('storage_error'))

        thread = threading.Thread(
            target=copy_current_request_context(work), args=(processor, params, completed, observer), daemon=True
        )
        try:
            thread.start()
            thread.join(max(0, self.start_time + self.actual_timeout - default_timer()))
        except BaseException:
            observer.notify()
            raise
        finally:
            with self._protection_lock:
                self._protection_observer = None
        if thread.is_alive():
            # Its worker retains the flock/DB and seals unfinished state.
            return observer.notify(), observer
        return completed[0], observer

    def _publish_protected_snapshot(self, store, refs):
        """Publish sealed machine evidence without performing engine work."""
        from wag_protection import Refusal  # pylint: disable=import-outside-toplevel

        if all(
            (ref['status'] == 'admitted' and ref['outcome'] in ('ok', 'empty'))
            or (ref['status'] == 'skipped' and ref['reason'] is None)
            for ref in refs
        ):
            status = 'complete'
        elif any(ref['status'] == 'unfinished' for ref in refs):
            status = 'unfinished'
        elif any(ref['status'] == 'admitted' for ref in refs):
            status = 'partial'
        else:
            status = 'refused'
        from searx.network.protected import (  # pylint: disable=import-outside-toplevel
            protection_descriptor,
            resolved_config_digest,
        )

        manifest = protection_descriptor() if isinstance(store, Refusal) else store.manifest
        self.result_container.set_outbound_protection(
            {
                'version': 2,
                'enabled': True,
                'contract': 'wag.outbound.v2',
                'artifact_digest': manifest.get('artifact_digest'),
                'registry_digest': manifest.get('registry_digest'),
                'config_digest': resolved_config_digest(settings['engines'], settings['outgoing']),
                'status': status,
                'retryable': status == 'complete',
                'engines': refs,
            }
        )

    def search_standard(self):
        """
        Update self.result_container, self.actual_timeout
        """
        if settings['outgoing'].get('wag_protection', {}).get('enabled', False) is not False:
            from wag_protection import Refusal  # pylint: disable=import-outside-toplevel
            from searx.network.protected import get_store  # pylint: disable=import-outside-toplevel

            store = get_store()
            if isinstance(store, Refusal):
                self.actual_timeout = 0
                self._search_protected(store, [])
            else:
                requests, self.actual_timeout = self._get_requests()
                self.actual_timeout = min(self.actual_timeout, 3.0)
                self._search_protected(store, requests)
            return True
        requests, self.actual_timeout = self._get_requests()

        # send all search-request
        if requests:
            self.search_multiple_requests(requests)

        # return results, suggestions, answers and infoboxes
        return True

    # do search-request
    def search(self) -> ResultContainer:
        self.start_time = default_timer()
        if not self.search_external_bang():
            if not self.search_answerers():
                self.search_standard()
        return self.result_container


class SearchWithPlugins(Search):
    """Inherit from the Search class, add calls to the plugins."""

    def __init__(self, search_query: "SearchQuery", request: "SXNG_Request", user_plugins: list[str]):
        super().__init__(search_query)
        self.user_plugins = user_plugins
        self.result_container.on_result = self._on_result
        # pylint: disable=line-too-long
        # get the "real" request to use it outside the Flask context.
        # see
        # * https://github.com/pallets/flask/blob/d01d26e5210e3ee4cbbdef12f05c886e08e92852/src/flask/globals.py#L55
        # * https://github.com/pallets/werkzeug/blob/3c5d3c9bd0d9ce64590f0af8997a38f3823b368d/src/werkzeug/local.py#L548-L559
        # * https://werkzeug.palletsprojects.com/en/2.0.x/local/#werkzeug.local.LocalProxy._get_current_object
        # pylint: enable=line-too-long
        self.request = request._get_current_object()

    def _on_result(self, result):
        return searx.plugins.STORAGE.on_result(self.request, self, result)

    def search(self) -> ResultContainer:

        if searx.plugins.STORAGE.pre_search(self.request, self):
            super().search()

        searx.plugins.STORAGE.post_search(self.request, self)
        self.result_container.close()

        return self.result_container
