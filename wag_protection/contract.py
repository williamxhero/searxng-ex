# SPDX-License-Identifier: AGPL-3.0-or-later
"""The canonical outbound-protection wire and storage contract."""

from dataclasses import dataclass, field
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Literal, NotRequired, TypeGuard, TypedDict, cast

CONTRACT = 'wag.outbound.v2'
VERSION = 2
PRODUCTION_ROOT = Path('/var/lib/wag-route-probe')
CALLERS = frozenset(('native_search', 'native_init', 'probe', 'release', 'legacy_probe'))
PHASES = frozenset(('engine_http', 'proxy_connect', 'connection_only', 'legacy'))
OUTCOMES = frozenset((
    'ok', 'empty', 'captcha', 'access_denied', 'rate_limited', 'challenge_unknown', 'timeout',
    'error', 'parser_error', 'response_limit', 'redirect_refused', 'protocol_retry_refused',
    'helper_refused', 'interrupted', 'runtime_error', 'request_refused', 'cancelled', 'not_sent',
    'unknown_terminated',
))
REASONS = frozenset((
    'engine_rate', 'domestic_rate', 'cooldown', 'operator_hold', 'lock_busy', 'storage_error',
    'clock_error', 'unfinished_attempt', 'identity_error', 'schema_error', 'import_error',
    'provenance_error', 'capability_refused', 'route_unsupported', 'deadline_exceeded',
    'helper_refused', 'redirect_refused', 'protocol_retry_refused', 'challenge_unknown',
    'release_consumed', 'evidence_unknown',
))
MANIFEST_FIELDS = frozenset((
    'schema', 'contract', 'mode', 'fork_commit', 'artifact_digest', 'registry_digest',
    'config_digest', 'python_digest', 'module_root', 'python_executable', 'root', 'shared_gid',
    'allowed_uids', 'files', 'distributions', 'wheels', 'registry',
))
ARTIFACT_FIELDS = (
    'contract', 'fork_commit', 'files', 'distributions', 'wheels', 'registry_digest', 'python_digest',
)


class DisabledSettings(TypedDict):
    enabled: Literal[False]
    root: NotRequired[str | os.PathLike[str]]
    artifact_manifest: NotRequired[str | os.PathLike[str]]


class EnabledSettings(TypedDict):
    enabled: Literal[True]
    root: str | os.PathLike[str]
    artifact_manifest: str | os.PathLike[str]


Settings = DisabledSettings | EnabledSettings


@dataclass(frozen=True)
class Refusal:
    reason: str

    def __post_init__(self):
        if self.reason not in REASONS:
            raise ValueError('invalid refusal reason')

    status = 'refused'
    retryable = False


@dataclass(frozen=True)
class EngineOutcome:
    engine: str
    outcome: str
    reservations: int
    connection_attempts: int | None
    http_attempts: int | None
    result_count: int | None
    elapsed_s: float | None
    deadline_exceeded: bool
    results: object = None


RECOVERY_DECISIONS = frozenset(('clock_reanchor', 'terminated_sender', 'combined'))
_MAINTENANCE_TOKEN = object()


def recovery_authorization(value):
    try:
        return (type(value) is str and 1 <= len(value.encode('utf-8')) <= 256
                and bool(value.strip()) and all(char.isprintable() for char in value))
    except UnicodeError:
        return False


class _EphemeralMaintenance:
    __slots__ = ()

    def __reduce_ex__(self, protocol):
        raise TypeError('maintenance witnesses cannot be serialized')


@dataclass(frozen=True, slots=True)
class PoisonSelection:
    rowid: int
    reason: str

    def __post_init__(self):
        if (type(self.rowid) is not int or self.rowid <= 0 or type(self.reason) is not str
                or self.reason not in ('clock_error', 'unfinished_attempt')):
            raise ValueError('invalid poison selection')


@dataclass(frozen=True, slots=True)
class MaintenanceCapability(_EphemeralMaintenance):
    authorization: str
    decision: str
    root: Path
    boot: str
    issued_mono: float
    deadline_mono: float
    clear_poison: tuple[PoisonSelection, ...]
    _issuance: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self._issuance is not _MAINTENANCE_TOKEN:
            raise TypeError('private maintenance issuance')


@dataclass(frozen=True, slots=True)
class SenderBinding(_EphemeralMaintenance):
    pid: int
    start_ticks: int
    boot: str
    attempt_ids: tuple[int, ...]
    _issuance: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self._issuance is not _MAINTENANCE_TOKEN:
            raise TypeError('private sender issuance')


@dataclass(frozen=True, slots=True)
class RecoveryProofV1(_EphemeralMaintenance):
    version: int
    capability: MaintenanceCapability
    approved_manifest: object = field(repr=False)
    sender_bindings: tuple[SenderBinding, ...]
    _witness: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self._witness is None:
            raise TypeError('private recovery issuance')


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    recovery_id: int
    decision: str
    terminated_count: int
    reanchored_count: int


class ProtectionError(Exception):
    """A typed refusal without exposing exception text or secret input."""

    def __init__(self, reason):
        if reason not in REASONS:
            raise ValueError('invalid refusal reason')
        super().__init__(reason)
        self.reason = reason


class EngineFailure(Exception):
    """A native adapter's classified failure, with no request or raw cause."""

    def __init__(self, outcome, *, suspension_s=0):
        if outcome not in OUTCOMES or not finite(suspension_s):
            raise ValueError('invalid engine failure')
        super().__init__(outcome)
        self.outcome = outcome
        self.suspension_s = suspension_s


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def json_digest(value):
    return hashlib.sha256(canonical_json(value).encode('utf-8')).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def load_json(text):
    return json.loads(text, object_pairs_hook=_unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def finite(value):
    return type(value) in (float, int) and math.isfinite(value) and value >= 0


def hex_value(value, size):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None


def canonical_path(value):
    path = Path(value)
    if not path.is_absolute() or str(path) != str(value) or path.resolve() != path:
        raise ValueError('noncanonical path')
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('symlink path')
    return path


def _settings_shape(value: dict[str, object]) -> TypeGuard[Settings]:
    enabled = value.get('enabled')
    return (type(enabled) is bool and not set(value) - {'enabled', 'root', 'artifact_manifest'}
            and (not enabled or all(key in value for key in ('root', 'artifact_manifest')))
            and all(isinstance(value[key], (str, os.PathLike))
                    for key in ('root', 'artifact_manifest') if key in value))


def validate_settings(value: object) -> Settings:
    """Validate raw protection values before SearXNG's bool coercion."""
    if not isinstance(value, dict) or set(value) - {'enabled', 'root', 'artifact_manifest'}:
        raise ValueError('invalid protection configuration')
    raw = cast(dict[str, object], value)
    enabled = raw.get('enabled', False)
    if type(enabled) is not bool:
        raise ValueError('protection enabled must be a boolean')
    result = {'enabled': False, **raw}
    for key in ('root', 'artifact_manifest'):
        if key in raw:
            canonical_path(raw[key])
        elif enabled:
            raise ValueError('missing protection path')
    if not _settings_shape(result):
        raise ValueError('invalid protection configuration')
    return result


def validate_evidence(value):
    if not isinstance(value, dict) or set(value) != {
        'version', 'release_id', 'artifact_digest', 'config_digest', 'checked_at', 'age_s', 'search', 'egress',
    }:
        raise ValueError('invalid public evidence fields')
    if type(value['version']) is not int or value['version'] != VERSION or not hex_value(value['release_id'], 32):
        raise ValueError('invalid evidence version')
    if not all(hex_value(value[key], 64) for key in ('artifact_digest', 'config_digest')) or not finite(value['age_s']):
        raise ValueError('invalid evidence fingerprint')
    if not isinstance(value['checked_at'], str) or len(value['checked_at']) > 80:
        raise ValueError('invalid evidence date')
    from datetime import datetime  # pylint: disable=import-outside-toplevel
    if datetime.fromisoformat(value['checked_at']).tzinfo is None:
        raise ValueError('evidence date needs timezone')
    search = value['search']
    if not isinstance(search, dict) or set(search) != {
        'status', 'result_count', 'responsive_engine_count', 'protection_status', 'quality_evidence_digest', 'reason',
    }:
        raise ValueError('invalid search evidence')
    if search['status'] not in ('passed', 'degraded', 'refused', 'not_checked', 'unknown'):
        raise ValueError('invalid search status')
    for key in ('result_count', 'responsive_engine_count'):
        if search[key] is not None and (type(search[key]) is not int or search[key] < 0):
            raise ValueError('invalid evidence count')
    if search['protection_status'] not in (None, 'complete', 'partial', 'refused', 'unfinished'):
        raise ValueError('invalid protection status')
    if search['quality_evidence_digest'] is not None and not hex_value(search['quality_evidence_digest'], 64):
        raise ValueError('invalid quality digest')
    if search['reason'] is not None and search['reason'] not in REASONS | {
        'empty', 'quality_failed', 'public_not_checked', 'operation_failed',
    }:
        raise ValueError('invalid search reason')
    if search['status'] == 'passed' and (
        search['reason'] is not None or not search['result_count'] or search['responsive_engine_count'] is None
        or search['responsive_engine_count'] < 2 or search['protection_status'] != 'complete'
        or search['quality_evidence_digest'] is None
    ):
        raise ValueError('passed search lacks usable evidence')
    egress = value['egress']
    if not isinstance(egress, dict) or set(egress) != {'status', 'reason'}:
        raise ValueError('invalid egress evidence')
    if egress['status'] not in ('passed', 'degraded', 'not_checked') or egress['reason'] not in (
        None, 'not_checked', 'connect_failed', 'deadline_exceeded', 'provenance_error',
    ) or (egress['status'] == 'passed' and egress['reason'] is not None):
        raise ValueError('invalid egress status')
    if len(canonical_json(value).encode()) > 16384:
        raise ValueError('evidence too large')
    return value


def validate_registry(registry):
    if not isinstance(registry, list) or not registry or len(registry) > 64:
        raise ValueError('invalid registry')
    names = []
    aliases = set()
    for entry in registry:
        if not isinstance(entry, dict) or set(entry) != {
            'engine', 'domestic', 'module', 'capability', 'source_digest', 'profile', 'aliases',
        }:
            raise ValueError('invalid registry entry')
        name = entry['engine']
        if not isinstance(name, str) or not 1 <= len(name) <= 80 or name in names:
            raise ValueError('invalid engine identity')
        names.append(name)
        if type(entry['domestic']) is not bool or entry['capability'] != 'online_one_send':
            raise ValueError('invalid capability')
        if not isinstance(entry['module'], str) or not re.fullmatch('[a-z][a-z0-9_]*', entry['module']):
            raise ValueError('invalid module')
        if not hex_value(entry['source_digest'], 64):
            raise ValueError('invalid source digest')
        profile = entry['profile']
        if not isinstance(profile, dict) or type(profile.get('live_hold')) is not bool:
            raise ValueError('invalid hold profile')
        if len(canonical_json(profile).encode()) > 8192:
            raise ValueError('profile too large')
        entry_aliases = entry['aliases']
        if not isinstance(entry_aliases, list) or name not in entry_aliases:
            raise ValueError('missing canonical alias')
        for alias in entry_aliases:
            if not isinstance(alias, str) or not 1 <= len(alias) <= 80 or alias in aliases:
                raise ValueError('alias collision')
            aliases.add(alias)
    if names != sorted(names):
        raise ValueError('registry must be ordered')
    return registry


def validate_manifest(manifest, root, mode):
    if not isinstance(manifest, dict):
        path = canonical_path(manifest)
        if not path.is_file() or path.stat().st_size > 131072:
            raise ValueError('invalid manifest file')
        manifest = load_json(path.read_text(encoding='utf-8'))
    # Copy through canonical JSON so the caller cannot mutate an approved handle.
    manifest = load_json(canonical_json(manifest))
    if set(manifest) != MANIFEST_FIELDS or len(canonical_json(manifest).encode()) > 131072:
        raise ValueError('invalid manifest fields')
    if manifest['schema'] != 'wag.protection-artifact.v2' or manifest['contract'] != CONTRACT:
        raise ValueError('invalid manifest contract')
    if mode not in ('production', 'synthetic') or manifest['mode'] != mode:
        raise ValueError('invalid mode')
    root = canonical_path(root)
    if manifest['root'] != str(root) or (mode == 'production' and root != PRODUCTION_ROOT):
        raise ValueError('invalid root')
    if mode == 'synthetic' and (root == PRODUCTION_ROOT or PRODUCTION_ROOT in root.parents):
        raise ValueError('production is not a fixture')
    if not hex_value(manifest['fork_commit'], 40):
        raise ValueError('invalid fork commit')
    for key in ('artifact_digest', 'registry_digest', 'config_digest', 'python_digest'):
        if not hex_value(manifest[key], 64):
            raise ValueError('invalid digest')
    if type(manifest['shared_gid']) is not int or manifest['shared_gid'] <= 0:
        raise ValueError('invalid shared group')
    uids = manifest['allowed_uids']
    if not isinstance(uids, list) or not uids or uids != sorted(set(uids)):
        raise ValueError('invalid allowed writers')
    if any(type(uid) is not int or uid < 0 for uid in uids) or 0 not in uids or os.getuid() not in uids:
        raise ValueError('unapproved writer')
    module_root = canonical_path(manifest['module_root'])
    if module_root != Path(__file__).resolve().parent.parent:
        raise ValueError('shadow module')
    python = canonical_path(manifest['python_executable'])
    if python != Path(sys.executable).resolve() or hashlib.sha256(python.read_bytes()).hexdigest() != manifest['python_digest']:
        raise ValueError('unapproved interpreter')
    files = manifest['files']
    if not isinstance(files, dict) or not files:
        raise ValueError('missing artifact files')
    for name, expected in files.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative) != name or not hex_value(expected, 64):
            raise ValueError('invalid artifact path')
        file = canonical_path(module_root / relative)
        if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            raise ValueError('artifact file mismatch')
    required_files = (
        'wag_protection/__init__.py', 'wag_protection/ledger.py', 'wag_protection/contract.py',
        'searx/data/engine_traits.json', 'searx/engines/__init__.py',
        'searx/settings.yml', 'searx/settings_defaults.py', 'searx/settings_loader.py',
        'searx/network/__init__.py', 'searx/network/client.py', 'searx/network/network.py',
        'searx/network/protected.py', 'searx/search/__init__.py',
        'searx/search/processors/abstract.py', 'searx/search/processors/online.py',
        'searx/results.py', 'searx/webutils.py', 'searx/webapp.py', 'searx/exceptions.py', 'searx/utils.py',
    )
    if any(name not in files for name in required_files):
        raise ValueError('missing native artifact file')
    distributions = manifest['distributions']
    wheels = manifest['wheels']
    if not isinstance(distributions, dict) or not isinstance(wheels, dict):
        raise ValueError('invalid dependencies')
    for name, version in distributions.items():
        if not isinstance(version, str) or importlib.metadata.version(name) != version:
            raise ValueError('dependency mismatch')
    for name, expected in wheels.items():
        if Path(name).name != name or not name.endswith('.whl') or not hex_value(expected, 64):
            raise ValueError('invalid wheel declaration')
        # A declared hash is not provenance without the approved wheel bytes.
        # Bind it to exactly one artifact-relative file already checked above;
        # no extra manifest field or implicit external wheel cache is trusted.
        matches = [path for path, digest in files.items() if Path(path).name == name and digest == expected]
        if len(matches) != 1:
            raise ValueError('unverified wheel artifact')
    registry = validate_registry(manifest['registry'])
    if json_digest(registry) != manifest['registry_digest']:
        raise ValueError('registry mismatch')
    for entry in registry:
        if files.get('searx/engines/' + entry['module'] + '.py') != entry['source_digest']:
            raise ValueError('unapproved engine source')
        if mode == 'production' and entry['engine'] == 'quark' and not entry['profile']['live_hold']:
            raise ValueError('quark must remain held')
    if json_digest({key: manifest[key] for key in ARTIFACT_FIELDS}) != manifest['artifact_digest']:
        raise ValueError('artifact projection mismatch')
    return manifest
