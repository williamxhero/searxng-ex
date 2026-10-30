# SPDX-License-Identifier: AGPL-3.0-or-later
"""Durable outbound protection; importing the package has no runtime effects."""

from .contract import (
    CONTRACT, VERSION, EngineFailure, EngineOutcome, ProtectionError, Refusal, validate_settings,
    MaintenanceCapability, PoisonSelection, RecoveryProofV1, RecoveryResult, SenderBinding,
)
from .ledger import DispatchNotification, initialize_fixture, migrate_legacy, open_store, recover

__all__ = [
    'CONTRACT', 'VERSION', 'EngineFailure', 'EngineOutcome', 'ProtectionError', 'Refusal',
    'DispatchNotification', 'initialize_fixture', 'migrate_legacy', 'open_store', 'recover', 'validate_settings',
    'MaintenanceCapability', 'PoisonSelection', 'RecoveryProofV1', 'RecoveryResult', 'SenderBinding',
]
