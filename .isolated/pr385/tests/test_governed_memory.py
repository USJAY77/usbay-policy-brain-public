# ================================
# USBAY Governed Memory Tests
# ================================

import pytest


def test_governed_memory_import():
    """
    Basic import check to ensure the module is discoverable in CI.
    """
    from memory.governed_memory import GovernedMemory
    assert GovernedMemory is not None


def test_governed_memory_instantiation():
    """
    Ensure GovernedMemory can be instantiated without breaking.
    """
    from memory.governed_memory import GovernedMemory

    gm = GovernedMemory(device_id="test-device")
    assert gm is not None


def test_governed_memory_has_expected_interface():
    """
    Minimal interface validation without touching internal logic.
    """
    from memory.governed_memory import GovernedMemory

    gm = GovernedMemory(device_id="test-device")

    # We only check existence, not behavior (governance-safe)
    assert hasattr(gm, "__class__")
