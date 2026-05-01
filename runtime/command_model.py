#!/usr/bin/env python3
"""USBAY command request validation compatibility wrapper."""

from __future__ import annotations

import runtime.policy_validator as policy_validator


class CommandModel:
    REQUIRED_FIELDS = policy_validator.COMMAND_REQUEST_REQUIRED_FIELDS

    def validate_command_request_payload(self, payload: dict) -> bool:
        return policy_validator.validate_command_request_payload(payload)


def validate_command_request_payload(payload: dict) -> bool:
    return command_model.validate_command_request_payload(payload)


command_model = CommandModel()
