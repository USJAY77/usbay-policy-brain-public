#!/usr/bin/env python3
"""
Minimal in-process websocket client registry for voice alerts.

This does not open a network listener by itself. It only tracks connected
transport objects that expose `send_json(payload)` or `send(payload)`.
"""

from __future__ import annotations

from typing import Any

_CLIENTS: list[object] = []


def register_client(client: object) -> None:
    if client not in _CLIENTS:
        _CLIENTS.append(client)


def unregister_client(client: object) -> None:
    if client in _CLIENTS:
        _CLIENTS.remove(client)


def has_clients() -> bool:
    return bool(_CLIENTS)


def client_count() -> int:
    return len(_CLIENTS)


def broadcast_json(payload: dict[str, Any]) -> int:
    sent = 0
    for client in list(_CLIENTS):
        try:
            if hasattr(client, "send_json"):
                client.send_json(payload)
            elif hasattr(client, "send"):
                client.send(payload)
            else:
                unregister_client(client)
                continue
            sent += 1
        except Exception:
            unregister_client(client)
    return sent
