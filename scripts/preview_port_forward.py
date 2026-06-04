"""Dev-preview TCP forwarder.

Why this exists: the Replit dev proxy maps externalPort 80 (the bare preview
domain and the workspace tooling) to localPort 8765, but the gateway listens on
port 5000. With nothing on 8765 the bare domain returns HTTP 502. This script
forwards 8765 -> 5000 so the standard preview URL reaches the running app.

It does NOT touch governance / Euria / USBAY decision logic. It is a plain
byte-for-byte TCP relay used only for local dev preview routing.
"""

import asyncio
import os

LISTEN_HOST = os.environ.get("FORWARD_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("FORWARD_LISTEN_PORT", "8765"))
TARGET_HOST = os.environ.get("FORWARD_TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("FORWARD_TARGET_PORT", "5000"))


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass


async def _handle(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    try:
        server_reader, server_writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
    except OSError:
        try:
            client_writer.close()
        except OSError:
            pass
        return
    await asyncio.gather(
        _pipe(client_reader, server_writer),
        _pipe(server_reader, client_writer),
    )


async def _main() -> None:
    try:
        server = await asyncio.start_server(
            _handle, LISTEN_HOST, LISTEN_PORT, reuse_address=True
        )
    except OSError as exc:
        print(f"[preview-forward] could not bind {LISTEN_HOST}:{LISTEN_PORT}: {exc}", flush=True)
        return
    print(
        f"[preview-forward] forwarding {LISTEN_HOST}:{LISTEN_PORT} -> {TARGET_HOST}:{TARGET_PORT}",
        flush=True,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
