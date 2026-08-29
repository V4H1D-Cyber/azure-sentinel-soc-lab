#!/usr/bin/env python3
"""
Controlled RDP brute-force validation script — see README.md section 3.9.

Sends a series of real RDP/CredSSP authentication attempts (genuine network
protocol exchanges, intentionally wrong passwords) at the honeypot's public
IP, using the `aardwolf` pure-Python RDP client library. Each attempt
produces a real Windows Security EventID 4625 on the target VM, the same
way an actual attacker's failed login would — nothing here fabricates or
injects log data directly.

This was run once, from an external machine, to validate that the deployed
Sentinel analytics rule (rdp-brute-force-detected) actually fires against
real traffic, after Azure itself blocked provisioning a second VM in this
subscription for the same purpose (see README.md section 3.9 for details).

Requires: pip install aardwolf   (needs a Rust toolchain to build on some
platforms — see https://rustup.rs if `pip install` fails with a Rust
compiler error).

Usage:
    python3 rdp_validate.py <target-ip> <username> [attempt-count]
"""
import asyncio
import sys

from aardwolf.commons.factory import RDPConnectionFactory
from aardwolf.commons.iosettings import RDPIOSettings


async def attempt(target_ip: str, username: str, password: str, n: int) -> None:
    url = f"RDP+ntlm-password://{username}:{password}@{target_ip}"
    ios = RDPIOSettings()
    try:
        factory = RDPConnectionFactory.from_url(url, ios)
        connection = factory.get_connection(ios)
        _, err = await asyncio.wait_for(connection.connect(), timeout=10)
        print(f"[{n}] pw={password!r} err={err}")
        try:
            await connection.disconnect()
        except Exception:
            pass
    except Exception as e:
        print(f"[{n}] pw={password!r} exception={e!r}")


async def main() -> None:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target-ip> <username> [attempt-count]")
        sys.exit(1)

    target_ip = sys.argv[1]
    username = sys.argv[2]
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 15

    for n in range(1, count + 1):
        await attempt(target_ip, username, f"WrongPass{n}!Xy", n)
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
