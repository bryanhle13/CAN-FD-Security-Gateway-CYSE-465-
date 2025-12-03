"""
can_fd_defense_fair_gateway.py

Improved gateway-based defense against high-priority flooding.

Changes vs the original version:
- Uses per-ID rate limits instead of a single global "fast is bad" threshold.
- Treats known-legitimate engine traffic differently from untrusted IDs.
- Adds basic semantic checks on LEGIT_ID payloads (plausible ranges).
- Makes it clearer in the logs why a frame was forwarded or blocked.

This doesn’t magically solve all CAN spoofing issues (an attacker can still
impersonate an ID), but it shows a more thoughtful policy than purely
"high rate == bad".
"""

import can
import threading
import time
import struct
import sys

CHANNEL = "demo"
rx_ready = threading.Event()

# Legitimate critical traffic ID (normal priority)
LEGIT_ID = 0x200
# Attacker uses a lower numeric ID -> higher CAN priority
FLOOD_ID = 0x001

# Per-ID rate limits (frames per second) and trust levels
PER_ID_POLICY = {
    LEGIT_ID: {
        "max_rate": 50,          # engine telemetry is allowed to be chatty
        "label": "LEGIT_ENGINE",
        "trusted": True,
    },
    FLOOD_ID: {
        "max_rate": 10,          # we are stricter on this known attacker ID
        "label": "UNTRUSTED_FLOOD",
        "trusted": False,
    },
}

# Default rate limit for IDs not in the policy table
DEFAULT_MAX_RATE = 15


def make_bus():
    """Helper to create a virtual CAN bus."""
    try:
        return can.interface.Bus(interface="virtual", channel=CHANNEL)
    except TypeError:
        return can.interface.Bus(bustype="virtual", channel=CHANNEL)


def pack_engine_data(rpm, coolant_temp, fuel_level):
    """Same engine payload as in the attack file."""
    return struct.pack("<HBB", rpm, coolant_temp, fuel_level)


def engine_payload_is_plausible(rpm, temp, fuel):
    """
    Very simple semantic checks for engine data.
    In a real system this could be much richer:
    - cross-checking against other sensors
    - sequence numbers
    - cryptographic MACs, etc.
    """
    if not (0 <= rpm <= 8000):
        return False
    if not (-40 <= temp <= 150):
        return False
    if not (0 <= fuel <= 100):
        return False
    return True


def defensive_gateway():
    """
    Gateway that enforces per-ID rate limiting and simple semantic checks.

    In a real system this would sit between physical segments; here it just logs
    which frames would be forwarded vs. blocked under the current policy.
    """
    bus = make_bus()
    print(
        f"[GW] listening with improved defense... "
        f"(python {sys.version.split()[0]}, python-can {can.__version__})",
        flush=True,
    )
    rx_ready.set()

    # msg_id -> list of timestamps in the last second
    id_timestamps = {}

    t_end = time.time() + 5  # watch for 5 seconds
    try:
        while time.time() < t_end:
            msg = bus.recv(timeout=1.0)
            if not msg:
                continue

            now = time.time()
            msg_id = msg.arbitration_id
            data = bytes(msg.data)

            # Look up per-ID policy
            policy = PER_ID_POLICY.get(
                msg_id,
                {
                    "max_rate": DEFAULT_MAX_RATE,
                    "label": "UNKNOWN_ID",
                    "trusted": False,
                },
            )
            max_rate = policy["max_rate"]
            label = policy["label"]
            trusted = policy["trusted"]

            # Maintain a 1-second sliding window of timestamps per ID
            ts_list = id_timestamps.get(msg_id, [])
            ts_list = [ts for ts in ts_list if now - ts < 1.0]
            ts_list.append(now)
            id_timestamps[msg_id] = ts_list

            rate = len(ts_list)

            print(
                f"[GW] RX ID=0x{msg_id:X} ({label}) RATE={rate}/s "
                f"(limit={max_rate}/s) DATA={data.hex(' ').upper()}",
                flush=True,
            )

            # 1) Rate-limit check with per-ID policy
            if rate > max_rate:
                print(
                    "     -> BLOCKED (per-ID rate limit exceeded for "
                    f"{label})",
                    flush=True,
                )
                continue

            # 2) Optional semantic checks for trusted engine traffic
            if msg_id == LEGIT_ID and len(data) >= 4:
                rpm, temp, fuel = struct.unpack("<HBB", data[:4])
                if not engine_payload_is_plausible(rpm, temp, fuel):
                    print(
                        "     -> BLOCKED (implausible engine payload for trusted LEGIT_ID)",
                        flush=True,
                    )
                    continue
                print(
                    f"     -> FORWARDED LEGIT_ENGINE "
                    f"(rpm={rpm}, temp={temp}, fuel={fuel})",
                    flush=True,
                )

            # 3) Untrusted / other IDs that pass the rate limit
            elif msg_id == FLOOD_ID:
                print(
                    "     -> FORWARDED (untrusted flood ID but under rate limit)",
                    flush=True,
                )
            else:
                print(
                    "     -> FORWARDED (other/unknown ID under default rate limit)",
                    flush=True,
                )

    finally:
        bus.shutdown()
        print("[GW] shutdown cleanly", flush=True)


def sender_legit():
    """
    Same legitimate sender as in the attack file, sending on LEGIT_ID.
    """
    bus = make_bus()
    rx_ready.wait(timeout=2)

    start = time.time()
    while time.time() - start < 3.0:
        payload = pack_engine_data(rpm=2500, coolant_temp=90, fuel_level=70)
        msg = can.Message(
            arbitration_id=LEGIT_ID,
            is_extended_id=False,
            data=payload,
            is_fd=False,
        )
        bus.send(msg)
        print(
            f"[LEGIT] sent ID=0x{LEGIT_ID:X} DATA={payload.hex(' ').upper()}",
            flush=True,
        )
        time.sleep(0.3)

    bus.shutdown()


def sender_attacker_flood():
    """
    Same flooding attacker as in the attack file.

    Now, the defensive gateway should start blocking these when the per-ID rate
    exceeds the configured max_rate for FLOOD_ID.
    """
    bus = make_bus()
    rx_ready.wait(timeout=2)

    payload = b"\xDE\xAD\xBE\xEF"

    start = time.time()
    while time.time() - start < 3.0:
        msg = can.Message(
            arbitration_id=FLOOD_ID,
            is_extended_id=False,
            data=payload,
            is_fd=False,
        )
        bus.send(msg)
        print(
            f"[ATTACK] flood ID=0x{FLOOD_ID:X} DATA={payload.hex(' ').upper()}",
            flush=True,
        )
        time.sleep(0.02)
    bus.shutdown()


def main():
    """
    Run defensive gateway + legit sender + flooding attacker.

    Shows how per-ID rate limiting and basic semantic checks can mitigate
    high-priority flooding while treating known legitimate traffic differently
    from untrusted IDs.
    """
    gw_thread = threading.Thread(target=defensive_gateway, daemon=True)
    gw_thread.start()

    legit_thread = threading.Thread(target=sender_legit, daemon=True)
    attacker_thread = threading.Thread(target=sender_attacker_flood, daemon=True)

    legit_thread.start()
    attacker_thread.start()

    legit_thread.join()
    attacker_thread.join()
    gw_thread.join()

    print("[SYS] Defense demo complete", flush=True)


if __name__ == "__main__":
    main()
