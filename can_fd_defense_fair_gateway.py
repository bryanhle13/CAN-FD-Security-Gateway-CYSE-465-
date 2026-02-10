"""
can_fd_defense_fair_gateway.py

Demonstrates a simple gateway-based defense against high-priority flooding.

- SecurityGateway monitors frame rates per CAN ID.
- Frames exceeding a per-ID rate threshold are blocked.
- Legitimate traffic on LEGIT_ID (0x200) should still get through
  even while an attacker floods FLOOD_ID (0x001).
"""

import can
import threading
import time
import struct
import sys

CHANNEL = "demo"
rx_ready = threading.Event()

LEGIT_ID = 0x200
FLOOD_ID = 0x001

# Any ID above this rate looks suspicious
MAX_FRAMES_PER_ID_PER_SEC = 10


def make_bus():
    """Helper to create a virtual CAN bus."""
    try:
        return can.interface.Bus(interface="virtual", channel=CHANNEL)
    except TypeError:
        return can.interface.Bus(bustype="virtual", channel=CHANNEL)


def pack_engine_data(rpm, coolant_temp, fuel_level):
    """Same engine payload as in the attack file."""
    return struct.pack("<HBB", rpm, coolant_temp, fuel_level)


def defensive_gateway():
    """
    Gateway that enforces simple per-ID rate limiting.

    In a real system this would sit between physical segments; here it just logs
    which frames would be forwarded vs. blocked under the current policy.
    """
    bus = make_bus()
    print(f"[GW] listening with defense... (python {sys.version.split()[0]}, "
          f"python-can {can.__version__})",
          flush=True)
    rx_ready.set()

    id_timestamps = {}  # msg_id -> list of timestamps

    t_end = time.time() + 5  # watch for 5 seconds
    try:
        while time.time() < t_end:
            msg = bus.recv(timeout=1.0)
            if not msg:
                continue

            now = time.time()
            msg_id = msg.arbitration_id
            data = bytes(msg.data)

            # Clean old timestamps (keep only last 1 second)
            ts_list = id_timestamps.get(msg_id, [])
            ts_list = [ts for ts in ts_list if now - ts < 1.0]
            ts_list.append(now)
            id_timestamps[msg_id] = ts_list

            rate = len(ts_list)

            print(f"[GW] RX ID=0x{msg_id:X} RATE={rate}/s DATA={data.hex(' ').upper()}",
                  flush=True)

            # Rate-limit check
            if rate > MAX_FRAMES_PER_ID_PER_SEC:
                print("     -> BLOCKED (per-ID rate limit exceeded)", flush=True)
                continue

            # "Forward" the frame: in this PoC we just log how it would be interpreted.
            if msg_id == LEGIT_ID and len(data) >= 4:
                rpm, temp, fuel = struct.unpack("<HBB", data[:4])
                print(f"     -> FORWARDED LEGIT (rpm={rpm}, temp={temp}, fuel={fuel})",
                      flush=True)
            elif msg_id == FLOOD_ID:
                print("     -> FORWARDED (attacker ID) but under rate limit", flush=True)
            else:
                print("     -> FORWARDED OTHER", flush=True)
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
        print(f"[LEGIT] sent ID=0x{LEGIT_ID:X} DATA={payload.hex(' ').upper()}",
              flush=True)
        time.sleep(0.3)

    bus.shutdown()


def sender_attacker_flood():
    """
    Same flooding attacker as in the attack file.

    Now, the defensive gateway should start blocking these when the per-ID rate
    exceeds MAX_FRAMES_PER_ID_PER_SEC.
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
        print(f"[ATTACK] flood ID=0x{FLOOD_ID:X} DATA={payload.hex(' ').upper()}",
              flush=True)
        time.sleep(0.02)
    bus.shutdown()


def main():
    """
    Run defensive gateway + legit sender + flooding attacker.

    Shows how rate limiting can mitigate a high-priority flood by blocking
    excessive frames from FLOOD_ID while still forwarding LEGIT_ID traffic.
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
