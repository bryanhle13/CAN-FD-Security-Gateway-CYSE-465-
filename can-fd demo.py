import can
import threading
import time
import struct
import sys

CHANNEL = "demo"  
rx_ready = threading.Event()


def receiver():
    """Receive CAN messages from the virtual bus."""
    try:
        bus = can.interface.Bus(interface="virtual", channel=CHANNEL)
    except TypeError:
        bus = can.interface.Bus(bustype="virtual", channel=CHANNEL)

    print(f"[RX] listening... (python {sys.version.split()[0]}, python-can {can.__version__})", flush=True)
    rx_ready.set()  

    t_end = time.time() + 8  
    try:
        while time.time() < t_end:
            msg = bus.recv(timeout=1.0)
            if msg:
                print(f"[RX] ID=0x{msg.arbitration_id:X} DLC={msg.dlc} Data={msg.data.hex(' ').upper()}", flush=True)
    finally:
        bus.shutdown()
        print("[RX] shutdown cleanly", flush=True)


def sender_basic():
    """Send a simple 4-byte CAN frame."""
    try:
        bus = can.interface.Bus(interface="virtual", channel=CHANNEL)
    except TypeError:
        bus = can.interface.Bus(bustype="virtual", channel=CHANNEL)

    rx_ready.wait(timeout=3) 

    msg = can.Message(arbitration_id=0x123, is_extended_id=False, data=b"\x11\x22\x33\x44")
    bus.send(msg)
    print("[TX] sent 0x123 11 22 33 44", flush=True)
    bus.shutdown()


def pack_engine_data(rpm, coolant_temp, fuel_level):
    """Pack RPM, coolant temp, and fuel level into a CAN payload."""
    return struct.pack("<HBBxxxx", rpm, coolant_temp, fuel_level)


def sender_packed():
    """Send a structured CAN payload (engine data)."""
    try:
        bus = can.interface.Bus(interface="virtual", channel=CHANNEL)
    except TypeError:
        bus = can.interface.Bus(bustype="virtual", channel=CHANNEL)

    payload = pack_engine_data(3500, 95, 75)
    msg = can.Message(arbitration_id=0x200, is_extended_id=False, data=payload)
    bus.send(msg)
    print(f"[TX] sent 0x200 {payload.hex(' ').upper()}", flush=True)
    bus.shutdown()


def main():
    """Run the receiver + two senders sequentially."""
    rx = threading.Thread(target=receiver, daemon=True)
    rx.start()

    sender_basic()
    time.sleep(0.3)
    sender_packed()

    rx.join()
    print("[SYS] Demo complete", flush=True)


if __name__ == "__main__":
    main()