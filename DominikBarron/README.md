# CAN-FD Flood / DoS Attack and Gateway Defense (CYSE 465)

This proof-of-concept demonstrates a **high-priority flooding (DoS) attack** on a
CAN-style bus and a simple **gateway-based rate-limiting defense**.

The scenario is:

- A legitimate **EngineECU** sends engine telemetry on CAN ID `0x200`
  (RPM, coolant temperature, fuel level).
- An **AttackerNode** floods the bus with high-priority frames on CAN ID `0x001`
  (lower numeric ID -> higher CAN priority).
- In the insecure case, the attacker dominates the bus and degrades availability
  of legitimate traffic.
- In the defended case, a **SecurityGateway** enforces per-ID rate limits and
  blocks the flooding traffic while still forwarding legitimate telemetry.

---

## Files

- `can_fd_attack_flood_dos.py`  
  Insecure scenario showing the high-priority flood / DoS attack on the CAN bus.

- `can_fd_defense_fair_gateway.py`  
  Defense scenario with a SecurityGateway that rate-limits traffic per CAN ID and
  mitigates the flooding attack.

- `requirements.txt`  
  Contains the Python dependency for the demo:
  ```text
  python-can>=4.3
