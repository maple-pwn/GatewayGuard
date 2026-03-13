# Simulators - Traffic Generation

## Overview
Three protocol simulators generate test traffic in UnifiedPacket format for testing and development.

## CAN Simulator (`can_simulator.py`)
- CAN bus traffic generator
- **Normal mode**: Random ID/payload traffic
- **Attack modes**: DoS (flood), Fuzzy (random bytes), Spoofing (fixed ID impersonation)

## Ethernet Simulator (`ethernet_simulator.py`)
- Automotive Ethernet/SOME-IP traffic generator
- Normal traffic only (no attack patterns)
- Simulates vehicle network communication

## V2X Simulator (`v2x_simulator.py`)
- Vehicle-to-everything communication generator
- Normal traffic only (no attack patterns)
- Simulates DSRC/C-V2X messages

## Output Format
All simulators produce **UnifiedPacket** (7-element tuple):
- timestamp, protocol, source, dest, msg_id, payload, domain

## Usage
```bash
python -m app.simulators.can_simulator --attack dos
python -m app.simulators.ethernet_simulator
python -m app.simulators.v2x_simulator
```
