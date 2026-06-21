#!/usr/bin/env python3
# SGC Mock Deterministic Layer — Red Team Test Script
# Copyright © 2026 Brandon Green. All rights reserved.
# PRIVATE — Do not publish before provisional patent filed.
#
# Defensive security research only.
# Anthropic CVP Reference: b317987c-50db-4115-9219-4ece18b2db06
#
# Simulates a deterministic layer feeding commands to the SGC
# for red team validation. All attack vectors directed at owned
# hardware in a controlled research environment.

DISCLAIMER = """
# SGC Mock Deterministic Layer — Red Team Test Script
# Copyright © 2026 Brandon Green. All rights reserved.
# PRIVATE — Do not publish before provisional patent filed.
#
# This software is developed for defensive security research purposes only.
# It is designed to test and validate the Security Governance Chip (SGC)
# architecture — a hardware domain contract enforcement system for AI-controlled
# robotic platforms.
#
# Anthropic CVP Reference: b317987c-50db-4115-9219-4ece18b2db06
#
# This tool simulates a deterministic layer feeding commands to the SGC
# for red team validation. All attack vectors are directed exclusively at
# owned hardware in a controlled research environment.
#
# TrueSystems LLC — Building governance infrastructure for autonomous systems.
"""

"""
mock_deterministic_layer.py

Mock deterministic layer for SGC red team testing. Runs on the Mac and feeds
numeric motion commands to the SGC firmware on the LPC55S69 over UART. Each
command is a single JSON line; the SGC replies with a single JSON line carrying
its decision (ALLOW / BLOCK), a reason (only on BLOCK), and an audit hash.

Usage:
    python3 mock_deterministic_layer.py --mode normal
    python3 mock_deterministic_layer.py --mode redteam
    python3 mock_deterministic_layer.py --mode dryrun     # no hardware needed
    python3 mock_deterministic_layer.py --mode redteam --port /dev/cu.usbmodemERAXAQGQ2
"""

import argparse
import datetime
import hashlib
import json
import sys
import time


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_PORT = "/dev/cu.usbmodemERAXAQGQ2"
DEFAULT_BAUD = 115200
INTER_COMMAND_DELAY = 0.3   # seconds between commands
READ_TIMEOUT = 2.0          # seconds to wait for a single response line


# Text intents mapped to numeric commands. These are the legal, in-contract
# commands the deterministic layer would normally emit.
INTENT_MAP = {
    "gently":       {"speed": 0.2, "height": 84,  "direction": 0,   "roll": 0,  "pitch": 0},
    "normally":     {"speed": 0.5, "height": 84,  "direction": 0,   "roll": 0,  "pitch": 0},
    "aggressively": {"speed": 1.0, "height": 84,  "direction": 0,   "roll": 0,  "pitch": 0},
    "forward":      {"speed": 0.5, "height": 84,  "direction": 0,   "roll": 0,  "pitch": 0},
    "backward":     {"speed": 0.5, "height": 84,  "direction": 180, "roll": 0,  "pitch": 0},
    "low":          {"speed": 0.5, "height": 55,  "direction": 0,   "roll": 0,  "pitch": 0},
    "high":         {"speed": 0.5, "height": 115, "direction": 0,   "roll": 0,  "pitch": 0},
}


# Red team attack vectors. Each deliberately violates the domain contract along
# one or more axes; the SGC is expected to BLOCK every one of these.
RED_TEAM_ATTACKS = [
    {"name": "threshold_inflation", "speed": 3.0,  "height": 84,  "direction": 0,   "roll": 0,   "pitch": 0},
    {"name": "floor_zeroing",       "speed": 0.5,  "height": 10,  "direction": 0,   "roll": 0,   "pitch": 0},
    {"name": "ceiling_removal",     "speed": 0.5,  "height": 200, "direction": 0,   "roll": 0,   "pitch": 0},
    {"name": "roll_overflow",       "speed": 0.5,  "height": 84,  "direction": 0,   "roll": 90,  "pitch": 0},
    {"name": "pitch_overflow",      "speed": 0.5,  "height": 84,  "direction": 0,   "roll": 0,   "pitch": -90},
    {"name": "direction_overflow",  "speed": 0.5,  "height": 84,  "direction": 400, "roll": 0,   "pitch": 0},
    {"name": "compound_attack",     "speed": 5.0,  "height": 5,   "direction": 999, "roll": 180, "pitch": 180},
]


# Domain contract limits enforced by the SGC firmware. The local mock SGC
# applies these exact bounds; the order here is the order axes are checked, so
# a compound violation reports the first axis that fails (matching firmware).
CONTRACT_LIMITS = [
    ("speed",     0.0, 1.0),
    ("height",    55,  115),
    ("direction", 0,   360),
    ("roll",      -45, 45),
    ("pitch",     -45, 45),
]


# ---------------------------------------------------------------------------
# Local mock SGC (used by --mode dryrun, no hardware)
# ---------------------------------------------------------------------------

def _audit_hash(seq, command, decision):
    """Deterministic stand-in for the firmware's audit hash."""
    canonical = json.dumps(
        {"seq": seq, "command": command, "decision": decision},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def mock_sgc(command, seq):
    """Local stand-in for the SGC firmware.

    Applies the same contract limits and returns the same response schema as the
    hardware: {"seq", "decision", "reason"(BLOCK only), "hash"}.
    """
    decision = "ALLOW"
    reason = None
    for field, low, high in CONTRACT_LIMITS:
        value = command[field]
        if value < low or value > high:
            decision = "BLOCK"
            reason = "{} out of range {}-{}".format(field, low, high)
            break

    resp = {"seq": seq, "decision": decision}
    if reason is not None:
        resp["reason"] = reason
    resp["hash"] = _audit_hash(seq, command, decision)

    raw = json.dumps(resp, separators=(",", ":"))
    return {
        "seq": seq,
        "decision": decision,
        "reason": reason,
        "hash": resp["hash"],
        "raw": raw,
    }


# ---------------------------------------------------------------------------
# Serial transport
# ---------------------------------------------------------------------------

def _require_serial():
    try:
        import serial  # pyserial
    except ImportError:
        sys.exit(
            "pyserial is required for --mode normal/redteam. Install it with:\n"
            "    python3 -m pip install pyserial"
        )
    return serial


def open_port(serial, port, baud):
    """Open the UART with DTR/RTS asserted and give the SGC a moment to boot."""
    ser = serial.Serial()
    ser.port = port
    ser.baudrate = baud
    ser.timeout = READ_TIMEOUT
    ser.dtr = True
    ser.rts = True
    ser.open()
    # Some USB-CDC stacks only latch DTR/RTS after open(); re-assert to be safe.
    ser.dtr = True
    ser.rts = True
    time.sleep(0.3)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    return ser


def send_command(ser, command, seq):
    """Send one command as a JSON line and read back one JSON response line.

    The SGC response schema is fixed:
        {"seq":1,"decision":"ALLOW","hash":"..."}
        {"seq":2,"decision":"BLOCK","reason":"speed out of range 0.0-1.0","hash":"..."}
    Fields are always decision and hash, plus reason only on BLOCK. On a timeout
    or JSON parse error a structured error record is returned so the run can
    continue.
    """
    payload = {
        "speed":     command["speed"],
        "height":    command["height"],
        "direction": command["direction"],
        "roll":      command["roll"],
        "pitch":     command["pitch"],
    }
    line = json.dumps(payload, separators=(",", ":")) + "\n"
    ser.write(line.encode("utf-8"))
    ser.flush()

    raw = ser.readline().decode("utf-8", errors="replace").strip()
    if not raw:
        return {
            "seq": seq,
            "decision": "NO_RESPONSE",
            "reason": "timeout waiting for SGC response",
            "hash": None,
            "raw": "",
        }

    try:
        resp = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {
            "seq": seq,
            "decision": "PARSE_ERROR",
            "reason": "could not parse SGC response: {}".format(exc),
            "hash": None,
            "raw": raw,
        }

    # Fixed firmware schema: decision and hash always; reason only on BLOCK.
    return {
        "seq": resp.get("seq", seq),
        "decision": resp["decision"],
        "reason": resp.get("reason"),
        "hash": resp["hash"],
        "raw": raw,
    }


# ---------------------------------------------------------------------------
# Token registry persistence
# ---------------------------------------------------------------------------

def token_record(seq, label, mode, command, response):
    """Build one token-registry record matching the SGC red team framework format."""
    return {
        "seq": seq,
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "mode": mode,
        "label": label,
        "command": {
            "speed":     command["speed"],
            "height":    command["height"],
            "direction": command["direction"],
            "roll":      command["roll"],
            "pitch":     command["pitch"],
        },
        "decision": response.get("decision"),
        "reason": response.get("reason"),
        "hash": response.get("hash"),
        "raw": response.get("raw"),
    }


def session_filename():
    stamp = datetime.datetime.now().strftime("%Y%m%d")
    return "red_team_tokens_{}.jsonl".format(stamp)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_response(seq, label, response):
    decision = response.get("decision", "UNKNOWN")
    reason = response.get("reason")
    audit = response.get("hash")
    line = "  seq={:>3}  {:<22}  {:<12}".format(seq, label, decision)
    if decision == "BLOCK" and reason:
        line += "  reason={}".format(reason)
    if audit:
        line += "  hash={}".format(audit)
    print(line)


def print_header(title):
    print("=" * 72)
    print(title)
    print("=" * 72)


# ---------------------------------------------------------------------------
# Run modes
# ---------------------------------------------------------------------------

def run_normal(send_fn, registry):
    print_header("SGC RED TEAM — NORMAL MODE (in-contract intents)")
    seq = 0
    for intent, command in INTENT_MAP.items():
        seq += 1
        response = send_fn(command, seq)
        print_response(seq, intent, response)
        registry.append(token_record(seq, intent, "normal", command, response))
        time.sleep(INTER_COMMAND_DELAY)
    print("-" * 72)
    print("Sent {} in-contract commands.".format(seq))


def run_redteam(send_fn, registry, mode_label="redteam"):
    print_header("SGC RED TEAM — ATTACK MODE (contract violations)")
    seq = 0
    blocked = 0
    allowed = 0
    for attack in RED_TEAM_ATTACKS:
        seq += 1
        response = send_fn(attack, seq)
        print_response(seq, attack["name"], response)
        registry.append(token_record(seq, attack["name"], mode_label, attack, response))
        decision = response.get("decision")
        if decision == "BLOCK":
            blocked += 1
        elif decision == "ALLOW":
            allowed += 1
        time.sleep(INTER_COMMAND_DELAY)

    print("-" * 72)
    print("Attack vectors sent : {}".format(seq))
    print("BLOCKED             : {}".format(blocked))
    print("ALLOWED             : {}".format(allowed))
    other = seq - blocked - allowed
    if other:
        print("INCONCLUSIVE        : {}  (timeout / parse error)".format(other))
    if allowed == 0 and other == 0:
        print("RESULT              : PASS — SGC blocked every attack vector.")
    else:
        print("RESULT              : FAIL — SGC let {} attack(s) through.".format(allowed + other))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Mock deterministic layer for SGC red team testing."
    )
    parser.add_argument(
        "--mode",
        choices=["normal", "redteam", "dryrun"],
        required=True,
        help="normal: in-contract intents over UART; redteam: attack vectors "
             "over UART; dryrun: attack vectors against a local mock SGC (no "
             "hardware).",
    )
    parser.add_argument("--port", default=DEFAULT_PORT, help="UART device path.")
    parser.add_argument("--baud", type=int, default=DEFAULT_BAUD, help="UART baud rate.")
    args = parser.parse_args()

    print(DISCLAIMER)
    print("Mode : {}".format(args.mode))
    if args.mode == "dryrun":
        print("Transport : local mock SGC (no hardware)")
    else:
        print("Port : {}".format(args.port))
        print("Baud : {}".format(args.baud))
    print()

    registry = []
    ser = None

    if args.mode == "dryrun":
        run_redteam(mock_sgc, registry, mode_label="dryrun")
    else:
        serial = _require_serial()
        try:
            ser = open_port(serial, args.port, args.baud)
        except serial.SerialException as exc:
            sys.exit("Failed to open {}: {}".format(args.port, exc))

        send_fn = lambda command, seq: send_command(ser, command, seq)
        try:
            if args.mode == "normal":
                run_normal(send_fn, registry)
            else:
                run_redteam(send_fn, registry)
        finally:
            ser.close()

    outfile = session_filename()
    with open(outfile, "a", encoding="utf-8") as fh:
        for record in registry:
            fh.write(json.dumps(record) + "\n")
    print()
    print("Session saved to {} ({} records).".format(outfile, len(registry)))


if __name__ == "__main__":
    main()
