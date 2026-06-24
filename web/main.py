import asyncio
import json
import re
import time

import serial
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI()
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_methods=["*"], 
    allow_headers=["*"]
)


@app.middleware("http")
async def disable_http_caching(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

nodes = {}
connected_clients = []
observed_frames = {}


async def emit_log(node_id: str, tag: str, message: str):
    timestamp = int(time.time() * 1000) % 1000000
    await broadcast_message({
        "type": "log",
        "node_id": node_id,
        "raw": f"[{timestamp:10d} ms] [{tag}] {message}"
    })


def normalize_display_log_line(line: str):
    normalized = line
    replacements = {
        "FLOOD suspected:": "DoS suspected:",
        "Flooding suspected:": "DoS suspected:",
        "Spam attack started.": "DoS attack started.",
        "Spam attack stopped.": "DoS attack stopped.",
        "DoS flood attack started.": "DoS attack started.",
        "DoS flood attack stopped.": "DoS attack stopped.",
    }
    for source, target in replacements.items():
        normalized = normalized.replace(source, target)
    return normalized


def parse_hex_data_tokens(dlc: int, data: str):
    if dlc < 0 or dlc > 8:
        raise ValueError("DLC must be between 0 and 8.")

    tokens = [token for token in str(data).strip().split() if token]
    if dlc == 0:
        if tokens:
            raise ValueError("DLC is 0 so data must be empty.")
        return []

    if len(tokens) != dlc:
        raise ValueError(f"Expected {dlc} data bytes, got {len(tokens)}.")

    parsed = []
    for index, token in enumerate(tokens):
        try:
            value = int(token, 16)
        except ValueError as exc:
            raise ValueError(f"Invalid hex byte at index {index}: {token}") from exc

        if value < 0 or value > 0xFF:
            raise ValueError(f"Hex byte out of range at index {index}: {token}")

        parsed.append(value)

    return parsed


def format_serial_hex_payload(dlc: int, data: str):
    bytes_out = parse_hex_data_tokens(int(dlc), data)
    return " ".join(f"0x{value:02X}" for value in bytes_out)


def mutate_payload_bytes(payload_bytes):
    if not payload_bytes:
        return [0xA5, 0x5A, 0xC3, 0x3C]

    mutated = list(payload_bytes)
    max_mutations = min(3, len(mutated))
    masks = [0xA5, 0x5A, 0x3C]

    for index in range(max_mutations):
        mutated[index] ^= masks[index]
        if mutated[index] == payload_bytes[index]:
            mutated[index] = (mutated[index] + 1) & 0xFF

    return mutated


def mutate_payload_bytes_for_iteration(payload_bytes, iteration: int):
    mutated = mutate_payload_bytes(payload_bytes)
    if not mutated:
        return mutated

    step = max(1, int(iteration))
    mutation_count = min(3, len(mutated))
    rotate_base = step % len(mutated)

    for offset in range(mutation_count):
        target = (rotate_base + offset) % len(mutated)
        delta = (0x11 + (step * 7) + (offset * 3)) & 0xFF
        mutated[target] = (mutated[target] + delta) & 0xFF

    return mutated


def format_payload_bytes(payload_bytes):
    return " ".join(f"{value:02X}" for value in payload_bytes)


def has_active_attack():
    for node in nodes.values():
        if node.get("active_attack_type"):
            return True
    return False


def remember_observed_frame(node_id: str, direction: str, mode: str, can_id: str,
                            dlc: int, data: str):
    if direction not in ["TX", "RX"]:
        return

    if mode not in ["single", "repeat", "bus"]:
        return

    if has_active_attack():
        return

    normalized_id = normalize_can_id(can_id)
    normalized_data = normalize_can_data(int(dlc), data)
    tokens = [token for token in normalized_data.split() if token]

    if nodes.get(node_id, {}).get("is_sim"):
        payload_tokens = tokens
    else:
        payload_tokens = tokens[:-1] if tokens else []

    observed_frames[normalized_id] = {
        "id": normalized_id,
        "wire_dlc": int(dlc),
        "wire_data": normalized_data,
        "payload_dlc": len(payload_tokens),
        "payload_data": " ".join(payload_tokens),
        "payload_bytes": [int(token, 16) for token in payload_tokens],
        "source_node_id": node_id,
        "source_direction": direction,
        "source_mode": mode,
        "captured_at": int(time.time() * 1000),
    }


def resolve_spoof_baseline(msg_id=None, preferred_node_id=None):
    requested_id = str(msg_id).strip() if msg_id is not None else ""
    if requested_id:
        normalized_id = normalize_can_id(requested_id)
        baseline = observed_frames.get(normalized_id)
        if baseline:
            return baseline

        try:
            requested_value = int(requested_id, 0)
        except ValueError:
            requested_value = None

        if requested_value not in [None, 0]:
            raise ValueError(
                f"No legitimate baseline captured yet for {normalized_id}. "
                "Send a normal message with this ID first."
            )

    if not observed_frames:
        raise ValueError(
            "No legitimate baseline captured yet. "
            "Send a normal message first."
        )

    candidates = list(observed_frames.values())
    if preferred_node_id:
        preferred_candidates = [
            baseline
            for baseline in candidates
            if baseline.get("source_node_id") == preferred_node_id
        ]
        if preferred_candidates:
            candidates = preferred_candidates

    return max(candidates, key=lambda baseline: baseline.get("captured_at", 0))


def build_spoof_payload(msg_id=None, preferred_node_id=None):
    baseline = resolve_spoof_baseline(msg_id, preferred_node_id)
    normalized_id = baseline["id"]

    spoof_payload_bytes = mutate_payload_bytes_for_iteration(
        baseline["payload_bytes"],
        1
    )
    payload_dlc = len(spoof_payload_bytes)
    payload_data = format_payload_bytes(spoof_payload_bytes)

    return {
        "id": normalized_id,
        "baseline": baseline,
        "payload_dlc": payload_dlc,
        "payload_data": payload_data,
    }


def update_node_alert_state_from_log(node_id: str, line: str):
    node = nodes.get(node_id)
    if not node:
        return

    defense = node.setdefault("defense", {})
    alert_match = re.search(r"\[ALERT\]\s+(DoS suspected|REPLAY suspected|FUZZING suspected|SPOOFING suspected)", line, re.IGNORECASE)
    if not alert_match:
        return

    alert_text = alert_match.group(1).lower()
    candidate_reason = None
    if alert_text.startswith("dos"):
        candidate_reason = "dos"
    elif alert_text.startswith("replay"):
        candidate_reason = "replay"
    elif alert_text.startswith("fuzzing"):
        candidate_reason = "fuzzing"
    elif alert_text.startswith("spoofing"):
        candidate_reason = "spoofing"

    if candidate_reason:
        reason_priority = {
            "replay": 1,
            "dos": 2,
            "spoofing": 3,
            "fuzzing": 4,
        }
        current_reason = defense.get("last_reason")
        current_at_ms = int(defense.get("last_reason_at_ms", 0))
        now_ms = int(time.time() * 1000)

        if (
            not current_reason or
            reason_priority.get(candidate_reason, 0) >= reason_priority.get(current_reason, 0) or
            (now_ms - current_at_ms) > 3000
        ):
            defense["last_reason"] = candidate_reason
            defense["last_reason_at_ms"] = now_ms

    id_match = re.search(r"ID=(0x[0-9A-Fa-f]+)", line)
    if id_match:
        defense["last_alert_id"] = normalize_can_id(id_match.group(1))


def get_sim_recipients(source_node_id: str):
    return [
        (other_id, other_node)
        for other_id, other_node in nodes.items()
        if other_node.get("is_sim") and other_id != source_node_id
    ]


def normalize_can_id(msg_id: str):
    text = str(msg_id).strip()
    if not text:
        return "0x000"

    try:
        parsed = int(text, 0)
        width = 8 if parsed > 0x7FF else 3
        return f"0x{parsed:0{width}X}"
    except ValueError:
        return text.upper()


def normalize_can_data(dlc: int, data: str):
    if dlc <= 0:
        return ""

    normalized = []
    for token in str(data).strip().split():
        try:
            normalized.append(f"{int(token, 16) & 0xFF:02X}")
        except ValueError:
            normalized.append(token.upper())

        if len(normalized) >= dlc:
            break

    return " ".join(normalized)


def build_sim_signature(msg_id: str, dlc: int, data: str):
    normalized_dlc = int(dlc)
    return {
        "id": normalize_can_id(msg_id),
        "dlc": normalized_dlc,
        "data": normalize_can_data(normalized_dlc, data),
    }


def spoof_required_changed_bytes(baseline_dlc: int, observed_dlc: int):
    return 1 if baseline_dlc <= 2 and observed_dlc <= 2 else 2


def is_sim_spoof_suspicious(baseline_bytes, baseline_dlc: int, dlc: int, data: str):
    observed_bytes = parse_hex_data_tokens(int(dlc), data)
    compare_length = min(int(baseline_dlc), len(observed_bytes))
    changed = sum(
        1
        for index in range(compare_length)
        if baseline_bytes[index] != observed_bytes[index]
    )

    if len(observed_bytes) != int(baseline_dlc):
        changed += 1

    return (
        len(observed_bytes) != int(baseline_dlc) or
        changed >= spoof_required_changed_bytes(int(baseline_dlc), len(observed_bytes))
    )


def build_sim_dos_frame(msg_id: str):
    normalized_id = normalize_can_id(msg_id)

    try:
        parsed_id = int(str(msg_id).strip(), 0)
    except ValueError:
        parsed_id = 0

    data = " ".join([
        "D0",
        "5A",
        f"{parsed_id & 0xFF:02X}",
        f"{(parsed_id >> 8) & 0xFF:02X}",
        "D0",
        "5A",
        "13",
        "A5",
    ])
    return normalized_id, 8, data


def build_sim_fuzz_frame(iteration: int):
    msg_id = f"0x{(0x100 + ((iteration * 73) % 0x6FF)):03X}"
    dlc = 1 + (iteration % 8)
    data = " ".join(
        f"{((iteration * 37) + (index * 29)) & 0xFF:02X}"
        for index in range(dlc)
    )
    return msg_id, dlc, data


def sim_attack_state_message(attack_type: str, started: bool):
    action = "started" if started else "stopped"
    messages = {
        "dos": f"DoS attack {action}.",
        "repeat": f"Repeat transmission {action}.",
        "replay": f"Replay attack {action}.",
        "fuzz": f"Fuzzing attack {action}.",
        "spoof": f"Spoofing attack {action}.",
    }
    return messages.get(attack_type, f"{attack_type} attack {action}.")


async def emit_sim_alert(node_id: str, msg_id: str, dlc: int, data: str,
                         reason: str, message: str):
    defense = nodes.get(node_id, {}).get("defense", {})
    defense["last_alert_id"] = normalize_can_id(msg_id)
    defense["last_reason"] = reason
    defense["last_reason_at_ms"] = int(time.time() * 1000)
    defense["last_alert_signature"] = build_sim_signature(msg_id, dlc, data)
    await emit_log(node_id, "ALERT", message)


def is_sim_defense_active(node: dict):
    defense = node.get("defense", {})
    if not defense.get("active"):
        return False
    if defense.get("until_ms", 0) <= int(time.time() * 1000):
        defense["active"] = False
        defense["duration_ms"] = 0
        defense["until_ms"] = 0
        return False
    return True


def should_block_sim_frame(node: dict, msg_id: str, dlc: int, data: str):
    if not is_sim_defense_active(node):
        return False

    defense = node.get("defense", {})
    normalized_id = normalize_can_id(msg_id)
    reason = defense.get("last_reason")
    now_ms = int(time.time() * 1000)

    if reason == "dos":
        return normalized_id == defense.get("last_alert_id")

    if reason == "fuzzing":
        trusted_ids = set(defense.get("trusted_ids", []))
        if normalized_id not in trusted_ids:
            return True

        last_allowed_at_ms = int(defense.get("last_allowed_at_ms", 0))
        min_gap_ms = int(defense.get("min_gap_ms", 100))
        if last_allowed_at_ms and (now_ms - last_allowed_at_ms) < min_gap_ms:
            return True

        defense["last_allowed_at_ms"] = now_ms
        return False

    if reason == "spoofing":
        if normalized_id != defense.get("last_alert_id"):
            return False

        baseline_bytes = defense.get("spoof_baseline_bytes") or []
        baseline_dlc = int(defense.get("spoof_baseline_dlc", 0))
        if baseline_bytes and baseline_dlc > 0:
            return is_sim_spoof_suspicious(baseline_bytes, baseline_dlc, dlc, data)

    signature = defense.get("last_alert_signature")
    if not signature:
        return False

    return signature == build_sim_signature(msg_id, dlc, data)


async def stop_active_attackers(target_node_id: str, attack_types):
    stopped_nodes = []

    for other_id, other_node in nodes.items():
        if other_id == target_node_id:
            continue
        if other_node.get("active_attack_type") not in attack_types:
            continue

        active_type = other_node.get("active_attack_type")

        if other_node.get("is_sim"):
            attack_task = other_node.get("attack_tasks", {}).get(active_type)
            if attack_task:
                attack_task.cancel()
                del other_node["attack_tasks"][active_type]
            await process_serial_line(
                other_id,
                f"[{0:10d} ms] [STATE] {sim_attack_state_message(active_type, False)}"
            )
        else:
            try:
                other_node["serial"].write(f"{active_type} stop\n".encode("utf-8"))
            except Exception:
                continue

        other_node["active_attack_type"] = None
        stopped_nodes.append(other_node["name"])

    return stopped_nodes

async def broadcast_message(message: dict):
    if not connected_clients:
        return
    text_data = json.dumps(message)
    disconnected = []
    for client in connected_clients:
        try:
            await client.send_text(text_data)
        except Exception:
            disconnected.append(client)
    
    for client in disconnected:
        connected_clients.remove(client)

async def process_serial_line(node_id: str, line: str):
    line = normalize_display_log_line(line)
    if "ML ANOMALY suspected:" in line:
        return

    # Example format: [   123456 ms] [RX] bus node=ESP32-NODE id=0x012 type=STD dlc=2 data=AA BB
    rx_match = re.search(r'\[(.*?)\]\s*\[(RX|TX|ATTACK)\]\s*([a-zA-Z0-9_-]+)\s*(.*)', line)
    
    if rx_match:
        timestamp, direction, mode, details = rx_match.groups()

        if mode == "legacy-text":
            return
        
        message = {
            "type": "can_message",
            "node_id": node_id,
            "raw": line,
            "timestamp": timestamp.strip(),
            "direction": direction,
            "mode": mode,
            "details": details,
            "parsed": None
        }
        
        if mode != "legacy-text":
            # node=ESP32-NODE id=0x012 type=STD dlc=2 data=AA BB
            details_match = re.search(r'node=(.*?)\s+id=(.*?)\s+type=(.*?)\s+dlc=(\d+)\s+data=(.*)', details)
            if details_match:
                node, can_id, can_type, dlc, data = details_match.groups()
                # Use the configured node name instead of the raw one from firmware for UI consistency
                # if this is a mocked node, or just use it anyway.
                message["parsed"] = {
                    "node_name": nodes.get(node_id, {}).get("name", node),
                    "id": can_id,
                    "type": can_type,
                    "dlc": int(dlc),
                    "data": data.strip()
                }
                remember_observed_frame(
                    node_id,
                    direction,
                    mode,
                    can_id,
                    int(dlc),
                    data.strip()
                )
        await broadcast_message(message)
    else:
        update_node_alert_state_from_log(node_id, line)
        # Standard log output
        await broadcast_message({
            "type": "log",
            "node_id": node_id,
            "raw": line
        })

async def read_serial(node_id: str):
    node = nodes[node_id]
    ser = node['serial']
    buffer = b""
    while True:
        try:
            if ser.in_waiting > 0:
                data = ser.read(ser.in_waiting)
                buffer += data
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    line_str = line.decode('utf-8', errors='ignore').strip()
                    if line_str:
                        await process_serial_line(node_id, line_str)
            await asyncio.sleep(0.01)
        except Exception as e:
            print(f"Serial read error on {node_id}: {e}")
            await broadcast_message({
                "type": "system",
                "node_id": node_id,
                "message": f"Serial error: {str(e)}"
            })
            break

async def mock_read_serial(node_id: str):
    # Simulate background activity for a mock node
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass

async def sim_attack_task(node_id: str, attack_type: str, msg_id: str, dlc: int, data: str, period: int):
    iteration = 0
    while True:
        try:
            iteration += 1
            timestamp = int(time.time() * 1000) % 1000000
            node = nodes[node_id]

            current_id = normalize_can_id(msg_id)
            current_dlc = int(dlc)
            current_data = normalize_can_data(current_dlc, data)
            if attack_type == "fuzz":
                current_id, current_dlc, current_data = build_sim_fuzz_frame(iteration)
            elif attack_type == "dos":
                current_id, current_dlc, current_data = build_sim_dos_frame(msg_id)

            baseline = None
            if attack_type == "spoof":
                baseline = observed_frames.get(current_id)
                if baseline:
                    spoof_payload_bytes = mutate_payload_bytes_for_iteration(
                        baseline["payload_bytes"],
                        iteration
                    )
                    current_dlc = len(spoof_payload_bytes)
                    current_data = format_payload_bytes(spoof_payload_bytes)

            tx_line = (
                f"[{timestamp:10d} ms] [ATTACK] {attack_type} "
                f"node={node['name']} id={current_id} type=STD dlc={current_dlc} data={current_data}"
            )
            await process_serial_line(node_id, tx_line)

            for other_id, other_node in get_sim_recipients(node_id):
                if should_block_sim_frame(other_node, current_id, current_dlc, current_data):
                    continue

                rx_line = (
                    f"[{timestamp:10d} ms] [RX] bus node={other_node['name']} "
                    f"id={current_id} type=STD dlc={current_dlc} data={current_data}"
                )
                await process_serial_line(other_id, rx_line)

                if attack_type == "replay" and iteration >= 3 and iteration % 3 == 0:
                    await emit_sim_alert(
                        other_id,
                        current_id,
                        current_dlc,
                        current_data,
                        "replay-duplicate",
                        f"REPLAY suspected: ID={current_id} repeated={iteration} window=1000ms"
                    )
                elif attack_type == "dos" and iteration >= 3 and iteration % 3 == 0:
                    rate = int(1000 / max(period, 1))
                    await emit_sim_alert(
                        other_id,
                        current_id,
                        current_dlc,
                        current_data,
                        "dos",
                        f"DoS suspected: ID={current_id} rate={rate} fps window=1000ms"
                    )
                elif attack_type == "fuzz" and iteration >= 4 and iteration % 3 == 1:
                    await emit_sim_alert(
                        other_id,
                        current_id,
                        current_dlc,
                        current_data,
                        "fuzzing",
                        "FUZZING suspected: unique_ids=5 id_switches=6 window=1200ms"
                    )
                elif attack_type == "spoof" and iteration >= 2 and iteration % 2 == 0:
                    baseline = observed_frames.get(current_id)
                    baseline_dlc = baseline["payload_dlc"] if baseline else current_dlc
                    changed_bytes = 0
                    if baseline:
                        current_bytes = [int(token, 16) for token in current_data.split()]
                        compare_length = min(len(current_bytes), len(baseline["payload_bytes"]))
                        changed_bytes = sum(
                            1
                            for index in range(compare_length)
                            if current_bytes[index] != baseline["payload_bytes"][index]
                        )
                        changed_bytes += abs(len(current_bytes) - len(baseline["payload_bytes"]))
                    else:
                        changed_bytes = min(4, current_dlc)

                    await emit_sim_alert(
                        other_id,
                        current_id,
                        current_dlc,
                        current_data,
                        "spoofing",
                        f"SPOOFING suspected: ID={current_id} changed_bytes={changed_bytes} baseline_dlc={baseline_dlc} observed_dlc={current_dlc}"
                    )

            await asyncio.sleep(period / 1000.0)
        except asyncio.CancelledError:
            break

class NodeCreate(BaseModel):
    id: str
    name: str
    port: str

@app.post("/api/nodes")
async def add_node(node: NodeCreate):
    if node.id in nodes:
        raise HTTPException(status_code=400, detail="Node already exists")
    
    is_sim = node.port.upper().startswith("SIM")
    ser = None
    task = None
    
    if is_sim:
        pass
    else:
        try:
            ser = serial.Serial(node.port, 115200, timeout=0)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Serial error: {str(e)}")
            
    nodes[node.id] = {
        "id": node.id,
        "name": node.name,
        "port": node.port,
        "serial": ser,
        "is_sim": is_sim,
        "task": task,
        "attack_tasks": {},
        "active_attack_type": None,
        "defense": {
            "active": False,
            "until_ms": 0,
            "duration_ms": 0,
            "last_alert_id": None,
            "last_reason": None,
            "last_reason_at_ms": 0,
            "last_alert_signature": None,
            "spoof_baseline_bytes": [],
            "spoof_baseline_dlc": 0,
            "trusted_ids": [],
            "last_allowed_at_ms": 0,
            "min_gap_ms": 100
        }
    }

    if is_sim:
        nodes[node.id]["task"] = asyncio.create_task(mock_read_serial(node.id))
    else:
        nodes[node.id]["task"] = asyncio.create_task(read_serial(node.id))
    
    await broadcast_message({
        "type": "system",
        "node_id": node.id,
        "message": f"Node {node.name} connected on {node.port}"
    })
    
    return {"status": "success"}

@app.get("/api/nodes")
async def get_nodes():
    return [
        {
            "id": n["id"],
            "name": n["name"],
            "port": n["port"],
            "defense_active": n.get("defense", {}).get("active", False)
        }
        for n in nodes.values()
    ]

@app.delete("/api/nodes/{node_id}")
async def delete_node(node_id: str):
    if node_id not in nodes:
        raise HTTPException(status_code=404, detail="Node not found")
        
    node = nodes[node_id]
    if node["task"]:
        node["task"].cancel()
    
    for atk_task in node.get("attack_tasks", {}).values():
        atk_task.cancel()
        
    if node["serial"]:
        node["serial"].close()
        
    del nodes[node_id]
    
    await broadcast_message({
        "type": "system",
        "node_id": node_id,
        "message": f"Node {node['name']} disconnected"
    })
    
    return {"status": "success"}

class CanMessagePayload(BaseModel):
    id: str   
    dlc: int
    data: str 

@app.post("/api/nodes/{node_id}/send")
async def send_can(node_id: str, msg: CanMessagePayload):
    if node_id not in nodes:
        raise HTTPException(status_code=404, detail="Node not found")
        
    sender = nodes[node_id]
    try:
        payload_tail = format_serial_hex_payload(msg.dlc, msg.data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    command = (
        f"send {msg.id} {msg.dlc}\n"
        if int(msg.dlc) == 0
        else f"send {msg.id} {msg.dlc} {payload_tail}\n"
    )
    
    if sender.get("is_sim"):
        # Mock behavior: show TX on sender, and RX on all other SIM nodes
        import time
        timestamp = int(time.time() * 1000) % 1000000
        current_id = normalize_can_id(msg.id)
        current_dlc = int(msg.dlc)
        current_data = normalize_can_data(current_dlc, msg.data)
        tx_line = (
            f"[{timestamp:10d} ms] [TX] single node={sender['name']} "
            f"id={current_id} type=STD dlc={current_dlc} data={current_data}"
        )
        await process_serial_line(node_id, tx_line)
        
        for other_id, other_node in nodes.items():
            if other_node.get("is_sim") and other_id != node_id:
                if should_block_sim_frame(other_node, current_id, current_dlc, current_data):
                    continue

                rx_line = (
                    f"[{timestamp:10d} ms] [RX] bus node={other_node['name']} "
                    f"id={current_id} type=STD dlc={current_dlc} data={current_data}"
                )
                await process_serial_line(other_id, rx_line)
    else:
        ser = sender['serial']
        try:
            ser.write(command.encode('utf-8'))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
        
    return {"status": "success"}


class DefensePayload(BaseModel):
    action: str
    duration: int = 10000


@app.post("/api/nodes/{node_id}/defense")
async def control_defense(node_id: str, payload: DefensePayload):
    if node_id not in nodes:
        raise HTTPException(status_code=404, detail="Node not found")

    node = nodes[node_id]
    action = payload.action.lower()
    if action not in ["on", "off", "status"]:
        raise HTTPException(
            status_code=400,
            detail="Unknown defense action. Use on, off, or status."
        )

    if action == "on" and (payload.duration < 1000 or payload.duration > 600000):
        raise HTTPException(
            status_code=400,
            detail="Defense duration must be between 1000 and 600000 ms."
        )

    if node.get("is_sim"):
        defense = node["defense"]
        now = int(time.time() * 1000)

        if action == "on":
            defense["active"] = True
            defense["duration_ms"] = payload.duration
            defense["until_ms"] = now + payload.duration
            defense["trusted_ids"] = sorted(observed_frames.keys())
            defense["last_allowed_at_ms"] = 0
            defense["spoof_baseline_bytes"] = []
            defense["spoof_baseline_dlc"] = 0
            if defense.get("last_reason") == "spoofing":
                baseline = observed_frames.get(defense.get("last_alert_id"))
                if baseline:
                    defense["spoof_baseline_bytes"] = list(baseline["payload_bytes"])
                    defense["spoof_baseline_dlc"] = int(baseline["payload_dlc"])
            mitigation_nodes = []
            if defense.get("last_reason") == "dos":
                mitigation_nodes = await stop_active_attackers(node_id, {"dos"})
            elif defense.get("last_reason") == "fuzzing":
                mitigation_nodes = await stop_active_attackers(node_id, {"fuzz"})
            await emit_log(
                node_id,
                "DEFENSE",
                f"Simulation defense enabled duration={payload.duration}ms"
            )
            if mitigation_nodes:
                await emit_log(
                    node_id,
                    "DEFENSE",
                    f"Requested attack mitigation on: {', '.join(mitigation_nodes)}"
                )
            return {
                "status": "success",
                "defense_active": True,
                "message": f"Defense active for {payload.duration} ms"
            }

        if action == "off":
            defense["active"] = False
            defense["duration_ms"] = 0
            defense["until_ms"] = 0
            defense["last_allowed_at_ms"] = 0
            defense["spoof_baseline_bytes"] = []
            defense["spoof_baseline_dlc"] = 0
            await emit_log(node_id, "DEFENSE", "Simulation defense disabled.")
            return {
                "status": "success",
                "defense_active": False,
                "message": "Defense cleared"
            }

        if defense["active"] and defense["until_ms"] <= now:
            defense["active"] = False
            defense["duration_ms"] = 0
            defense["until_ms"] = 0

        await emit_log(
            node_id,
            "STATUS",
            f"defense_active={1 if defense['active'] else 0}"
        )
        return {
            "status": "success",
            "defense_active": defense["active"],
            "message": "Defense is active" if defense["active"] else "Defense is idle"
        }

    if action == "on":
        mitigation_nodes = []
        if node.get("defense", {}).get("last_reason") == "dos":
            mitigation_nodes = await stop_active_attackers(node_id, {"dos"})
        elif node.get("defense", {}).get("last_reason") == "fuzzing":
            mitigation_nodes = await stop_active_attackers(node_id, {"fuzz"})
        command = f"defense on {payload.duration}\n"
        response = {
            "status": "success",
            "defense_active": True,
            "optimistic": True,
            "message": (
                f"Sent defense on {payload.duration}"
                if not mitigation_nodes
                else f"Sent defense on {payload.duration} and requested attack mitigation"
            )
        }
    elif action == "off":
        command = "defense off\n"
        response = {
            "status": "success",
            "defense_active": False,
            "optimistic": True,
            "message": "Sent defense off"
        }
    else:
        command = "defense status\n"
        response = {
            "status": "success",
            "pending": True,
            "message": "Requested defense status from node"
        }

    try:
        node["serial"].write(command.encode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return response

class AttackAction(BaseModel):
    action: str

class DosPayload(AttackAction):
    id: str = "0"
    period: int = 20

class RepeatPayload(AttackAction):
    id: str = "0"
    dlc: int = 8
    data: str = ""
    period: int = 100

class ReplayPayload(AttackAction):
    period: int = 250

@app.post("/api/nodes/{node_id}/attack/{attack_type}")
async def toggle_attack(node_id: str, attack_type: str, payload: dict):
    if node_id not in nodes:
        raise HTTPException(status_code=404, detail="Node not found")
    if attack_type not in ["dos", "spam", "repeat", "replay", "fuzz", "spoof"]:
        raise HTTPException(status_code=400, detail="Unknown attack type")
        
    node = nodes[node_id]
    action = payload.get("action", "stop")
    normalized_type = "dos" if attack_type == "spam" else attack_type
    supported_attack_types = ["dos", "repeat", "replay", "fuzz", "spoof"]
    
    # Handle stopping
    if action == "stop":
        if node.get("is_sim"):
            if normalized_type in node["attack_tasks"]:
                node["attack_tasks"][normalized_type].cancel()
                del node["attack_tasks"][normalized_type]
            node["active_attack_type"] = None
            await process_serial_line(
                node_id,
                f"[{0:10d} ms] [STATE] {sim_attack_state_message(normalized_type, False)}"
            )
        else:
            try:
                node['serial'].write(f"{normalized_type} stop\n".encode('utf-8'))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
            node["active_attack_type"] = None
        return {"status": "success"}

    # Handle starting
    if node.get("is_sim"):
        # Keep one active simulated attack at a time so the UI stays truthful.
        for existing_task in node["attack_tasks"].values():
            existing_task.cancel()
        node["attack_tasks"].clear()
            
        period = payload.get(
            "period",
            20 if normalized_type == "dos" else
            (100 if normalized_type == "repeat" else
             (250 if normalized_type == "replay" else
              (35 if normalized_type == "fuzz" else 120)))
        )
        msg_id = payload.get("id", "0x00")
        dlc = payload.get(
            "dlc",
            8 if normalized_type in ["dos", "fuzz"] else 2
        )
        data = payload.get(
            "data",
            "FF FF" if normalized_type == "replay" else
            ("AA 55" if normalized_type == "spoof" else "00")
        )

        if normalized_type == "spoof":
            try:
                spoof_payload = build_spoof_payload(payload.get("id"), node_id)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

            msg_id = spoof_payload["id"]
            dlc = spoof_payload["payload_dlc"]
            data = spoof_payload["payload_data"]
        
        node["attack_tasks"][normalized_type] = asyncio.create_task(
            sim_attack_task(node_id, normalized_type, msg_id, dlc, data, period)
        )
        node["active_attack_type"] = normalized_type
        await process_serial_line(
            node_id,
            f"[{0:10d} ms] [STATE] {sim_attack_state_message(normalized_type, True)}"
        )
    else:
        for existing_type in supported_attack_types:
            if existing_type == normalized_type:
                continue
            try:
                node['serial'].write(f"{existing_type} stop\n".encode('utf-8'))
            except Exception:
                pass

        command = ""
        if normalized_type == "dos":
            command = f"dos start {payload.get('id', '0')} {payload.get('period', 20)}\n"
        elif normalized_type == "repeat":
            try:
                payload_tail = format_serial_hex_payload(
                    int(payload.get('dlc', 0)),
                    payload.get('data', '')
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

            command = (
                f"repeat {payload.get('id', '0')} {payload.get('period', 100)} {payload.get('dlc', 0)}\n"
                if int(payload.get('dlc', 0)) == 0
                else f"repeat {payload.get('id', '0')} {payload.get('period', 100)} {payload.get('dlc', 0)} {payload_tail}\n"
            )
        elif normalized_type == "replay":
            command = f"replay start {payload.get('period', 250)}\n"
        elif normalized_type == "fuzz":
            command = f"fuzz start {payload.get('period', 35)}\n"
        elif normalized_type == "spoof":
            try:
                spoof_payload = build_spoof_payload(payload.get("id"), node_id)
                payload_tail = format_serial_hex_payload(
                    spoof_payload["payload_dlc"],
                    spoof_payload["payload_data"]
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

            command = (
                f"spoof start {spoof_payload['id']} {payload.get('period', 120)} {spoof_payload['payload_dlc']}\n"
                if int(spoof_payload["payload_dlc"]) == 0
                else (
                    f"spoof start {spoof_payload['id']} {payload.get('period', 120)} "
                    f"{spoof_payload['payload_dlc']} {payload_tail}\n"
                )
            )
            
        try:
            node['serial'].write(command.encode('utf-8'))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
        node["active_attack_type"] = normalized_type

    return {"status": "success"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

# Create static dir if it doesn't exist
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
