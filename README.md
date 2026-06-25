# ESP32 CAN Security Demo

ESP32 + TJA1050 CAN demo with:

- UART terminal control
- web control panel
- attack simulation
- heuristic detection
- manual defense activation

The firmware is tailored for ESP32 and keeps legacy text-over-CAN mode for compatibility.

## Hướng dẫn chạy lần đầu (Quick Start)

Dành cho người mới chạy chương trình này lần đầu.

### 1. Chuẩn bị

- **Phần cứng**: ít nhất 1 board ESP32 (khuyến nghị 2-3 board để demo tấn công/phòng thủ đầy đủ), mỗi board nối với module CAN transceiver `TJA1050` (RX → `GPIO27`, TX → `GPIO26`), cáp USB để nạp firmware và giao tiếp UART. Nếu chưa có phần cứng, có thể bỏ qua bước nạp firmware và dùng node giả lập (`SIM1`, `SIM2`, ...) trong web UI.
- **Phần mềm**:
  - [Python 3.10+](https://www.python.org/downloads/) (đã có sẵn `pip`)
  - [PlatformIO Core](https://platformio.org/install/cli) — cài bằng `pip install platformio`, hoặc dùng extension PlatformIO IDE trong VS Code
  - Driver USB-to-UART cho board (thường là CP210x hoặc CH340, tùy loại board ESP32)

### 2. Lấy mã nguồn

```powershell
git clone https://github.com/vnulic/CAN-ESP32.git
cd CAN-ESP32-thi-nghiem
```

### 3. Nạp firmware lên board (nếu dùng phần cứng thật)

Xác định cổng COM của board đang cắm:

```powershell
python -m platformio device list
```

Build và nạp:

```powershell
python -m platformio run -t upload --upload-port COM7
```

Nếu gặp lỗi `Wrong boot mode detected (0x13)`, giữ nút **BOOT** trên board, nhấn-thả nhanh **EN/RESET** (vẫn giữ BOOT), rồi chạy lại lệnh upload trong lúc vẫn giữ BOOT khoảng 10-15 giây.

Lặp lại bước này cho mỗi board (Node A, B, C) với cổng COM tương ứng.

### 4. Cài và chạy web control panel

```powershell
python -m pip install -r web/requirements.txt
cd web
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Mở trình duyệt

Truy cập:

```text
http://localhost:8000
```

### 6. Thêm node trong giao diện web

- Dùng phần cứng thật: thêm node với cổng COM tương ứng (ví dụ `COM7`, `COM8`, `COM9`)
- Không có phần cứng: thêm node giả lập với tên cổng `SIM1`, `SIM2`, `SIM3`, ...

Sau khi thêm node, chọn node ở sidebar bên trái để gửi frame CAN hoặc khởi chạy các kịch bản tấn công (DoS, Replay, Fuzzing, Spoofing) và xem cảnh báo/phòng thủ theo thời gian thực. Tham khảo phần "A/B/C Demo Script" và "Web Demo Flow" dưới đây để chạy đúng kịch bản.

## Hardware

Default firmware settings:

- CAN RX: `GPIO27`
- CAN TX: `GPIO26`
- CAN bitrate: `500 kbps`
- UART monitor: `115200`

## Terminal Commands

```text
send <id> <dlc> <data...>
repeat <id> <period_ms> <dlc> <data...>
repeat stop

dos start <id> <period_ms>
dos stop
spam start <id> <period_ms>
spam stop

replay start [period_ms]
replay stop

fuzz start [period_ms]
fuzz stop

spoof start <id> <period_ms> <dlc> <data...>
spoof stop

defense on [duration_ms]
defense off
defense status

status
verbose on
verbose off
text <message>
help
```

Notes:

- `spam` is kept as an alias of `dos`
- with `ENABLE_COUNTER_PROTECTION = 1`, raw payload input is limited to `7` bytes
- the firmware appends the last counter byte automatically
- unrecognized input is sent using legacy text mode

## Attack Coverage

Implemented attacks:

- `DoS`: high-rate frames on one ID
- `Replay`: resend the latest captured valid frame
- `Fuzzing`: rapidly mutate IDs and payloads
- `Spoofing`: send forged payloads on a known ID

Implemented detection:

- `DoS suspected`
- `REPLAY suspected` by duplicate window
- `REPLAY suspected` by counter mismatch
- `FUZZING suspected` by ID churn / window behavior
- `SPOOFING suspected` by payload baseline deviation
- ML detection code is present in the repo but currently disabled by default

## Web UI

Install and run:

```powershell
python -m pip install -r web/requirements.txt
python -m uvicorn web.main:app --host 0.0.0.0 --port 8000 --reload
```

Open:

```text
http://localhost:8000
```

Use `COM7`, `COM8`, ... for real ESP32 nodes or `SIM1`, `SIM2`, ... for simulated nodes.

## A/B/C Demo Script

Recommended roles:

- Node A: normal sender
- Node B: detector / defender
- Node C: attacker

### 1. Normal traffic

Node A:

```text
send 0x120 2 0x10 0x20
repeat 0x120 1000 2 0x10 0x20
```

Expected on Node B:

- `[RX]` appears
- no `[ALERT]`

Stop:

```text
repeat stop
```

### 2. Replay attack

Preparation:

- Node A sends one valid frame first
- Node C must have seen that frame on the bus

Node C:

```text
replay start
```

Expected on Node B:

- repeated `[RX]`
- `[ALERT] REPLAY suspected ...`

Optional defense on Node B:

```text
defense on
```

Stop:

```text
replay stop
```

### 3. DoS attack

Node C:

```text
dos start 0x120 20
```

Expected on Node B:

- dense RX stream
- `[ALERT] DoS suspected ...`

Stop:

```text
dos stop
```

### 4. Fuzzing attack

Node C:

```text
fuzz start 35
```

Expected on Node B:

- fast-changing IDs and payloads
- `[ALERT] FUZZING suspected ...`

Stop:

```text
fuzz stop
```

### 5. Spoofing attack

Preparation:

- let Node A send the same ID normally a few times to establish a baseline

Node A:

```text
send 0x120 2 0x10 0x20
send 0x120 2 0x10 0x20
send 0x120 2 0x10 0x20
```

Node C:

```text
spoof start 0x120 120 2 0xAA 0x55
```

Expected on Node B:

- `[ALERT] SPOOFING suspected ...`

Stop:

```text
spoof stop
```

## Web Demo Flow

With real hardware:

1. Add `Node A = COMx`
2. Add `Node B = COMy`
3. Add `Node C = COMz`
4. Select a node in the left sidebar
5. Use the right panel to send or launch attacks

With simulation only:

1. Add `Node A = SIM1`
2. Add `Node B = SIM2`
3. Add `Node C = SIM3`
4. Launch `DoS`, `Replay`, `Fuzz`, or `Spoof` from `Node C`
5. Observe alerts on the workspace cards for the other nodes

## Build

```powershell
python -m platformio run
```

Upload:

```powershell
python -m platformio run -t upload --upload-port COM7
```
