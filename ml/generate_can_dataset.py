import csv
import random
import time
import math
import os

# Cấu hình
NUM_SAMPLES = 10000

# Trạng thái giả lập của các Node bình thường
nodes = {
    0x100: {"period": 0.05, "last_time": 0, "counter": 0, "type": "sine"},   # 50ms
    0x200: {"period": 0.10, "last_time": 0, "counter": 0, "type": "random"}, # 100ms
    0x300: {"period": 0.25, "last_time": 0, "counter": 0, "type": "static"}  # 250ms
}

def generate_normal_data(node_id, current_time, node_state):
    data = [0] * 8
    
    # Sinh dữ liệu cảm biến giả lập
    if node_state["type"] == "sine":
        val = int((math.sin(current_time * 2) + 1) * 127)
        data[0] = val
    elif node_state["type"] == "random":
        data[0] = random.randint(0, 255)
    elif node_state["type"] == "static":
        data[0] = 0xAA

    # Byte cuối cùng là Counter (để khớp với ENABLE_COUNTER_PROTECTION của bạn)
    data[7] = node_state["counter"]
    node_state["counter"] = (node_state["counter"] + 1) % 256
    
    return data

def main():
    files = {
        "Normal": open("Normal.csv", "w", newline=''),
        "DoS": open("DoS.csv", "w", newline=''),
        "Fuzzing": open("Fuzzing.csv", "w", newline=''),
        "Spoofing": open("Spoofing.csv", "w", newline='')
    }
    
    writers = {}
    for label, f in files.items():
        writer = csv.writer(f)
        writer.writerow(["timestamp", "ID", "DLC", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7"])
        writers[label] = writer

    current_time = 0.0
    
    # Biến trạng thái tấn công
    attack_mode = "Normal"
    attack_end_time = 0
    attack_types = ["DoS", "Fuzzing", "Spoofing", "DoS"] # Ensure we hit all of them
    attack_idx = 0
    
    for i in range(NUM_SAMPLES):
        # Cứ mỗi 2000 frame, tạo 1 đợt tấn công kéo dài 0.5 giây
        if i % 2000 == 0 and i > 0:
            attack_mode = attack_types[attack_idx % len(attack_types)]
            attack_idx += 1
            attack_end_time = current_time + 0.5
            print(f"[{current_time:.2f}s] Bắt đầu tấn công: {attack_mode}")

        if current_time > attack_end_time:
            attack_mode = "Normal"

        label = "Normal"
        can_id = 0
        dlc = 8
        data = [0]*8

        # Xử lý luồng tấn công
        if attack_mode == "DoS":
            # Spam frame liên tục (0x000) với tần suất siêu nhanh
            can_id = 0x000
            data = [0xFF] * 8
            label = "DoS"
            current_time += 0.002 # Cách nhau 2ms
            
        elif attack_mode == "Fuzzing":
            # Frame rác, ID random, data random
            can_id = random.randint(0x001, 0x7FF)
            data = [random.randint(0, 255) for _ in range(8)]
            label = "Fuzzing"
            current_time += 0.01

        elif attack_mode == "Spoofing":
            # Giả mạo ID 0x100 nhưng counter bị sai lệch hoặc data tăng vọt
            can_id = 0x100
            data = [0xFF, 0xEE, 0, 0, 0, 0, 0, random.randint(0, 255)] # Counter sai quy luật
            label = "Spoofing"
            current_time += 0.01

        else:
            # Luồng NORMAL
            # Tìm node đến hạn gửi
            target_id = None
            for nid, state in nodes.items():
                if current_time - state["last_time"] >= state["period"]:
                    target_id = nid
                    break
            
            if target_id is not None:
                can_id = target_id
                data = generate_normal_data(target_id, current_time, nodes[target_id])
                nodes[target_id]["last_time"] = current_time
                label = "Normal"
                current_time += 0.001
            else:
                # Tăng thời gian nếu không có ai gửi
                current_time += 0.005
                continue # Bỏ qua vòng lặp này, không ghi frame

        # Ghi ra CSV tương ứng (ID được ghi dưới dạng số nguyên base-10 để Edge Impulse hiểu được)
        row = [f"{current_time:.4f}", can_id, dlc] + data
        writers[label].writerow(row)

    for f in files.values():
        f.close()

    print(f"Đã tạo thành công 4 file CSV: Normal.csv, DoS.csv, Fuzzing.csv, Spoofing.csv!")

if __name__ == "__main__":
    main()
