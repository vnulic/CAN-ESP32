import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from micromlgen import port
import glob

def main():
    print("1. Đọc dữ liệu từ các file CSV...")
    # Đọc tất cả các file CSV trong thư mục hiện tại
    all_files = glob.glob("*.csv")
    dataset_files = [f for f in all_files if f in ["Normal.csv", "DoS.csv", "Fuzzing.csv", "Spoofing.csv"]]
    
    if not dataset_files:
        print("Không tìm thấy các file dữ liệu (Normal.csv, DoS.csv, ...)")
        return

    df_list = []
    for file in dataset_files:
        label = file.replace(".csv", "")
        df = pd.read_csv(file)
        df['Label'] = label # Thêm cột nhãn
        df_list.append(df)
        
    data = pd.concat(df_list, ignore_index=True)
    
    print(f"Tổng số frame thu thập được: {len(data)}")

    # 2. Tiền xử lý dữ liệu
    # Bỏ cột timestamp vì Random Forest không cần quan tâm đến thời gian tuyệt đối
    X = data[['ID', 'DLC', 'D0', 'D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7']].values
    y = data['Label'].values

    # Chia tập train/test (80% học, 20% thi)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("2. Đang huấn luyện Random Forest...")
    # Tạo mô hình với 20 cây quyết định (đủ nhẹ cho ESP32, độ chính xác cao)
    clf = RandomForestClassifier(n_estimators=20, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)

    # Đánh giá trên tập Train
    train_acc = clf.score(X_train, y_train)
    print(f"-> Độ chính xác trên tập Train (Lúc học): {train_acc * 100:.2f}%")

    print("\n3. Đánh giá mô hình trên tập kiểm tra (Test Set):")
    # Đánh giá trên tập Test
    test_acc = clf.score(X_test, y_test)
    print(f"-> Độ chính xác trên tập Test (Lúc thi): {test_acc * 100:.2f}%\n")
    
    y_pred = clf.predict(X_test)
    
    print("--- MA TRẬN NHẦM LẪN (CONFUSION MATRIX) ---")
    labels = clf.classes_
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    cm_df = pd.DataFrame(cm, index=[f"Thực tế: {label}" for label in labels], columns=[f"Đoán là: {label}" for label in labels])
    print(cm_df.to_string())
    
    print("\n--- BÁO CÁO CHI TIẾT ---")
    print(classification_report(y_test, y_pred))

    print("4. Chuyển đổi mô hình thành C++ (TinyML)...")
    # Sử dụng micromlgen để port mô hình sang C++
    c_code = port(clf)
    
    with open("ml_model.h", "w") as f:
        f.write(c_code)
        
    print("Thành công! Đã lưu mô hình C++ vào file 'ml_model.h'")

if __name__ == "__main__":
    main()
