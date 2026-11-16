
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

import cipher_library as library

# ================= 1. HÀM DỰNG GIAO DIỆN DÙNG CHUNG =================

def make_title(parent, text):
    """Tiêu đề ở đầu mỗi phần."""
    label = tk.Label(parent, text=text)
    label.pack(anchor="w", padx=10, pady=(10, 4))


def make_input_frame(parent):
    """Khung viền chìm để chứa các ô nhập."""
    frame = tk.Frame(parent, bd=2, relief=tk.GROOVE, padx=10, pady=8)
    frame.pack(fill="x", padx=10, pady=4)
    return frame


def make_entry(frame, row, label_text, width):
    """Một dòng gồm nhãn bên trái và ô nhập bên phải (xếp theo hàng row)."""
    label = tk.Label(frame, text=label_text)
    label.grid(row=row, column=0, sticky="w", pady=3)
    entry = tk.Entry(frame, width=width)
    entry.grid(row=row, column=1, sticky="w", padx=6, pady=3)
    return entry


def make_text_box(parent, height):
    """Ô chữ nhiều dòng có thanh cuộn."""
    box = scrolledtext.ScrolledText(parent, height=height, wrap=tk.WORD)
    box.pack(fill="both", expand=True, padx=10, pady=4)
    return box


def make_result_label(parent):
    """Dòng chữ để hiện kết quả."""
    label = tk.Label(parent, text="", justify="left")
    label.pack(anchor="w", padx=10, pady=4)
    return label


def write_text(box, text):
    """Xóa nội dung cũ của ô chữ rồi ghi nội dung mới."""
    box.delete("1.0", tk.END)
    box.insert(tk.END, text)


def read_text(box):
    """Lấy toàn bộ chữ trong ô chữ ("end-1c" để bỏ ký tự xuống dòng Tkinter tự thêm ở cuối)."""
    return box.get("1.0", "end-1c")


def show_error(message):
    """Hiện hộp thoại báo lỗi."""
    messagebox.showerror("Lỗi", message)


# ================= 2. KHUNG DES VĂN BẢN / TỆP (dùng cho tab 2 và tab 3) =================

def make_des_panel(parent, title, encrypt_command, decrypt_command, choose_command, clear_command):
    panel = {}
    panel["key_type"] = tk.StringVar(value="hex")      # biến lưu lựa chọn kiểu khóa: "hex" hoặc "text"
    panel["file_data"] = None                           # các byte của tệp đã chọn; None = chưa chọn tệp

    make_title(parent, title)
    frame = make_input_frame(parent)

    # Dòng 0: kiểu khóa
    tk.Label(frame, text="Kiểu khóa:").grid(row=0, column=0, sticky="w")
    key_type_frame = tk.Frame(frame)
    key_type_frame.grid(row=0, column=1, sticky="w", padx=6)
    hex_choice = tk.Radiobutton(key_type_frame, text="16 ký tự hex", variable=panel["key_type"], value="hex")
    hex_choice.pack(side="left")
    text_choice = tk.Radiobutton(key_type_frame, text="8 ký tự chữ", variable=panel["key_type"], value="text")
    text_choice.pack(side="left", padx=10)

    # Dòng 1: khóa
    panel["key_entry"] = make_entry(frame, 1, "Khóa K:", 26)

    # Dòng 2: chọn tệp
    tk.Label(frame, text="Tệp .txt:").grid(row=2, column=0, sticky="w", pady=3)
    file_frame = tk.Frame(frame)
    file_frame.grid(row=2, column=1, sticky="w", padx=6)
    tk.Button(file_frame, text="Chọn tệp...", command=choose_command).pack(side="left")
    tk.Button(file_frame, text="Bỏ tệp", command=clear_command).pack(side="left", padx=6)
    panel["file_label"] = tk.Label(file_frame, text="(chưa chọn, dùng ô dữ liệu bên dưới)")
    panel["file_label"].pack(side="left", padx=6)

    # Hai nút bên phải
    button_frame = tk.Frame(frame)
    button_frame.grid(row=0, column=2, rowspan=3, padx=20)
    tk.Button(button_frame, text="Mã hóa", command=encrypt_command).pack(fill="x", pady=2)
    tk.Button(button_frame, text="Giải mã", command=decrypt_command).pack(fill="x", pady=2)

    # Ô dữ liệu vào và ô kết quả
    tk.Label(parent, text="Dữ liệu (mã hóa: văn bản; giải mã: chuỗi hex bản mã)").pack(anchor="w", padx=10)
    panel["input_box"] = make_text_box(parent, 5)

    panel["output_title"] = tk.Label(parent, text="Kết quả")
    panel["output_title"].pack(anchor="w", padx=10)
    panel["output_box"] = make_text_box(parent, 6)
    panel["info_label"] = make_result_label(parent)
    return panel


def choose_file(panel):
    """Mở hộp thoại chọn tệp, đọc cả tệp vào panel["file_data"]."""
    path = filedialog.askopenfilename(filetypes=[("Tệp văn bản", "*.txt"), ("Tất cả", "*.*")])
    if path == "":                      # người dùng bấm Hủy
        return
    file = open(path, "rb")
    panel["file_data"] = file.read()
    file.close()
    file_name = path.replace("\\", "/").split("/")[-1]     # chỉ lấy tên tệp, bỏ đường dẫn
    panel["file_label"].config(text=file_name)


def clear_file(panel):
    """Bỏ tệp đã chọn, quay lại dùng ô dữ liệu."""
    panel["file_data"] = None
    panel["file_label"].config(text="(chưa chọn, dùng ô dữ liệu bên dưới)")


def run_des(panel, decrypt, use_standard):
    """Xử lý nút Mã hóa / Giải mã của một khung DES.

    decrypt     : 0 = mã hóa, 1 = giải mã
    use_standard: False = thuật toán nhóm, True = thư viện chuẩn
    """
    key_bytes, error = library.read_des_key(panel["key_entry"].get(), panel["key_type"].get())
    if error:
        show_error(error)
        return

    # Ưu tiên tệp đã chọn; nếu chưa chọn tệp thì lấy chữ trong ô dữ liệu
    if panel["file_data"] is not None:
        data = panel["file_data"]
    else:
        data = read_text(panel["input_box"]).encode("utf-8")

    result, error = library.des_text(data, key_bytes, decrypt, use_standard)
    if error:
        show_error(error)
        return

    if decrypt == 1:
        panel["output_title"].config(text="Bản rõ")
    else:
        panel["output_title"].config(text="Bản mã (hex)")
    write_text(panel["output_box"], result["output"])
    panel["info_label"].config(text="Số khối 64 bít: " + str(result["blocks"]) +
                                    "   |   Thời gian chạy: " + str(round(result["milliseconds"], 3)) + " ms")


# ================= 3. TAB 1: TINYDES TỪNG BƯỚC =================

def tinydes_encrypt():
    tinydes_run(0)


def tinydes_decrypt():
    tinydes_run(1)


def tinydes_run(decrypt):
    trace, milliseconds, error = library.tinydes_run(tinydes_block_entry.get(), tinydes_key_entry.get(), decrypt)
    if error:
        show_error(error)
        return

    if decrypt == 1:
        name = "Bản rõ P"
    else:
        name = "Bản mã C"
    output_text = library.binary(trace.out, 8) + " (hex " + library.number_to_hex(trace.out, 2) + ")"
    tinydes_result_label.config(text=name + " = " + output_text +
                                     "   |   Thời gian chạy: " + str(round(milliseconds, 3)) + " ms")
    write_text(tinydes_steps_box, library.tinydes_steps(trace, decrypt))


def build_tinydes_tab(tab):
    global tinydes_block_entry, tinydes_key_entry, tinydes_result_label, tinydes_steps_box

    frame = make_input_frame(tab)
    tinydes_block_entry = make_entry(frame, 0, "Khối vào (8 bít hoặc 2 ký tự hex):", 16)
    tinydes_key_entry = make_entry(frame, 1, "Khóa K (8 bít hoặc 2 ký tự hex):", 16)

    button_frame = tk.Frame(frame)
    button_frame.grid(row=0, column=2, rowspan=2, padx=20)
    tk.Button(button_frame, text="Mã hóa", command=tinydes_encrypt).pack(fill="x", pady=2)
    tk.Button(button_frame, text="Giải mã", command=tinydes_decrypt).pack(fill="x", pady=2)

    tinydes_result_label = make_result_label(tab)
    tk.Label(tab, text="Các bước trung gian").pack(anchor="w", padx=10)
    tinydes_steps_box = make_text_box(tab, 24)


# ================= 4. TAB 2: DES THUẬT TOÁN NHÓM =================

def group_encrypt():
    run_des(group_panel, 0, False)


def group_decrypt():
    run_des(group_panel, 1, False)


def group_choose_file():
    choose_file(group_panel)


def group_clear_file():
    clear_file(group_panel)


def build_group_tab(tab):
    global group_panel
    group_panel = make_des_panel(tab, "", group_encrypt, group_decrypt, group_choose_file, group_clear_file)


# ================= 5. TAB 3: KIỂM THỬ BẰNG THƯ VIỆN CHUẨN =================

def test_one_block():
    ciphertext, error = library.standard_one_block(test_plaintext_entry.get(), test_key_entry.get())
    if error:
        show_error(error)
        return
    test_result_label.config(text="Bản mã (hex) = " + ciphertext)


def test_encrypt():
    run_des(test_panel, 0, True)


def test_decrypt():
    run_des(test_panel, 1, True)


def test_choose_file():
    choose_file(test_panel)


def test_clear_file():
    clear_file(test_panel)


def build_test_tab(tab):
    global test_plaintext_entry, test_key_entry, test_result_label, test_panel

    # Phần 1: một khối 64 bít
    make_title(tab, "Kiểm thử một khối 64 bít bằng thư viện chuẩn PyCryptodome")
    frame = make_input_frame(tab)
    test_plaintext_entry = make_entry(frame, 0, "Bản rõ (16 ký tự hex):", 22)
    test_key_entry = make_entry(frame, 1, "Khóa K (16 ký tự hex):", 22)
    tk.Button(frame, text="Chạy", command=test_one_block).grid(row=0, column=2, rowspan=2, padx=20)
    test_result_label = make_result_label(tab)

    ttk.Separator(tab).pack(fill="x", padx=10, pady=4)     # đường kẻ ngang ngăn 2 phần

    # Phần 2: văn bản / tệp
    test_panel = make_des_panel(tab, "Kiểm thử văn bản / tệp .txt bằng thư viện chuẩn (ECB, đệm PKCS#7)",
                                test_encrypt, test_decrypt, test_choose_file, test_clear_file)


# ================= 6. TAB 4: TẤN CÔNG VÉT CẠN =================

def attack_tinydes():
    found_keys, error = library.tinydes_bruteforce(brute_plaintext_entry.get(), brute_ciphertext_entry.get())
    if error:
        show_error(error)
        return

    if len(found_keys) == 0:
        keys_text = "không có"
    else:
        keys_text = ", ".join(found_keys)          # nối các khóa, cách nhau bởi dấu phẩy
    brute_result_label.config(text="Đã thử 256 khóa, tìm được " + str(len(found_keys)) + " khóa:\n" + keys_text)


def attack_des():
    unknown_bits_text = unknown_bits_box.get()
    if not unknown_bits_text.isdigit():
        show_error("Số bit chưa biết N phải là số từ 8 đến 20.")
        return

    # Hiện chữ "Đang chạy..." trước, vì trong lúc vét cạn cửa sổ sẽ đứng yên vài giây
    write_text(des_brute_box, "Đang thử 2^" + unknown_bits_text + " khóa, vui lòng chờ...")
    window.update()

    result, error = library.des_bruteforce(des_plaintext_entry.get(), des_key_entry.get(),
                                           int(unknown_bits_text))
    if error:
        write_text(des_brute_box, "")
        show_error(error)
        return

    text = ""
    text += "Bản rõ P            = " + result["plaintext"] + "\n"
    text += "Bản mã C = DES(P,K) = " + result["ciphertext"] + "\n"
    text += "\n"
    text += "Khóa kẻ tấn công biết ('?' là " + str(result["unknown_bits"]) + " bit chưa biết,\n"
    text += "bit cuối mỗi byte là bit chẵn lẻ):\n"
    text += "  " + result["known_key"] + "\n"
    text += "\n"
    text += "Số khóa đã thử      : " + str(result["tried"]) + "\n"
    text += "Số khóa thỏa mãn    : " + str(result["found_count"]) + "\n"
    text += "Khóa tìm được       : " + result["found_key"] + "\n"
    text += "Tìm thấy ở lần thử  : " + str(result["found_index"]) + "\n"
    text += "Thời gian           : " + str(result["seconds"]) + " giây\n"
    text += "Tốc độ              : " + str(result["speed"]) + " khóa/giây\n"
    text += "\n"
    text += "Ước tính với DES đầy đủ (2^56 khóa) ở tốc độ này:\n"
    text += "  Thử hết            : " + str(result["full_years"]) + " năm\n"
    text += "  Trung bình (1/2)   : " + str(result["average_years"]) + " năm\n"
    write_text(des_brute_box, text)


def build_bruteforce_tab(tab):
    global brute_plaintext_entry, brute_ciphertext_entry, brute_result_label
    global des_plaintext_entry, des_key_entry, unknown_bits_box, des_brute_box

    left = tk.Frame(tab)                # nửa trái: TinyDES
    left.pack(side="left", fill="both", expand=True)
    right = tk.Frame(tab)               # nửa phải: DES rút gọn
    right.pack(side="left", fill="both", expand=True)

    # ----- Nửa trái: vét cạn TinyDES -----
    make_title(left, "Vét cạn TinyDES (2^8 = 256 khóa)")
    frame = make_input_frame(left)
    brute_plaintext_entry = make_entry(frame, 0, "Bản rõ P:", 12)
    brute_ciphertext_entry = make_entry(frame, 1, "Bản mã C:", 12)
    tk.Button(frame, text="Tấn công", command=attack_tinydes).grid(row=0, column=2, rowspan=2, padx=16)
    brute_result_label = make_result_label(left)


    # ----- Nửa phải: vét cạn DES rút gọn -----
    make_title(right, "Vét cạn DES rút gọn (chưa biết N bit khóa)")
    frame = make_input_frame(right)
    des_plaintext_entry = make_entry(frame, 0, "Bản rõ P (hex):", 20)
    des_key_entry = make_entry(frame, 1, "Khóa thật K (hex):", 20)

    tk.Label(frame, text="Số bit chưa biết N:").grid(row=2, column=0, sticky="w", pady=3)
    unknown_bits_box = tk.Spinbox(frame, from_=8, to=20, width=5)     # ô chọn số 8..20
    unknown_bits_box.grid(row=2, column=1, sticky="w", padx=6)

    tk.Button(frame, text="Tấn công", command=attack_des).grid(row=0, column=2, rowspan=3, padx=16)
    des_brute_box = make_text_box(right, 20)


# ================= 7. CỬA SỔ CHÍNH =================

window = tk.Tk()
window.title("Hệ mã khối TinyDES và DES")
window.geometry("1100x800")

# Notebook là khung có nhiều tab; mỗi tab là một Frame
notebook = ttk.Notebook(window)
notebook.pack(fill="both", expand=True, padx=8, pady=8)

tinydes_tab = tk.Frame(notebook)
group_tab = tk.Frame(notebook)
test_tab = tk.Frame(notebook)
bruteforce_tab = tk.Frame(notebook)

notebook.add(tinydes_tab, text="  TinyDES   ")
notebook.add(group_tab, text="  DES  ")
notebook.add(test_tab, text="  Kiểm thử  ")
notebook.add(bruteforce_tab, text="  Tấn công vét cạn  ")

build_tinydes_tab(tinydes_tab)
build_group_tab(group_tab)
build_test_tab(test_tab)
build_bruteforce_tab(bruteforce_tab)

window.mainloop()       # chạy vòng lặp giao diện: chờ người dùng bấm nút cho đến khi đóng cửa sổ
