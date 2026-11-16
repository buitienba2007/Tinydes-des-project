
import ctypes
import os
import time

from Crypto.Cipher import DES as StandardDES          # thư viện chuẩn, để kiểm thử
from Crypto.Util.Padding import pad, unpad

#  1. Nạp thư viện C

# Thư mục core nằm cạnh thư mục gui
this_folder = os.path.dirname(os.path.abspath(__file__))
core_folder = os.path.join(this_folder, "..", "core")

if os.name == "nt":                                     # Windows
    library_path = os.path.join(core_folder, "cipher.dll")
else:                                                   # Linux, macOS
    library_path = os.path.join(core_folder, "libcipher.so")

cipher = ctypes.CDLL(os.path.abspath(library_path))

# Khai báo các struct của cipher.h để Python đọc được các bước trung gian.
class TDRound(ctypes.Structure):
    _fields_ = [("KL", ctypes.c_uint8), ("KR", ctypes.c_uint8),     # 2 nửa khóa của vòng (4 bit)
                ("Ki", ctypes.c_uint8),                             # khóa con (6 bit)
                ("L0", ctypes.c_uint8), ("R0", ctypes.c_uint8),     # 2 nửa đầu vòng (4 bit)
                ("E", ctypes.c_uint8), ("XOR", ctypes.c_uint8),     # Expand (6 bit), XOR khóa con (6 bit)
                ("S", ctypes.c_uint8), ("F", ctypes.c_uint8),       # S-box (4 bit), P-box = F (4 bit)
                ("L1", ctypes.c_uint8), ("R1", ctypes.c_uint8)]     # 2 nửa cuối vòng (4 bit)


class TDTrace(ctypes.Structure):
    _fields_ = [("input", ctypes.c_uint8), ("key", ctypes.c_uint8), ("out", ctypes.c_uint8),
                ("KL0", ctypes.c_uint8), ("KR0", ctypes.c_uint8),   # 2 nửa khóa ban đầu
                ("L0", ctypes.c_uint8), ("R0", ctypes.c_uint8),     # 2 nửa khối vào
                ("r", TDRound * 3)]                                 # 3 vòng


#   c_uint8  : số 8 bit (uint8_t)      c_int    : số nguyên (int)
#   c_uint64 : số 64 bit (uint64_t)    c_char_p : mảng byte (uint8_t*)
#   c_void_p : con trỏ bất kỳ          POINTER(TDTrace): con trỏ tới struct TDTrace
cipher.td_run.argtypes = [ctypes.c_uint8, ctypes.c_uint8, ctypes.c_int, ctypes.POINTER(TDTrace)]
cipher.td_run.restype = ctypes.c_uint8

cipher.des_buf.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
cipher.des_buf.restype = ctypes.c_int

cipher.des_run.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int, ctypes.c_void_p]
cipher.des_run.restype = ctypes.c_uint64

cipher.des_bruteforce.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int,
                                  ctypes.c_void_p, ctypes.c_void_p]
cipher.des_bruteforce.restype = ctypes.c_int


# 2. Hàm phụ 

def remove_spaces(text):  #Bỏ mọi khoảng trắng 
    return text.replace(" ", "")

# Kiểm tra chuỗi chỉ gồm ký tự hex 0-9, A-F (hoặc a-f)
def is_hex(text):
    for character in text:
        if character not in "0123456789ABCDEFabcdef":
            return False
    return True

# Viết số dạng hex in hoa, đủ digits chữ số: number_to_hex(146, 4) -> '0092
def number_to_hex(number, digits):
    text = hex(number)                  # hex(146) = '0x92'
    text = text[2:].upper()             # bỏ '0x' ở đầu -> '92'
    while len(text) < digits:           # thêm số 0 bên trái cho đủ độ dài
        text = "0" + text
    return text

#Viết số dạng nhị phân đủ width bit
def binary(number, width):
    text = bin(number)[2:]              # bỏ '0b'
    while len(text) < width:
        text = "0" + text
    return text


def milliseconds_since(start):      
    return (time.perf_counter() - start) * 1000     # Số ms đã trôi qua kể từ thời điểm start.


# 3. Tinydes

def read_tinydes_block(text, name):
    #Đọc khối / khóa TinyDES: 8 ký tự 0/1  hoặc 2 ký tự hex .
    #Trả về (số 8 bit, error).

    text = remove_spaces(text)
    if len(text) == 8 and text.count("0") + text.count("1") == 8:
        return int(text, 2), None                   # đọc theo cơ số 2
    if len(text) == 2 and is_hex(text):
        return int(text, 16), None                  # đọc theo cơ số 16
    return None, name + " cần 8 bit nhị phân hoặc 2 ký tự hex."


def tinydes_run(block_text, key_text, decrypt):
    #Mã hóa (decrypt = 0) , giải mã (decrypt = 1) một khối TinyDES.
    #Hàm C td_run ghi mọi bước trung gian vào struct trace.
    #Trả về (trace, milliseconds, error).
    
    block, error = read_tinydes_block(block_text, "Khối vào")
    if error:
        return None, 0, error
    key, error = read_tinydes_block(key_text, "Khóa")
    if error:
        return None, 0, error

    trace = TDTrace()                               # struct rỗng để C ghi vào
    start = time.perf_counter()
    cipher.td_run(block, key, decrypt, ctypes.byref(trace))     # truyền địa chỉ của trace
    milliseconds = milliseconds_since(start)
    return trace, milliseconds, None


def tinydes_steps(trace, decrypt):               # Đổi các bước trong trace thành chuỗi nhiều dòng
    text = ""
    if decrypt == 0:
        text += "P = " + binary(trace.input, 8) + " (" + number_to_hex(trace.input, 2) + ")"
        text += "  ->  L0 = " + binary(trace.L0, 4) + ", R0 = " + binary(trace.R0, 4) + "\n"
    else:
        text += "C = " + binary(trace.input, 8) + " (" + number_to_hex(trace.input, 2) + ")"
        text += "  ->  L3 = " + binary(trace.L0, 4) + ", R3 = " + binary(trace.R0, 4) + "\n"
    text += "K = " + binary(trace.key, 8) + " (" + number_to_hex(trace.key, 2) + ")"
    text += "  ->  KL0 = " + binary(trace.KL0, 4) + ", KR0 = " + binary(trace.KR0, 4) + "\n"

    for round_number in range(1, 4):                # vòng 1, 2, 3
        step = trace.r[round_number - 1]
        if decrypt == 0:
            key_index = round_number                # mã hóa dùng K1, K2, K3
        else:
            key_index = 4 - round_number            # giải mã dùng K3, K2, K1
        k = str(key_index)
        before = str(key_index - 1)

        text += "\n"
        if decrypt == 0:
            text += "--- Vòng " + str(round_number) + " ---\n"
        else:
            text += "--- Bước " + str(round_number) + " (dùng khóa K" + k + ") ---\n"

        text += "  KL" + k + " = " + binary(step.KL, 4) + "   KR" + k + " = " + binary(step.KR, 4) + "\n"
        text += "  K" + k + " = Compress(KL" + k + " KR" + k + ") = " + binary(step.Ki, 6) + "\n"

        if decrypt == 0:
            # Mã hóa: L_k = R_(k-1);  R_k = L_(k-1) XOR F(R_(k-1), K_k)
            text += "  Expand(R" + before + ") = " + binary(step.E, 6) + "\n"
            text += "  Expand(R" + before + ") ⊕ K" + k + " = " + binary(step.XOR, 6) + "\n"
            text += "  S-box = " + binary(step.S, 4) + "\n"
            text += "  F" + k + " = P-box = " + binary(step.F, 4) + "\n"
            text += "  L" + k + " = R" + before + " = " + binary(step.L1, 4)
            text += "   R" + k + " = L" + before + " ⊕ F" + k + " = " + binary(step.R1, 4) + "\n"
        else:
            # Giải mã: R_(k-1) = L_k;  L_(k-1) = R_k XOR F(L_k, K_k)
            text += "  Expand(L" + k + ") = " + binary(step.E, 6) + "\n"
            text += "  Expand(L" + k + ") ⊕ K" + k + " = " + binary(step.XOR, 6) + "\n"
            text += "  S-box = " + binary(step.S, 4) + "\n"
            text += "  F" + k + " = P-box = " + binary(step.F, 4) + "\n"
            text += "  L" + before + " = R" + k + " ⊕ F" + k + " = " + binary(step.L1, 4)
            text += "   R" + before + " = L" + k + " = " + binary(step.R1, 4) + "\n"

    text += "\n"
    if decrypt == 0:
        text += "Bản mã C = L3 R3 = " + binary(trace.out, 8) + " (hex " + number_to_hex(trace.out, 2) + ")"
    else:
        text += "Bản rõ P = L0 R0 = " + binary(trace.out, 8) + " (hex " + number_to_hex(trace.out, 2) + ")"
    return text


def tinydes_bruteforce(plaintext_text, ciphertext_text):
    #Thử cả 256 khóa TinyDES, giữ các khóa thỏa TinyDES(P, K) = C
    #Trả về (danh sách khóa hex tìm được, error)

    plaintext, error = read_tinydes_block(plaintext_text, "Bản rõ")
    if error:
        return None, error
    ciphertext, error = read_tinydes_block(ciphertext_text, "Bản mã")
    if error:
        return None, error

    found_keys = []
    for key in range(256):
        if cipher.td_run(plaintext, key, 0, None) == ciphertext:      # None = không ghi các bước
            found_keys.append(number_to_hex(key, 2))
    return found_keys, None


# 4. DES : mã hóa văn bản , tệp

def read_des_key(key_text, key_type):
    #Đổi khóa người dùng nhập thành 8 byte. Trả về (key_bytes, error).
    #key_type = "hex" : khóa là 16 ký tự hex
    #key_type = "text": khóa là 8 ký tự chữ(nên là không dấu )
    
    if key_type == "hex":
        key_hex = remove_spaces(key_text)
        if len(key_hex) != 16 or not is_hex(key_hex):
            return None, "Khóa hex cần đúng 16 ký tự 0-9, A-F."
        return bytes.fromhex(key_hex), None

    key_bytes = key_text.encode("utf-8")
    if len(key_bytes) != 8:
        return None, ("Khóa chữ cần đúng 8 byte (hiện có " + str(len(key_bytes)) + " byte). "
                      "Chữ có dấu tiếng Việt chiếm 2-3 byte mỗi ký tự.")
    return key_bytes, None


def group_des(data, key_bytes, decrypt):
    """Mã hóa / giải mã bằng hàm des_buf của nhóm (C). Trả về các byte kết quả, hoặc None nếu sai đệm."""
    output_buffer = ctypes.create_string_buffer(len(data) + 8)     # vùng nhớ để C ghi kết quả vào
    output_length = cipher.des_buf(data, len(data), key_bytes, output_buffer, decrypt)
    if output_length < 0:
        return None
    return output_buffer.raw[:output_length]


def standard_des(data, key_bytes, decrypt):
    #dùng thư viện chuẩn PyCryptodome (ECB + đệm PKCS#7)
    standard_cipher = StandardDES.new(key_bytes, StandardDES.MODE_ECB)
    if decrypt == 0:
        return standard_cipher.encrypt(pad(data, 8))

    decrypted = standard_cipher.decrypt(data)
    try:
        return unpad(decrypted, 8)
    except ValueError:                  # đệm PKCS#7 sai
        return None


def des_text(data, key_bytes, decrypt, use_standard):
    #Mã hóa / giải mã dữ liệu dài (văn bản hoặc tệp).
    #data: các byte cần xử lý. Khi giải mã, data là chuỗi hex bản mã.
    #use_standard: False = thuật toán nhóm, True = thư viện chuẩn.
    #Trả về (result, error); result có "output", "blocks", "milliseconds".
    if len(data) == 0:
        return None, "Chưa có dữ liệu: hãy gõ văn bản hoặc chọn tệp .txt."

    # Giải mã: đổi chuỗi hex thành các byte
    if decrypt == 1:
        hex_text = data.decode("utf-8", errors="ignore")
        hex_text = "".join(hex_text.split())            # bỏ mọi khoảng trắng và xuống dòng
        if len(hex_text) % 16 != 0 or not is_hex(hex_text):
            return None, "Bản mã phải là chuỗi hex (0-9, A-F), độ dài là bội của 16."
        data = bytes.fromhex(hex_text)

    start = time.perf_counter()
    if use_standard:
        output = standard_des(data, key_bytes, decrypt)
    else:
        output = group_des(data, key_bytes, decrypt)
    milliseconds = milliseconds_since(start)

    if output is None:
        return None, "Giải mã thất bại: sai khóa hoặc bản mã không hợp lệ."

    result = {"milliseconds": milliseconds}
    if decrypt == 0:
        result["output"] = output.hex().upper()                         # bản mã viết dạng hex
        result["blocks"] = len(output) // 8
    else:
        result["output"] = output.decode("utf-8", errors="replace")     # bản rõ là chữ
        result["blocks"] = len(data) // 8
    return result, None


# 5. Kiểm thử 1 khối bằng thư viện chuẩn 

def standard_one_block(plaintext_text, key_text):
    #    """Mã hóa đúng 1 khối 64 bít bằng thư viện chuẩn (không đệm). Trả về (bản mã hex, error)."""

    plaintext_hex = remove_spaces(plaintext_text)
    key_hex = remove_spaces(key_text)
    if len(plaintext_hex) != 16 or len(key_hex) != 16 or not is_hex(plaintext_hex + key_hex):
        return None, "Bản rõ và khóa cần đúng 16 ký tự hex (0-9, A-F)."

    standard_cipher = StandardDES.new(bytes.fromhex(key_hex), StandardDES.MODE_ECB)
    ciphertext = standard_cipher.encrypt(bytes.fromhex(plaintext_hex))
    return ciphertext.hex().upper(), None


def group_one_block(block_text, key_text, decrypt):
    #Mã hóa (decrypt = 0) / giải mã (decrypt = 1) đúng 1 khối 64 bít bằng hàm des_run của nhóm (C).
    #Không đệm, dùng để đối chiếu. Trả về (khối kết quả dạng hex, error).
    
    block_hex = remove_spaces(block_text)
    key_hex = remove_spaces(key_text)
    if len(block_hex) != 16 or len(key_hex) != 16 or not is_hex(block_hex + key_hex):
        return None, "Khối vào và khóa cần đúng 16 ký tự hex (0-9, A-F)."

    block = int(block_hex, 16)          # đổi chuỗi hex thành số
    key = int(key_hex, 16)
    output = cipher.des_run(block, key, decrypt, None)
    return number_to_hex(output, 16), None


# 6. Vét cạn DES rút gọn

def key_with_unknown_bits(key, unknown_bits):
    """Viết khóa 64 bit dạng nhị phân theo từng byte, thay N bit hiệu dụng cuối bằng '?'.

    Mỗi byte có 8 bit: 7 bit đầu là bit hiệu dụng, bit cuối là bit chẵn lẻ (PC-1 bỏ đi).
    Các bit chưa biết được lấy từ phải sang trái, bỏ qua bit chẵn lẻ.
    """
    bits = list(bin(key)[2:].zfill(64))                 # 64 ký tự '0'/'1', bits[0] là bit trái nhất

    position = 63                                       # bắt đầu từ bit phải nhất
    remaining = unknown_bits
    while remaining > 0:
        if position % 8 != 7:                           # bỏ qua bit chẵn lẻ (bit cuối mỗi byte)
            bits[position] = "?"
            remaining = remaining - 1
        position = position - 1

    text = ""
    for i in range(0, 64, 8):                           # cách mỗi 8 bit một khoảng trắng
        text += "".join(bits[i:i + 8]) + " "
    return text.strip()


def des_bruteforce(plaintext_text, key_text, unknown_bits):
    """Kẻ tấn công biết P và C = DES(P, K), chỉ chưa biết N bit hiệu dụng cuối của khóa.

    Hàm C des_bruteforce thử cả 2^N khả năng. Trả về (result, error).
    """
    plaintext_hex = remove_spaces(plaintext_text)
    key_hex = remove_spaces(key_text)
    if len(plaintext_hex) != 16 or len(key_hex) != 16 or not is_hex(plaintext_hex + key_hex):
        return None, "Bản rõ và khóa cần đúng 16 ký tự hex (0-9, A-F)."
    if unknown_bits < 8 or unknown_bits > 20:
        return None, "Số bit chưa biết N phải từ 8 đến 20."

    plaintext = int(plaintext_hex, 16)                  # đổi chuỗi hex thành số
    key = int(key_hex, 16)
    ciphertext = cipher.des_run(plaintext, key, 0, None)

    # Hai biến 64 bit để hàm C ghi kết quả vào (C nhận con trỏ tới chúng)
    found_key = ctypes.c_uint64(0)
    found_index = ctypes.c_uint64(0)

    start = time.perf_counter()
    found_count = cipher.des_bruteforce(plaintext, ciphertext, key, unknown_bits,
                                        ctypes.byref(found_key), ctypes.byref(found_index))
    seconds = (time.perf_counter() - start)

    tried = 2 ** unknown_bits                           # số khóa đã thử
    speed = tried / seconds                             # số khóa mỗi giây
    seconds_per_year = 365 * 24 * 3600
    full_years = (2 ** 56) / speed / seconds_per_year   # thời gian thử hết 2^56 khóa

    result = {
        "plaintext": plaintext_hex.upper(),
        "ciphertext": number_to_hex(ciphertext, 16),
        "known_key": key_with_unknown_bits(key, unknown_bits),
        "unknown_bits": unknown_bits,
        "tried": tried,
        "found_count": found_count,
        "found_key": number_to_hex(found_key.value, 16),
        "found_index": found_index.value,
        "seconds": round(seconds, 3),
        "speed": int(speed),
        "full_years": int(full_years),
        "average_years": int(full_years / 2),
    }
    return result, None