# Hệ mã khối TinyDES và DES

Bài tập nhóm môn **An toàn và bảo mật thông tin**.

## Cấu trúc thư mục

```
core/                   Thuật toán viết bằng C
  cipher.h              Các bảng hoán vị, S-box, struct lưu các bước trung gian
  bits.h                 Các hàm thao tác bit
  tinydes.c             TinyDES: sinh khóa con, hàm F, 3 vòng Feistel
  des.c                 DES: sinh 16 khóa con, hàm F, 16 vòng, mã hóa tệp, vét cạn
  build.bat             Biên dịch thành cipher.dll
gui/                    Giao diện Python
  cipher_library.py     Nạp cipher.dll, kiểm tra dữ liệu nhập, gọi hàm C
  app.py                Cửa sổ chương trình với 4 tab

```

## Yêu cầu

- Windows, Python 3 (64-bit)
- Thư viện PyCryptodome (chỉ dùng cho tab Kiểm thử)
- Trình biên dịch C 64-bit: MinGW-w64 (`gcc`) hoặc Visual Studio (`cl`).

## Cách chạy giao diện

1. Cài PyCryptodome:
   ```
   python -m pip install pycryptodome
   ```
2. Build thư viện C: 
   nháy đúp `core\build.bat` .
3. Chạy giao diện:
   ```
   python app.py
   ```

Thư mục `gui` phải nằm cạnh thư mục `core`, vì `cipher_library.py` tìm `cipher.dll` ở `../core`.

## Chức năng

| Tab | Chức năng |
|---|---|
| TinyDES | Mã hóa / giải mã 1 khối 8 bit, hiển thị khóa con và từng bước Expand, XOR, S-box, P-box của 3 vòng |
| DES | Mã hóa / giải mã văn bản hoặc tệp `.txt` bằng thuật toán của nhóm. Khóa nhập dạng 16 ký tự hex hoặc 8 ký tự chữ |
| Kiểm thử | Mã hóa bằng thư viện chuẩn PyCryptodome: 1 khối 64 bit và văn bản / tệp (so với tab DES) |
| Tấn công vét cạn | Thử cả 256 khóa TinyDES; vét cạn DES rút gọn khi chưa biết N bit khóa (N từ 8 đến 20) và ước tính thời gian phá DES đầy đủ |
