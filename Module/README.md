# 目錄說明
- 存放各類 function
## 檔案用途
- `utils.h`, `utils.c` 預先定義好了可能會用到的 struct, enum 及相關 function。
- `readwrite.h`, `readwrite.c` 為讀寫組檔案。
- `steganography.h`, `steganography.c` 為隱寫組檔案。
- `test.c` 允許各組用來測試，自行修改後請勿上傳。

## Makefile
- `make` / `make test.exe` 生成 `test.c` 的執行檔 (`test.exe`)，用於測試。
- `make clean` 刪除 `make` 生成的檔案。
