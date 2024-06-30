# Steganography
- Compiler Term Project
## 檔案用途
- `main.l` 為 flex 檔
- `main.y` 為 bison 檔
- `grammer.h`, `grammer.c` 為文法組檔案。
- `Module/` 存放各類 function。
- `test.c` 允許各組用來測試，自行修改後請勿上傳。

## Makefile
- `make`
- `make test.exe` 生成 `test.c` 的執行檔 (`test.exe`)，用於測試。
- `make clean` 刪除 `make` 生成的檔案。
