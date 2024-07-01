# Steganography
- Compiler Term Project
## 檔案用途
- `main.l` 為 flex 檔
- `main.y` 為 bison 檔
- `grammer.h`, `grammer.c` 為文法組檔案。
- `Module/` 存放各類 function。

## Makefile
- `make`
- `make clean` 刪除 `make` 生成的檔案。

## GRAMMAR
### Steganography
- `INJECT message INTO in.pcap USEKEY key PROTO proto[start:size] OUT out.pcap;`
- `INJECT message INTO in.pcap USEKEY key PROTO proto[start:size];`
### Extract
- `SELECT FROM covert.pcap INTO extract USEKEY key PROTO proto[start:size];`
### Chi Square  Analysis
- `ANALYSIS_CS OF analysis.pcap PROTO proto[start:size];`
### Rescaled Range  Analysis
- `ANALYSIS_RS OF analysis.pcap PROTO proto[start:size];`

## ARGUMENT
- `in.pcap`
    -  The input PCAP file is used for hiding data.
- `out.pcap`  
    - The output PCAP file contains hidden data. The default filename is covert.pcap.
- `covert.pcap`
    - The input PCAP file may contain hidden data.
- `analysis.pcap`
    - The input PCAP file is used for analysis.
- `message`
    - The file has the data you want to hide.
- `key`
    - The file has the key used to do hidden data.
- `extract`
    - The file has the extracted data from covert.pcap.
- `proto`
    - The protocol name, including IP, UDP, TCP.
- `start`
    - The starting byte of the proto header.
- `size`
    - The number of bytes of the proto header.

## EXAMPLE
- Extract:
    - `SELECT FROM covert.pcap INTO extract USEKEY key PROTO IP[7:3];`
- Inject:
    - `INJECT message INTO in.pcap USEKEY key PROTO UDP[7:3] OUT out.pcap;`
- Chi Square Analysis:
    - `ANALYSIS_CS OF analysis.pcap PROTO IP[7:1];`
- RS Analysis:
    - `ANALYSIS_RS OF analysis.pcap PROTO IP[7:3];`
