# 🛡️ Wireshark Packet Analyzer

A Python-based packet capture analyzer for `.pcapng` files that detects unencrypted DNS & HTTP traffic, ARP spoofing attempts, and generates a detailed security report.

---

## ✨ Features

- 📦 **Protocol Summary:** Counts and lists all detected protocols.
- 🌐 **DNS Detection:** Flags unencrypted DNS queries.
- 🔓 **HTTP Traffic Scan:** Detects unencrypted HTTP request methods and hosts.
- ⚠️ **ARP Spoofing Alerts:** Identifies conflicting IP-to-MAC mappings.
- 📝 **Report Generator:** Outputs `report.txt` with security risks and recommendations.

---

## 📸 Terminal Output

> Example of running the analyzer from the terminal:

![Terminal Screenshot](https://raw.githubusercontent.com/Mithul-Kumaran/Wireshark-packet-analyzer/main/cmd.png)

---

## 📄 Sample Report

> This is an excerpt of the generated `report.txt`:

![Security Report Screenshot](https://raw.githubusercontent.com/Mithul-Kumaran/Wireshark-packet-analyzer/main/report.png)

---

## 🚀 How to Use

```bash
python3 wireshark_analyser.py yourfile.pcapng
