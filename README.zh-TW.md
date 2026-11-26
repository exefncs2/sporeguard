# 🛡️ SporeGuard（繁體中文說明）

[English](./README.md) | [繁體中文](./README.zh-TW.md) | [AI / Agent 索引 (`llms.txt`)](./llms.txt) | [🍄 SporeFlow](https://github.com/exefncs2/sporeflow) | [🍄 SporeVault](https://github.com/exefncs2/sporevault)

---

## 一、定位與設計理念（為什麼老三不用 Rust，改用純 Python？）

**SporeGuard** 是蘑菇三兄弟（`SporeFlow` × `SporeVault` × `SporeGuard`）的**資安異常日誌雷達**：只監控、只報警、絕不介入攔截系統。

前面兩套（`SporeFlow`、`SporeVault`）都是 100% 純 Rust，但 **SporeGuard 刻意選用「零第三方套件的純 Python 標準庫單檔」**，這是刻意做的工程分層取捨：

1. **熱路徑（Data Plane）與維運層（Control Plane）分工**：
   - 高頻向量比對、大頁記憶體鎖定、`:9090` 裸二進位通道交給 **Rust（SporeFlow / SporeVault）** 扛。
   - SporeGuard 每小時只醒來跑一次（`Type=oneshot`），99% 工作是呼叫 Linux 原生指令（`journalctl`、`ss`、`notify-send`、`systemctl`）並組裝規則，寫成 Rust 不會有體感加速，反而多一層編譯成本。
2. **資安維運腳本重視「開箱即審、改規則免重編」**：
   - 單一 ~400 行純文字檔，打開就能一眼審完所有正則規則（`HIGH_RISK_PATTERNS`）、白名單埠（`ALLOWED_EXPOSED_PORTS`）與冷卻秒數，改完立刻生效。
3. **零供應鏈依賴（0 `pip` 套件）**：
   - 完全只吃 Linux 系統內建的 `/usr/bin/python3` 標準庫，免裝虛擬環境、免怕第三方 Python 套件爆 CVE 漏洞。

---

## 二、核心功能與保護機制

- **`--learn`（建立 24 小時正常基線）**：擷取近期系統日誌，先洗掉時間戳、`[PID]`、`0xADDR` 與長數字，排除高危關鍵字後寫入 SporeVault 的 `security-baseline` 叢集。
- **`--scan`（異常巡檢與對外埠守門）**：
  - 掃描近期 `err..emerg` 系統日誌，送進 SporeVault / SporeFlow 比對基線相似度（低於 `0.55` 視為陌生異常）。
  - 強制觸發高危事件：認證失敗、SELinux AVC 拒絕、記憶體 Segfault / OOM。
  - 檢查 `ss -tulnH`，除了 `127.x`、`::1` 與已知桌面白名單埠（`5355`、`1716`），任何非本機迴路的對外監聽埠直接報警。
- **防洗版保護**：同事件指紋 2 小時冷卻（`~/.local/state/spore-guard/state.json`）＋ 單次巡檢最多寫入 5 筆。
- **異常紀錄與通知**：寫入 `security-alert` 叢集（插 `#security-alert` 旗幟，可於 `http://127.0.0.1:8081` 檢視）並發送 KDE 桌面通知。

---

## 三、安裝與使用方式

```bash
# 1. 安裝至 ~/.local/bin
install -m 755 spore-guard.py ~/.local/bin/spore-guard.py

# 2. 建立 24 小時正常日誌基線（需先啟動本機 SporeFlow 與 SporeVault）
spore-guard.py --learn

# 3. 手動巡檢或測試桌面通知
spore-guard.py --scan
spore-guard.py --test-alert

# 4. 設定每 60 分鐘自動巡檢（systemd --user timer）
spore-guard.py --set-interval 60
```

授權條款：MIT（`SPDX-License-Identifier: MIT`）。
