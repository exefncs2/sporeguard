#!/usr/bin/env python3
"""SporeGuard：結合 SporeFlow (:9090) 與 SporeVault (:8081) 的極輕量本機資安異常雷達。

設計定位：只監控、只報警、不介入系統攔截。
- `--learn`：擷取本機近期正常系統日誌樣態，寫入 `security-baseline` 叢集作為比對基線。
- `--scan` ：巡檢近期系統錯誤與對外監聽埠，透過 SporeFlow 比對基線相似度，
             發現陌生異常或高危事件時同步寫入 `security-alert`（網頁介面可見）並觸發桌面通知。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

SPOREVAULT_BASE_URL = "http://127.0.0.1:8081"
BASELINE_CLUSTER = "security-baseline"
ALERT_CLUSTER = "security-alert"
HTTP_TIMEOUT_SECONDS = 5.0
SIMILARITY_ANOMALY_THRESHOLD = 0.55
ALERT_COOLDOWN_SECONDS = 7200  # 同指紋事件 2 小時內不重複跳通知，避免轟炸桌面與資料庫
MAX_BASELINE_SAMPLES = 40
MAX_ALERTS_PER_SCAN = 5  # 單次巡檢最多寫入筆數，防止系統洗版把 vault.svdb 灌爆
DEFAULT_INTERVAL_MINUTES = 60
STATE_FILE = Path.home() / ".local" / "state" / "spore-guard" / "state.json"
SYSTEMD_USER_DIR = Path.home() / ".config" / "systemd" / "user"

# Bazzite / KDE 桌面已知的正常區網服務埠：5355 (systemd-resolved LLMNR)、1716 (KDE Connect)
ALLOWED_EXPOSED_PORTS: frozenset[str] = frozenset({"5355", "1716"})

# 這些事件即使與過往錯誤相似，仍屬高風險資安訊號，必須強制觸發警報
HIGH_RISK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("認證失敗", re.compile(r"authentication failure|failed password|invalid user", re.IGNORECASE)),
    ("SELinux 拒絕", re.compile(r"avc:\s+denied", re.IGNORECASE)),
    ("記憶體異常崩潰", re.compile(r"segfault at|out of memory: killed process", re.IGNORECASE)),
)

# 去除時間戳、PID 與十六進位位址，避免同一種正常訊息只因數字變動就被誤判為陌生事件
NORMALIZE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^\d+月\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"), ""),
    (re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"), ""),
    (re.compile(r"\[\d+\]"), "[PID]"),
    (re.compile(r"0x[0-9a-fA-F]+"), "0xADDR"),
    (re.compile(r"\b\d{4,}\b"), "NUM"),
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
LOGGER = logging.getLogger("spore-guard")


@dataclass(frozen=True)
class SecurityEvent:
    """正規化後的單筆待檢安全事件。"""

    category: str
    signature: str
    raw_line: str
    forced_reason: str | None = None


def normalize_log_line(raw_line: str) -> str:
    """移除動態時間與 PID，保留穩定的事件骨架供向量比對與去重。"""
    cleaned = raw_line.strip()
    for pattern, replacement in NORMALIZE_RULES:
        cleaned = pattern.sub(replacement, cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def compute_fingerprint(text: str) -> str:
    """計算事件穩定指紋，用於冷卻去重。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def load_state() -> dict[str, float]:
    """讀取上次各指紋的報警時間戳；若檔案損壞則安全重置。"""
    if not STATE_FILE.exists():
        return {}
    try:
        with STATE_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
        return {str(k): float(v) for k, v in data.items()}
    except (OSError, ValueError, TypeError) as exc:
        LOGGER.warning("讀取冷卻狀態失敗，改用空狀態：%s", exc)
        return {}


def save_state(state: dict[str, float]) -> None:
    """原子寫入冷卻狀態，順便清理超過冷卻期的舊鍵避免檔案膨脹。"""
    now = time.time()
    pruned = {k: v for k, v in state.items() if now - v < ALERT_COOLDOWN_SECONDS * 2}
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = STATE_FILE.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        json.dump(pruned, fh, ensure_ascii=False, indent=2)
    tmp_path.replace(STATE_FILE)


def run_cmd(args: list[str]) -> str:
    """執行唯讀系統查詢指令；失敗時回傳空字串並記錄警告。"""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        LOGGER.warning("執行指令失敗 %s：%s", args, exc)
        return ""


def api_add_record(cluster: str, text: str) -> dict[str, object] | None:
    """透過 SporeVault HTTP API 寫入紀錄並同步至 SporeFlow 唯讀池。"""
    query = urllib.parse.urlencode({"cluster": cluster})
    url = f"{SPOREVAULT_BASE_URL}/api/add?{query}"
    req = urllib.request.Request(
        url,
        data=text.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        LOGGER.error("寫入 SporeVault 失敗：%s", exc)
        return None


def api_search_baseline(signature: str) -> tuple[float, float]:
    """查詢事件與正常基線的最高餘弦相似度，回傳 (max_score, elapsed_ms)。"""
    query = urllib.parse.urlencode({"q": signature, "cluster": BASELINE_CLUSTER})
    url = f"{SPOREVAULT_BASE_URL}/api/search?{query}"
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        LOGGER.warning("查詢 SporeVault 基線失敗：%s", exc)
        return 0.0, 0.0

    hits = payload.get("hits", [])
    elapsed_ms = float(payload.get("elapsed_ms", 0.0))
    if not hits:
        return 0.0, elapsed_ms
    top_score = max(float(item.get("score", 0.0)) for item in hits)
    return top_score, elapsed_ms


def send_desktop_alert(title: str, body: str, urgency: str = "critical") -> None:
    """發送 KDE Plasma 桌面通知；在無 GUI 環境下自動降級為 log 輸出。"""
    try:
        subprocess.run(
            [
                "/usr/bin/notify-send",
                "-u",
                urgency,
                "-a",
                "SporeGuard",
                "-i",
                "security-high",
                title,
                body,
            ],
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        LOGGER.warning("無法發送桌面通知：%s", exc)


def collect_exposed_ports() -> list[SecurityEvent]:
    """檢查綁定於非迴路位址（0.0.0.0 / [::] / *）的監聽埠。"""
    output = run_cmd(["/usr/bin/ss", "-tulnH"])
    events: list[SecurityEvent] = []
    seen: set[str] = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, state, local_addr = parts[0], parts[1], parts[4]
        if state != "LISTEN":
            continue
        # 僅放行本機迴路位址（127.x / ::1）與已知正常桌面區網埠，其餘對外暴露埠皆納入檢查
        if local_addr.startswith(("127.", "[::1]:", "::1:")):
            continue
        port = local_addr.rsplit(":", 1)[-1]
        if port in ALLOWED_EXPOSED_PORTS:
            continue
        sig = f"exposed-port {proto} {local_addr}"
        if sig in seen:
            continue
        seen.add(sig)
        events.append(
            SecurityEvent(
                category="對外監聽埠",
                signature=sig,
                raw_line=f"{proto} LISTEN {local_addr}",
                forced_reason="偵測到非本機迴路（對外）監聽埠",
            )
        )
    return events


def collect_journal_events(since: str, priority: str, limit: int) -> list[SecurityEvent]:
    """擷取指定時間窗與優先級的 journalctl 紀錄並去重。"""
    output = run_cmd(
        [
            "/usr/bin/journalctl",
            "--since",
            since,
            "-p",
            priority,
            "--no-pager",
            "-n",
            str(limit),
        ]
    )
    events: list[SecurityEvent] = []
    seen: set[str] = set()
    for line in output.splitlines():
        if not line.strip() or line.startswith("--"):
            continue
        sig = normalize_log_line(line)
        if len(sig) < 12 or sig in seen:
            continue
        seen.add(sig)
        forced_reason = next(
            (label for label, pat in HIGH_RISK_PATTERNS if pat.search(line)),
            None,
        )
        events.append(
            SecurityEvent(
                category="系統日誌",
                signature=sig,
                raw_line=line.strip(),
                forced_reason=forced_reason,
            )
        )
    return events


def cmd_learn() -> int:
    """從過去 24 小時日誌抽取去重樣態，建立 SporeFlow 正常基線。"""
    samples = collect_journal_events("24 hours ago", "notice..err", 250)
    if not samples:
        LOGGER.warning("找不到可用於建立基線的系統日誌。")
        return 1

    added = 0
    for event in samples[:MAX_BASELINE_SAMPLES]:
        # 排除明確高危事件，避免將異常行為學進正常基線
        if event.forced_reason is not None:
            continue
        record_text = f"#baseline {event.signature}"
        if api_add_record(BASELINE_CLUSTER, record_text) is not None:
            added += 1

    LOGGER.info("基線建立完成：共寫入 %d 筆樣態至 cluster=%s", added, BASELINE_CLUSTER)
    return 0


def cmd_scan(window_minutes: int) -> int:
    """巡檢近期系統錯誤與對外監聽埠，透過 SporeFlow 比對基線並觸發報警。"""
    state = load_state()
    now = time.time()
    candidates = collect_journal_events(f"{window_minutes} minutes ago", "err..emerg", 80)
    candidates.extend(collect_exposed_ports())

    if not candidates:
        LOGGER.info("巡檢完成：過去 %d 分鐘無異常日誌或對外監聽埠。", window_minutes)
        return 0

    alert_count = 0
    for event in candidates:
        if alert_count >= MAX_ALERTS_PER_SCAN:
            LOGGER.warning("已達單次警報上限（%d 筆），其餘事件略過以保護資料庫。", MAX_ALERTS_PER_SCAN)
            break
        fp = compute_fingerprint(event.signature)
        if now - state.get(fp, 0.0) < ALERT_COOLDOWN_SECONDS:
            continue

        score, elapsed_ms = api_search_baseline(event.signature)
        is_anomaly = event.forced_reason is not None or score < SIMILARITY_ANOMALY_THRESHOLD
        if not is_anomaly:
            continue

        reason = event.forced_reason or f"與正常基線相似度過低 ({score:.2f} < {SIMILARITY_ANOMALY_THRESHOLD:.2f})"
        alert_text = (
            f"#security-alert [{event.category}] {reason} | "
            f"score={score:.2f} ({elapsed_ms:.2f}ms) | {event.signature[:220]}"
        )
        api_add_record(ALERT_CLUSTER, alert_text)
        send_desktop_alert(
            f"SporeGuard 異常警報（{event.category}）",
            f"{reason}\n{event.signature[:140]}\n詳情見 {SPOREVAULT_BASE_URL}",
        )
        state[fp] = now
        alert_count += 1
        LOGGER.warning("觸發警報：%s", alert_text)

    save_state(state)
    LOGGER.info("巡檢結束：檢查 %d 筆候選事件，觸發 %d 筆新警報。", len(candidates), alert_count)
    return 0


def cmd_set_interval(minutes: int) -> int:
    """動態調整 systemd user timer 巡檢間隔與對應日誌時間窗。"""
    if minutes < 1 or minutes > 1440:
        LOGGER.error("巡檢間隔需介於 1 ~ 1440 分鐘（24 小時）之間。")
        return 1

    window_minutes = minutes + 2  # 多抓 2 分鐘緩衝，避免排程抖動漏掉邊界日誌
    timer_path = SYSTEMD_USER_DIR / "spore-guard.timer"
    service_path = SYSTEMD_USER_DIR / "spore-guard.service"

    timer_content = (
        "[Unit]\n"
        f"Description=Run SporeGuard anomaly scan every {minutes} minutes\n\n"
        "[Timer]\n"
        "OnBootSec=2min\n"
        f"OnUnitActiveSec={minutes}min\n"
        "Persistent=false\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    service_content = (
        "[Unit]\n"
        "Description=SporeGuard Local Security Anomaly Radar (One-shot Scan)\n"
        "After=sporeflow.service sporevault.service\n"
        "Wants=sporeflow.service sporevault.service\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart=/usr/bin/python3 %h/.local/bin/spore-guard.py --scan --window-minutes {window_minutes}\n"
        "Nice=10\n"
    )

    SYSTEMD_USER_DIR.mkdir(parents=True, exist_ok=True)
    timer_path.write_text(timer_content, encoding="utf-8")
    service_path.write_text(service_content, encoding="utf-8")

    subprocess.run(["/usr/bin/systemctl", "--user", "daemon-reload"], check=True)
    subprocess.run(["/usr/bin/systemctl", "--user", "restart", "spore-guard.timer"], check=True)
    LOGGER.info("已更新巡檢間隔為每 %d 分鐘一次（日誌回溯窗 %d 分鐘）。", minutes, window_minutes)
    return 0


def cmd_test_alert() -> int:
    """發送一筆測試警報，端到端驗證 SporeVault 寫入與 KDE 桌面通知。"""
    test_text = "#security-alert #test [測試警報] SporeGuard 報警通道驗收測試"
    resp = api_add_record(ALERT_CLUSTER, test_text)
    if resp is None:
        return 1
    send_desktop_alert(
        "SporeGuard 測試警報",
        f"報警通道正常！紀錄已寫入 #{resp.get('id')}，可於 {SPOREVAULT_BASE_URL} 查看。",
        urgency="normal",
    )
    LOGGER.info("測試警報已送出（SporeVault ID #%s）。", resp.get("id"))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SporeGuard 本機資安異常雷達")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--learn", action="store_true", help="建立 24 小時正常基線至 SporeVault")
    group.add_argument("--scan", action="store_true", help="執行單次巡檢並觸發異常報警（預設）")
    group.add_argument("--test-alert", action="store_true", help="送出一筆測試警報驗證桌面通知與網頁介面")
    group.add_argument(
        "--set-interval",
        type=int,
        metavar="MINUTES",
        help="調整自動巡檢間隔（1~1440 分鐘，預設 60 分鐘）",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=DEFAULT_INTERVAL_MINUTES + 2,
        help="單次 --scan 回溯的日誌分鐘數（預設 62 分鐘）",
    )
    args = parser.parse_args()

    if args.learn:
        return cmd_learn()
    if args.test_alert:
        return cmd_test_alert()
    if args.set_interval is not None:
        return cmd_set_interval(args.set_interval)
    return cmd_scan(args.window_minutes)


if __name__ == "__main__":
    raise SystemExit(main())
