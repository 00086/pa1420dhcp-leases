# PA-1420 防火牆 DHCP 租約智能監控與分析系統 📡

專為 Palo Alto Networks PA-1420 次世代防火牆設計的自動化 DHCP 租約監控系統。具備排程自動 API 擷取、XML 拖曳匯入、日期歷史分區、自動排除完全重複資料、同日多重租約保留、自然 IP 數值排序，以及自適應無跳動視窗的現代化 Web UI。

近期升級新增：**硬體效能歷史圖表**、**ARP 固定 IP 聯防比對**、**即時資安威脅日誌分析**，以及**精確的記憶體與 SSD 分區狀態剖析**，進一步強化網管與資安維運的整體掌握度。

---

## 🌟 系統核心功能特性

### 1. 網路與租約管理
* **PA-1420 API 自動定時擷取**
  * 內建排程引擎（APScheduler），固定於每日 **01:00、05:00、09:00、13:00、17:00、21:00**（一日 6 次）自動連線 PA-1420 XML API。
  * 支援「立即從 PA-1420 抓取」按鈕，隨時手動即時同步最新租約。
* **高精度資料庫防重複與歷史保留機制**
  * **完全重複排除**：同日、同 IP、同 MAC、同租約時間，將被視為重複而略過。
  * **同日更新保留**：同一設備在同日若有**不同的租約配發時間**，會被判定為獨立租約，分開保留多筆紀錄。
* **多來源與彈性日期歸屬**
  * 支援點擊選取與拖曳上傳 XML 備份檔，上傳時可自由指定歸屬之「租約日期」。
* **真實 IP 數值順序排序**
  * 自訂 SQLite 排序規則（`COLLATE IP_CMP`），保證 `192.50.8.x` 恆排在 `192.50.10.x` 之前。

### 2. 進階網管與資安維運分析
* **ARP 與固定 IP 聯防比對 (`show arp all`)**
  * 即時比對當日 DHCP 紀錄，揪出「手動設定固定 IP 的未授權設備」或「IP/MAC 衝突」。
  * 內建 **多執行緒背景非同步 DNS 查詢 (PTR)**：不卡頓前端網頁，快速分類設備。
  * 內建 `ip_hostname_cache` 永久快取，成功解析之主機名稱下次開啟秒速載入。
* **系統硬體效能歷史監控 (Chart.js) 與精確剖析**
  * 背景每 1 分鐘自動採樣「MP CPU」、「DP CPU」、「記憶體」、「SSD 使用率」與「活躍連線數」，點擊標籤可彈出 **最近 3 小時動態歷史折線圖**。
  * **高階記憶體解析**：完美相容 PAN-OS 11，將「程序實質佔用 (Used)」與「可釋放之磁碟快取 (Buff/Cache)」明確拆分，避免誤判記憶體不足。
  * **SSD 分區透視**：點擊 SSD 標籤除了顯示趨勢圖，更會即時動態列出 `/opt/panlogs`、`/opt/pancfg` 等所有底層實體分區的詳細容量狀態。
* **即時資安威脅與阻擋事件排行 (Threat Logs)**
  * 透過 API 擷取最新威脅事件，自動與 DHCP 資料庫交叉關聯，直接帶出內部 IP 的設備主機名稱與 MAC。
  * 內建視覺化「威脅等級分佈甜甜圈圖」、「Top 5 來源 IP」、「Top 5 威脅特徵」排行榜。

### 3. 現代化使用者介面 (Port: 5006)
* 鎖定全螢幕外部捲軸（`100vh overflow-hidden`），僅內部表格捲動。
* 使用 `table-layout: fixed` 鎖定 6 大欄位寬度，切換日期或無資料時表頭絕不位移。
* **極致體驗的彈出視窗 (Modal)**：加大為 `modal-xl`，鎖定 Header 與 Footer 標題列，內容超出螢幕時僅在視窗內部平滑滾動，並搭配最佳化字體大小與緊湊行高。

---

## 📁 專案目錄架構

```text
dhcpxml/
├── app.py              # 後端服務、API、排程器與資料庫核心
├── pa1420key.txt       # 防火牆 IP、介面與 API Key 配置檔
├── requirements.txt    # Python 依賴套件清單 (含 flask, requests, apscheduler 等)
├── dhcp_records.db     # SQLite 資料庫 (啟動後自動建立多張關聯表與快取表)
└── templates/
    └── index.html      # 前端 Web UI (Bootstrap 5, Icons, Chart.js)
```

---

## ⚙️ 防火牆連線配置 (`pa1420key.txt`)

在專案根目錄下建立 `pa1420key.txt`，依序填入三行內容：

```text
192.168.1.1
ethernet1/1
LUFRPT14MW55QW...（您的 PA-1420 API Key）...==
```

* **第 1 行**：PA-1420 管理介面 IP。
* **第 2 行**：監控的 DHCP 網路介面（例如 `ethernet1/16`；若欲取得所有介面可填 `all`）。
* **第 3 行**：PA-1420 XML API Key。

---

## 🚀 虛擬環境建置與執行

### 1. 建立並啟動虛擬環境

* **Windows (CMD / PowerShell)**：
```cmd
python -m venv venv
venv\Scripts\activate
```

* **Linux / macOS**：
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. 安裝依賴套件 (`requirements.txt`)

確認終端機前方有出現 `(venv)` 後，執行安裝指令：
```bash
python -m pip install --upgrade pip
pip install flask requests urllib3 apscheduler pyinstaller
```

### 3. 開發模式啟動

```bash
python app.py
```
啟動後打開瀏覽器造訪：`http://localhost:5006`

---

## 📦 打包成單一執行檔 (.exe) 終極指南

為了讓單一執行檔順利載入 Flask 樣板，且**避免遺漏動態載入的排程器套件**，請務必按照以下步驟操作。

### 步驟 1：確保程式碼支援打包與動態載入
確認 `app.py` 頂端包含以下宣告，除了讓 Flask 找得到解壓縮路徑外，也能**防呆強制匯入**排程觸發器，避免打包工具誤刪：
```python
import sys
import os
from flask import Flask
from apscheduler.schedulers.background import BackgroundScheduler
import apscheduler.triggers.cron      # 強制匯入供打包工具識別
import apscheduler.triggers.interval  # 強制匯入供打包工具識別

if getattr(sys, 'frozen', False):
    base_dir = sys._MEIPASS
    template_folder = os.path.join(base_dir, 'templates')
    app = Flask(__name__, template_folder=template_folder)
else:
    app = Flask(__name__)
```

### 步驟 2：使用指定虛擬環境的打包指令 (防呆關鍵)
**請確保您處於 `(venv)` 環境中**，並且**千萬不要直接輸入 `pyinstaller`**（以免呼叫到系統全域的編譯器導致漏抓套件）。

請在專案根目錄執行以下指令（透過 `python -m PyInstaller` 強制使用虛擬環境，並加入隱藏依賴參數）：

* **Windows 打包指令**：
```cmd
python -m PyInstaller --noconfirm --clean --onefile --windowed --name "PA1420_DHCP_Monitor" --add-data "templates;templates" --hidden-import apscheduler --collect-all apscheduler app.py
```
*(💡 註：若希望執行時保留背景日誌 Console 視窗，可將 `--windowed` 參數移除。)*

* **Linux / macOS 打包指令 (注意分隔符號為冒號 `:` )**：
```bash
python -m PyInstaller --noconfirm --clean --onefile --name "PA1420_DHCP_Monitor" --add-data "templates:templates" --hidden-import apscheduler --collect-all apscheduler app.py
```

### 步驟 3：部署與執行
打包成功後（Terminal 顯示 `Build complete!`）：
1. 進入 `dist/` 資料夾，取出 `PA1420_DHCP_Monitor.exe`。
2. 將該執行檔放置於目標機器的任意資料夾，並在**同目錄下建立好 `pa1420key.txt`**。
3. 雙擊執行 `PA1420_DHCP_Monitor.exe`，系統即會在背景無感啟動，並自動產生 `dhcp_records.db` 資料庫。
4. 使用瀏覽器連線至 `http://localhost:5006` 即可開始監控。

---

## 📄 授權條款

本專案採用 **[MIT License](https://opensource.org/licenses/MIT)** 授權。可自由修改、整合與商業使用。