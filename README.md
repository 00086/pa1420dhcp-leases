# PA-1420 防火牆 DHCP 租約智能監控與分析系統 📡

專為 Palo Alto Networks PA-1420 次世代防火牆設計的自動化 DHCP 租約監控系統。具備排程自動 API 擷取、XML 拖曳匯入、日期歷史分區、自動排除完全重複資料、同日多重租約保留、自然 IP 數值排序，以及自適應無跳動視窗的現代化 Web UI。

近期升級新增：**硬體效能歷史圖表**、**ARP 固定 IP 聯防比對**與**即時資安威脅日誌分析**，進一步強化網管與資安維運的整體掌握度。

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
* 內建 **多執行緒背景非同步 DNS 查詢 (PTR)**：不會造成前端網頁卡頓。
* 自動識別歷史 DHCP 紀錄及 VMware 等常見廠商設備（OUI）。
* 內建 `ip_hostname_cache` 永久快取，成功解析之主機名稱下次開啟秒速載入。


* **系統硬體效能與連線數歷史監控 (Chart.js)**
* 背景每 1 分鐘自動採樣「MP CPU (管理平面)」、「DP CPU (資料平面)」、「系統記憶體 (RAM)」與「活躍連線數」。
* 前端儀表板即時呈現最新數據，點擊標籤即可彈出 **最近 3 小時動態歷史折線圖**。


* **即時資安威脅與阻擋事件排行 (Threat Logs)**
* 透過 API 即時擷取最新阻擋與威脅事件。
* 自動與本地 DHCP 資料庫進行身分交叉關聯，內部 IP 直接帶出設備主機名稱與 MAC。
* 內建視覺化「威脅等級分佈甜甜圈圖」，以及「Top 5 來源 IP」、「Top 5 威脅特徵」排行榜。



### 3. 使用者介面 (Port: 5006)

* 鎖定全螢幕外部捲軸（`100vh overflow-hidden`），僅內部表格捲動。
* 使用 `table-layout: fixed` 鎖定 6 大欄位寬度，切換日期或無資料時表頭絕不位移。
* 支援非同步輪詢 (Polling)：背景排程或 DNS 解析完成時，前端網頁與儀表板資訊將自動更新。

---

## 📁 專案目錄架構

```text
dhcpxml/
├── app.py              # 後端服務、API、排程器與資料庫核心
├── pa1420key.txt       # 防火牆 IP、介面與 API Key 配置檔
├── requirements.txt    # Python 依賴套件清單 (新增 Chart.js 需求)
├── dhcp_records.db     # SQLite 資料庫 (啟動後自動建立多張資料表)
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

```text
Flask>=3.0.0
Werkzeug>=3.0.0
requests>=2.31.0
APScheduler>=3.10.0
pyinstaller>=6.0.0

```

執行安裝指令：

```bash
pip install -r requirements.txt

```

### 3. 開發模式啟動

```bash
python app.py

```

啟動後打開瀏覽器造訪：`http://localhost:5006`

---

## 📦 打包成單一執行檔 (.exe) 指南

為了讓單一執行檔解壓縮後能順利載入 Flask 的 `templates` 樣板，需調整 `app.py` 中的樣板路徑定義，並使用 PyInstaller 進行資源打包。

### 步驟 1：確保 `app.py` 支援 PyInstaller 資源路徑

確認 `app.py` 開頭的 Flask 初始化代碼包含執行檔路徑判斷（`sys._MEIPASS`）：

```python
import sys
import os
from flask import Flask

if getattr(sys, 'frozen', False):
    # PyInstaller 解壓縮後的暫存目錄
    base_dir = sys._MEIPASS
    template_folder = os.path.join(base_dir, 'templates')
    app = Flask(__name__, template_folder=template_folder)
else:
    app = Flask(__name__)

```

### 步驟 2：執行 PyInstaller 打包指令

在虛擬環境啟用狀態下，於專案根目錄執行以下指令：

* **Windows 打包指令**：

```cmd
pyinstaller --noconfirm --clean --onefile --windowed --name "PA1420_DHCP_Monitor" --add-data "templates;templates" app.py

```

*(若希望在背景執行時仍能看到後端日誌 Console，可拿掉 `--windowed` 參數)*

* **Linux / macOS 打包指令**：

```bash
pyinstaller --noconfirm --clean --onefile --name "PA1420_DHCP_Monitor" --add-data "templates:templates" app.py

```

### 步驟 3：部署與執行

打包完成後，可執行檔會生成於 `dist/` 資料夾內：

1. 將 `dist/PA1420_DHCP_Monitor.exe` 複製到欲部署的目錄。
2. 在該執行檔**同級目錄**下放置已設定好的 `pa1420key.txt`。
3. 雙擊執行 `PA1420_DHCP_Monitor.exe`，系統即會在背景啟動並在該目錄自動建立 `dhcp_records.db`。
4. 使用瀏覽器連線至 `http://localhost:5006` 即可開始使用。

---

## 📄 授權條款

本專案採用 **[MIT License](https://opensource.org/licenses/MIT)** 授權。可自由修改、整合與商業使用。