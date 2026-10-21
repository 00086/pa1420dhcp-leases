import sys
import os
import sqlite3
import math
import ipaddress
import datetime
import xml.etree.ElementTree as ET
import requests
import urllib3
import time
from flask import Flask, render_template, request, jsonify
from apscheduler.schedulers.background import BackgroundScheduler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if getattr(sys, 'frozen', False):
    # PyInstaller 解壓縮後的暫存目錄
    base_dir = sys._MEIPASS
    template_folder = os.path.join(base_dir, 'templates')
    app = Flask(__name__, template_folder=template_folder)
else:
    app = Flask(__name__)

# -------------------------------------------------------------
# PA-1420 設定與讀取
# -------------------------------------------------------------
PA_CONFIG_FILE = "pa1420key.txt"

def get_pa_config():
    if not os.path.exists(PA_CONFIG_FILE):
        raise FileNotFoundError(f"找不到設定檔案：{PA_CONFIG_FILE}")

    with open(PA_CONFIG_FILE, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]

    if len(lines) < 3:
        raise ValueError(
            f"{PA_CONFIG_FILE} 格式錯誤！必須包含三行：\n"
            "第 1 行：防火牆 IP\n"
            "第 2 行：介面名稱 (例如 ethernet1/16 或 all)\n"
            "第 3 行：API Key"
        )

    fw_ip = lines[0].replace("http://", "").replace("https://", "").rstrip("/")
    interface = lines[1]
    api_key = lines[2]

    if interface.lower() == 'all':
        cmd = "<show><dhcp><server><lease><all/></lease></server></dhcp></show>"
    else:
        cmd = f"<show><dhcp><server><lease><interface>{interface}</interface></lease></server></dhcp></show>"

    return fw_ip, interface, api_key, cmd

# -------------------------------------------------------------
# 資料庫與自然 IP 排序
# -------------------------------------------------------------
def ip_collation(ip1, ip2):
    try:
        val1 = int(ipaddress.IPv4Address(ip1))
        val2 = int(ipaddress.IPv4Address(ip2))
        return (val1 > val2) - (val1 < val2)
    except ValueError:
        return (ip1 > ip2) - (ip1 < ip2)

def init_db(db_name="dhcp_records.db"):
    conn = sqlite3.connect(db_name)
    conn.create_collation("IP_CMP", ip_collation)
    cursor = conn.cursor()
    
    # 建立主表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dhcp_leases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_date TEXT NOT NULL,
            ip TEXT NOT NULL,
            mac TEXT NOT NULL,
            hostname TEXT,
            state TEXT,
            duration INTEGER,
            leasetime TEXT
        )
    ''')
    
    # 明確建立四欄位複合唯一索引：日期、IP、MAC、租約時間皆相同才視為重複
    cursor.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS idx_dhcp_lease_unique 
        ON dhcp_leases(record_date, ip, mac, leasetime)
    ''')
    
    conn.commit()
    return conn
    
def parse_and_insert_xml(xml_bytes, record_date=None):
    if record_date is None:
        record_date = datetime.date.today().isoformat()

    conn = init_db()
    cursor = conn.cursor()

    if isinstance(xml_bytes, str):
        xml_bytes = xml_bytes.encode('utf-8')

    root = ET.fromstring(xml_bytes)

    if root.attrib.get('status') == 'error':
        err_msg = root.findtext('.//msg') or "Palo Alto API 回應未知錯誤"
        conn.close()
        raise ValueError(f"PA-1420 回傳錯誤：{err_msg}")

    entries = root.findall('.//entry')
    success_count = 0
    duplicate_count = 0
    multi_lease_count = 0 # 👈 新增：統計同 IP 不同時間的次數

    for entry in entries:
        ip = entry.findtext('ip', default='').strip()
        mac = entry.findtext('mac', default='').strip()
        hostname = entry.findtext('hostname', default='').strip()
        state = entry.findtext('state', default='').strip()
        duration = entry.findtext('duration', default='0').strip()
        leasetime = entry.findtext('leasetime', default='').strip()

        if not ip or not mac:
            continue

        try:
            # 👈 在寫入前，先檢查該日期是否已經有這個 IP 的紀錄
            cursor.execute("SELECT COUNT(*) FROM dhcp_leases WHERE record_date = ? AND ip = ?", (record_date, ip))
            ip_exists = cursor.fetchone()[0] > 0

            cursor.execute('''
                INSERT OR IGNORE INTO dhcp_leases 
                (record_date, ip, mac, hostname, state, duration, leasetime) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (record_date, ip, mac, hostname, state, int(duration) if duration.isdigit() else 0, leasetime))
            
            if cursor.rowcount == 1:
                success_count += 1
                # 👈 如果寫入成功，且該 IP 先前已存在於同日，代表這是「同 IP 不同時間」的第二筆以上紀錄
                if ip_exists:
                    multi_lease_count += 1
            else:
                duplicate_count += 1
        except sqlite3.Error as e:
            print(f"DB Error: {e}")

    conn.commit()
    conn.close()
    return success_count, duplicate_count, multi_lease_count # 👈 記得回傳新計數器

# -------------------------------------------------------------
# 狀態追蹤 (用於讓前端網頁知道排程最新狀態)
# -------------------------------------------------------------
last_job_info = {
    "timestamp": 0,
    "type": "system",
    "status": "waiting",
    "message": "等待排程或手動更新...",
    "success_count": 0,
    "duplicate_count": 0,
    "multi_lease_count": 0,
    "date": ""
}
    
# -------------------------------------------------------------
# PA-1420 API 抓取作業 (加入 job_type 與全域狀態更新)
# -------------------------------------------------------------
def fetch_pa_dhcp_job(job_type="auto"):
    global last_job_info
    today_str = datetime.date.today().isoformat()
    print(f"\n[{datetime.datetime.now()}] 啟動 PA-1420 DHCP 抓取作業 ({job_type})...")

    try:
        fw_ip, interface, api_key, cmd = get_pa_config()
        api_url = f"https://{fw_ip}/api/"
        params = {"type": "op", "cmd": cmd, "key": api_key}

        response = requests.get(api_url, params=params, verify=False, timeout=30)
        response.raise_for_status()

        success, duplicate, multi_lease = parse_and_insert_xml(response.content, record_date=today_str)
        print(f"[{datetime.datetime.now()}] PA-1420 抓取完成！新增：{success} 筆(含多重租約 {multi_lease} 筆)，略過重複：{duplicate} 筆")
        
        result = {
            "timestamp": time.time(),
            "type": job_type,       # 標記是 auto 還是 manual
            "status": "success", 
            "success_count": success, 
            "duplicate_count": duplicate, 
            "multi_lease_count": multi_lease,
            "date": today_str,
            "fw_ip": fw_ip,
            "interface": interface
        }
        last_job_info = result      # 👈 寫入全域狀態供前端抓取
        return result

    except Exception as e:
        print(f"[{datetime.datetime.now()}] PA-1420 抓取失敗：{str(e)}")
        result = {
            "timestamp": time.time(),
            "type": job_type,
            "status": "error",
            "message": str(e)
        }
        last_job_info = result      # 👈 寫入全域錯誤狀態
        return result

# -------------------------------------------------------------
# Web 路由
# -------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/fetch-now', methods=['POST'])
def trigger_fetch_now():
    # 標記為手動抓取
    result = fetch_pa_dhcp_job(job_type="manual")
    return jsonify(result)

# 👈 新增：提供前端輪詢最新狀態的 API
@app.route('/api/latest-status', methods=['GET'])
def get_latest_status():
    return jsonify(last_job_info)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': '沒有收到檔案'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': '未選擇檔案'})

    upload_date = request.form.get('record_date')
    if not upload_date:
        upload_date = datetime.date.today().isoformat()

    try:
        file_bytes = file.read()
        # 👈 接收 multi_lease_count
        success, duplicate, multi_lease = parse_and_insert_xml(file_bytes, record_date=upload_date)

        return jsonify({
            'status': 'success',
            'message': f'檔案已成功匯入至【{upload_date}】！',
            'success_count': success,
            'duplicate_count': duplicate,
            'multi_lease_count': multi_lease, # 👈 將資料回傳給前端
            'record_date': upload_date
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})
@app.route('/api/leases', methods=['GET'])
def get_leases():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    query_date = request.args.get('date', datetime.date.today().isoformat())

    conn = init_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM dhcp_leases WHERE record_date = ?", (query_date,))
    total_records = cursor.fetchone()[0]
    total_pages = math.ceil(total_records / per_page) if total_records > 0 else 1

    offset = (page - 1) * per_page
    
    # 依 IP 數值排序，同一 IP 則依 id (先後順序) 排列
    cursor.execute('''
        SELECT ip, mac, hostname, state, duration, leasetime, record_date
        FROM dhcp_leases 
        WHERE record_date = ?
        ORDER BY ip COLLATE IP_CMP ASC, id ASC
        LIMIT ? OFFSET ?
    ''', (query_date, per_page, offset))

    rows = cursor.fetchall()
    conn.close()

    data = [{
        'ip': row[0],
        'mac': row[1],
        'hostname': row[2],
        'state': row[3],
        'duration': row[4],
        'leasetime': row[5],
        'record_date': row[6]
    } for row in rows]

    return jsonify({
        'data': data,
        'current_page': page,
        'total_pages': total_pages,
        'total_records': total_records,
        'selected_date': query_date
    })
    
# -------------------------------------------------------------
# 定時排程器：每日 01:00、05:00、09:00、13:00、17:00、21:00 自動執行
# -------------------------------------------------------------
scheduler = BackgroundScheduler(timezone="Asia/Taipei")
# 👈 修改為 args=['auto'] 並更新時間頻率
scheduler.add_job(fetch_pa_dhcp_job, args=['auto'], trigger='cron', hour='1,5,9,13,17,21', minute=0)
scheduler.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=True, use_reloader=False)