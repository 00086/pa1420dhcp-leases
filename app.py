import os
import sqlite3
import math
import ipaddress
import datetime
import xml.etree.ElementTree as ET
import requests
import urllib3
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
            cursor.execute('''
                INSERT OR IGNORE INTO dhcp_leases 
                (record_date, ip, mac, hostname, state, duration, leasetime) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (record_date, ip, mac, hostname, state, int(duration) if duration.isdigit() else 0, leasetime))
            
            if cursor.rowcount == 1:
                success_count += 1
            else:
                duplicate_count += 1
        except sqlite3.Error as e:
            print(f"DB Error: {e}")

    conn.commit()
    conn.close()
    return success_count, duplicate_count

# -------------------------------------------------------------
# PA-1420 API 抓取作業
# -------------------------------------------------------------
def fetch_pa_dhcp_job():
    today_str = datetime.date.today().isoformat()
    print(f"\n[{datetime.datetime.now()}] 啟動 PA-1420 DHCP 抓取作業...")

    try:
        fw_ip, interface, api_key, cmd = get_pa_config()
        api_url = f"https://{fw_ip}/api/"
        params = {
            "type": "op",
            "cmd": cmd,
            "key": api_key
        }

        response = requests.get(api_url, params=params, verify=False, timeout=30)
        response.raise_for_status()

        success, duplicate = parse_and_insert_xml(response.content, record_date=today_str)
        print(f"[{datetime.datetime.now()}] PA-1420 抓取完成！新增：{success} 筆，略過重複：{duplicate} 筆")
        return {
            "status": "success", 
            "success_count": success, 
            "duplicate_count": duplicate, 
            "date": today_str,
            "fw_ip": fw_ip,
            "interface": interface
        }

    except Exception as e:
        print(f"[{datetime.datetime.now()}] PA-1420 抓取失敗：{str(e)}")
        return {"status": "error", "message": str(e)}

# -------------------------------------------------------------
# Web 路由
# -------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/fetch-now', methods=['POST'])
def trigger_fetch_now():
    result = fetch_pa_dhcp_job()
    return jsonify(result)

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
        success, duplicate = parse_and_insert_xml(file_bytes, record_date=upload_date)

        return jsonify({
            'status': 'success',
            'message': f'檔案已成功匯入至【{upload_date}】！',
            'success_count': success,
            'duplicate_count': duplicate,
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
# 定時排程器：每日 01:00、07:00、15:00、23:00 自動執行
# -------------------------------------------------------------
scheduler = BackgroundScheduler(timezone="Asia/Taipei")
scheduler.add_job(fetch_pa_dhcp_job, trigger='cron', hour='1,7,15,23', minute=0)
scheduler.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=True, use_reloader=False)