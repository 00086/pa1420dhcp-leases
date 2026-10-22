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
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, request, jsonify
from apscheduler.schedulers.background import BackgroundScheduler
import apscheduler.triggers.cron
import apscheduler.triggers.interval

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

def fetch_pa_disk_space():
    """擷取 PA-1420 SSD 磁碟各分區使用狀態"""
    try:
        root = run_pa_command("<show><system><disk-space/></system></show>")
        result_text = root.findtext('.//result', default='')

        partitions = []
        panlogs_info = None

        # 逐行解析磁碟資訊，跳過標題列
        lines = result_text.strip().split('\n')
        for line in lines:
            parts = line.split()
            # 確保格式正確 (Filesystem, Size, Used, Avail, Use%, Mounted on)
            if len(parts) >= 6 and parts[0] != 'Filesystem':
                fs, size, used, avail, use_pct_str, mount = parts[:6]
                try:
                    use_pct = int(use_pct_str.replace('%', ''))
                except ValueError:
                    use_pct = 0
                
                part_info = {
                    'filesystem': fs,
                    'size': size,
                    'used': used,
                    'avail': avail,
                    'percent': use_pct,
                    'mount': mount
                }
                partitions.append(part_info)
                
                # 優先抓取最關鍵的 /opt/panlogs 作為標籤主要顯示的基準
                if mount == '/opt/panlogs':
                    panlogs_info = part_info

        # 若找不到 panlogs 則抓取根目錄 / 作為標籤基準
        if not panlogs_info:
            for p in partitions:
                if p['mount'] == '/':
                    panlogs_info = p
                    break

        if panlogs_info:
            return {
                'total': panlogs_info['size'],
                'used': panlogs_info['used'],
                'avail': panlogs_info['avail'],
                'percent': panlogs_info['percent'],
                'desc': f"{panlogs_info['used']} / {panlogs_info['size']}",
                'all_partitions': partitions  # 👈 將所有分區清單一併回傳
            }
    except Exception as e:
        print(f"SSD 容量解析異常: {e}")

    return {'total': '-', 'used': '-', 'avail': '-', 'percent': 0, 'desc': '-', 'all_partitions': []}
    
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

def run_pa_command(cmd_xml):
    fw_ip, _, api_key, _ = get_pa_config()
    api_url = f"https://{fw_ip}/api/"
    params = {"type": "op", "cmd": cmd_xml, "key": api_key}
    response = requests.get(api_url, params=params, verify=False, timeout=15)
    response.raise_for_status()
    root = ET.fromstring(response.content)
    if root.attrib.get('status') == 'error':
        err_msg = root.findtext('.//msg') or "PA API 回應錯誤"
        raise ValueError(err_msg)
    return root

# -------------------------------------------------------------
# 資料庫初始化 (含租約、健康歷程、DNS 快取)
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
    
    # 租約主表
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
    cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_dhcp_lease_unique ON dhcp_leases(record_date, ip, mac, leasetime)')

    # 系統健康歷程表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_health_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_time TEXT NOT NULL,
            mp_cpu REAL,
            dp_cpu REAL,
            mem_usage_pct REAL,
            active_sessions INTEGER
        )
    ''')

    # 固定 IP 反向 DNS 快取表 (永久儲存解析結果)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_hostname_cache (
            ip TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    ''')
    
    # 自動檢查並擴充 disk_usage_pct 欄位 (相容既有 DB)
    cursor.execute("PRAGMA table_info(system_health_log)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'disk_usage_pct' not in columns:
        cursor.execute("ALTER TABLE system_health_log ADD COLUMN disk_usage_pct REAL DEFAULT 0.0")

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
    multi_lease_count = 0

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
            cursor.execute("SELECT COUNT(*) FROM dhcp_leases WHERE record_date = ? AND ip = ?", (record_date, ip))
            ip_exists = cursor.fetchone()[0] > 0

            cursor.execute('''
                INSERT OR IGNORE INTO dhcp_leases 
                (record_date, ip, mac, hostname, state, duration, leasetime) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (record_date, ip, mac, hostname, state, int(duration) if duration.isdigit() else 0, leasetime))
            
            if cursor.rowcount == 1:
                success_count += 1
                if ip_exists:
                    multi_lease_count += 1
            else:
                duplicate_count += 1
        except sqlite3.Error as e:
            print(f"DB Error: {e}")

    cursor.execute("SELECT COUNT(DISTINCT ip) FROM dhcp_leases WHERE record_date = ?", (record_date,))
    unique_ip_count = cursor.fetchone()[0]

    conn.commit()
    conn.close()
    return success_count, duplicate_count, multi_lease_count, unique_ip_count

# -------------------------------------------------------------
# 狀態追蹤
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

        success, duplicate, multi_lease, unique_ip_count = parse_and_insert_xml(response.content, record_date=today_str)
        print(f"[{datetime.datetime.now()}] PA-1420 抓取完成！新增：{success} 筆(含多重租約 {multi_lease} 筆)，略過重複：{duplicate} 筆，今日不重複 IP：{unique_ip_count} 筆")
        
        result = {
            "timestamp": time.time(),
            "type": job_type,
            "status": "success", 
            "success_count": success, 
            "duplicate_count": duplicate, 
            "multi_lease_count": multi_lease,
            "unique_ip_count": unique_ip_count,
            "date": today_str,
            "fw_ip": fw_ip,
            "interface": interface
        }
        last_job_info = result
        return result

    except Exception as e:
        print(f"[{datetime.datetime.now()}] PA-1420 抓取失敗：{str(e)}")
        result = {
            "timestamp": time.time(),
            "type": job_type,
            "status": "error",
            "message": str(e)
        }
        last_job_info = result
        return result

# -------------------------------------------------------------
# 系統硬體狀態擷取 (MP CPU / DP CPU / RAM / Sessions)
# -------------------------------------------------------------
def fetch_pa_health_data():
    """集中擷取 PA-1420 硬體資訊 (含 MP/DP CPU、記憶體 used+cache、磁碟各分區、連線數)"""
    # 1. 系統基本資訊
    info_root = run_pa_command("<show><system><info/></system></show>")
    system_elem = info_root.find('.//system')
    
    hostname = system_elem.findtext('hostname', default='PA-1420') if system_elem is not None else 'PA-1420'
    model = system_elem.findtext('model', default='PA-1420') if system_elem is not None else 'PA-1420'
    sw_version = system_elem.findtext('sw-version', default='-') if system_elem is not None else '-'
    uptime = system_elem.findtext('uptime', default='-') if system_elem is not None else '-'

    # 2. 連線數統計
    session_root = run_pa_command("<show><session><info/></session></show>")
    active_sessions = int(session_root.findtext('.//num-active', default='0'))
    max_sessions = int(session_root.findtext('.//num-max', default='1'))
    session_usage_pct = round((active_sessions / max_sessions) * 100, 2) if max_sessions > 0 else 0.0

    # 3. MP CPU (管理平面) 與 記憶體 (同時解析 total, used, free, buff/cache)
    mp_cpu = 0.0
    mem_usage_pct = 0.0
    mem_desc = ""
    try:
        res_root = run_pa_command("<show><system><resources/></system></show>")
        res_text = res_root.findtext('.//result', default='')
        
        # 解析 MP CPU
        cpu_match = re.search(r'(?:%?Cpu\(s\)|Cpu\(s\)):\s*[\d\.]+%?\s*us,.*?([\d\.]+)%?\s*id', res_text)
        if cpu_match:
            idle = float(cpu_match.group(1))
            mp_cpu = round(max(0.0, 100.0 - idle), 1)

        # 彈性解析記憶體 (相容 PAN-OS 11 的 MiB / KiB / GiB 及小數點，同時提取 buff/cache)
        mem_line_match = re.search(r'([^\n\r]*\bMem\b[^\n\r]*total[^\n\r]*)', res_text, re.IGNORECASE)
        if mem_line_match:
            line = mem_line_match.group(1)
            tot_m = re.search(r'([\d\.]+)\s*([kKmMgGtT]?i?B?)?\s*total', line, re.IGNORECASE)
            usd_m = re.search(r'([\d\.]+)\s*([kKmMgGtT]?i?B?)?\s*used', line, re.IGNORECASE)
            free_m = re.search(r'([\d\.]+)\s*([kKmMgGtT]?i?B?)?\s*free', line, re.IGNORECASE)
            cache_m = re.search(r'([\d\.]+)\s*([kKmMgGtT]?i?B?)?\s*(?:buff/cache|cache|buffers)', line, re.IGNORECASE)

            if tot_m:
                tot_val = float(tot_m.group(1))
                line_lower = line.lower()
                
                # 自動判斷單位換算係數 (統一換算為 GB)
                if 'mib' in line_lower:
                    unit_factor = 1 / 1024
                elif 'gib' in line_lower:
                    unit_factor = 1.0
                elif 'kib' in line_lower or 'k total' in line_lower:
                    unit_factor = 1 / (1024 * 1024)
                else:
                    unit_factor = 1 / (1024 * 1024) if tot_val > 1000000 else (1 / 1024 if tot_val > 1000 else 1.0)

                tot_g = round(tot_val * unit_factor, 1)
                usd_g = round(float(usd_m.group(1)) * unit_factor, 1) if usd_m else 0.0
                cache_g = round(float(cache_m.group(1)) * unit_factor, 1) if cache_m else 0.0

                if tot_g > 0:
                    mem_usage_pct = round((usd_g / tot_g) * 100, 1)
                    if cache_g > 0:
                        mem_desc = f"{usd_g}G + {cache_g}G快取 / {tot_g}G"
                    else:
                        mem_desc = f"{usd_g}G / {tot_g}G"
    except Exception as e:
        print("MP CPU/Mem 解析異常:", e)

    # 4. DP CPU (資料平面)
    dp_cpu = 0.0
    try:
        dp_root = run_pa_command("<show><running><resource-monitor><second><last>1</last></second></resource-monitor></running></show>")
        vals = [float(e.text.strip()) for e in dp_root.findall('.//cpu-load-average//value') if e.text and e.text.strip().replace('.','',1).isdigit()]
        if not vals:
            dp_root = run_pa_command("<show><running><resource-monitor><minute><last>1</last></minute></resource-monitor></running></show>")
            vals = [float(e.text.strip()) for e in dp_root.findall('.//cpu-load-average//value') if e.text and e.text.strip().replace('.','',1).isdigit()]
        
        if vals:
            dp_cpu = round(sum(vals) / len(vals), 1)
    except Exception as e:
        print("DP CPU 解析異常:", e)

    # 5. SSD 各分區空間解析
    disk_info = fetch_pa_disk_space()

    return {
        'hostname': hostname,
        'model': model,
        'sw_version': sw_version,
        'uptime': uptime,
        'mp_cpu': mp_cpu,
        'dp_cpu': dp_cpu,
        'mem_usage_pct': mem_usage_pct,
        'mem_desc': mem_desc,
        'active_sessions': active_sessions,
        'max_sessions': max_sessions,
        'session_usage_pct': session_usage_pct,
        'disk_usage_pct': disk_info['percent'],
        'disk_desc': disk_info['desc'],
        'disk_partitions': disk_info['all_partitions']
    }
    
def log_system_health_job():
    try:
        data = fetch_pa_health_data()
        conn = init_db()
        cursor = conn.cursor()
        now_str = datetime.datetime.now().isoformat()

        cursor.execute('''
            INSERT INTO system_health_log (record_time, mp_cpu, dp_cpu, mem_usage_pct, active_sessions, disk_usage_pct)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (now_str, data['mp_cpu'], data['dp_cpu'], data['mem_usage_pct'], data['active_sessions'], data.get('disk_usage_pct', 0.0)))

        threshold = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
        cursor.execute("DELETE FROM system_health_log WHERE record_time < ?", (threshold,))

        conn.commit()
        conn.close()
    except Exception as e:
        print("背景記錄系統健康狀態失敗:", e)
        
# -------------------------------------------------------------
# 背景 DNS 解析工作核心與進度追蹤
# -------------------------------------------------------------
dns_worker_status = {
    "is_running": False,
    "total": 0,
    "done": 0
}
dns_lock = threading.Lock()

def background_dns_worker(target_ips):
    global dns_worker_status
    with dns_lock:
        dns_worker_status["is_running"] = True
        dns_worker_status["total"] = len(target_ips)
        dns_worker_status["done"] = 0

    print(f"\n[背景 DNS 任務] 啟動，準備深度解析 {len(target_ips)} 筆固定 IP...")

    def resolve_single_ip(target_ip):
        global dns_worker_status
        name_found = None
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(3.0)
            fqdn = socket.gethostbyaddr(target_ip)[0]
            socket.setdefaulttimeout(old_timeout)
            name_found = fqdn.split('.')[0] if '.' in fqdn else fqdn
        except Exception:
            pass

        if name_found:
            try:
                conn = sqlite3.connect("dhcp_records.db")
                cur = conn.cursor()
                now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cur.execute("INSERT OR REPLACE INTO ip_hostname_cache (ip, hostname, updated_at) VALUES (?, ?, ?)",
                            (target_ip, name_found, now_str))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"寫入快取異常: {e}")

        with dns_lock:
            dns_worker_status["done"] += 1

    with ThreadPoolExecutor(max_workers=15) as executor:
        executor.map(resolve_single_ip, target_ips)

    with dns_lock:
        dns_worker_status["is_running"] = False
    print(f"[背景 DNS 任務] 解析完成！共處理 {len(target_ips)} 筆。")

# -------------------------------------------------------------
# 資安威脅日誌擷取
# -------------------------------------------------------------
def fetch_pa_threat_logs(count=100):
    fw_ip, _, api_key, _ = get_pa_config()
    api_url = f"https://{fw_ip}/api/"
    
    query_params = {
        "type": "log",
        "log-type": "threat",
        "nlogs": str(count),
        "key": api_key
    }
    resp = requests.get(api_url, params=query_params, verify=False, timeout=15)
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    
    job_id = root.findtext('.//job')
    if not job_id:
        raise ValueError(root.findtext('.//msg') or "無法取得 Log Job ID")
    
    for _ in range(10):
        time.sleep(0.5)
        poll_params = {
            "type": "log",
            "action": "get",
            "job-id": job_id,
            "key": api_key
        }
        poll_resp = requests.get(api_url, params=poll_params, verify=False, timeout=15)
        poll_root = ET.fromstring(poll_resp.content)
        status = poll_root.findtext('.//status')
        if status == 'FIN':
            return poll_root
            
    raise TimeoutError("查詢 PA-1420 威脅日誌逾時")

# -------------------------------------------------------------
# Web 路由
# -------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/fetch-now', methods=['POST'])
def trigger_fetch_now():
    result = fetch_pa_dhcp_job(job_type="manual")
    return jsonify(result)

@app.route('/api/latest-status', methods=['GET'])
def get_latest_status():
    return jsonify(last_job_info)

@app.route('/api/system-health', methods=['GET'])
def get_system_health():
    try:
        data = fetch_pa_health_data()
        return jsonify({'status': 'success', **data})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/health-history', methods=['GET'])
def get_health_history():
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT record_time, mp_cpu, dp_cpu, mem_usage_pct, active_sessions, disk_usage_pct 
        FROM system_health_log 
        ORDER BY id DESC LIMIT 180
    ''')
    rows = cursor.fetchall()
    conn.close()

    history = [{
        'record_time': r[0],
        'mp_cpu': r[1],
        'dp_cpu': r[2],
        'mem_usage_pct': r[3],
        'active_sessions': r[4],
        'disk_usage_pct': r[5] if len(r) > 5 and r[5] is not None else 0.0
    } for r in reversed(rows)]

    return jsonify({'status': 'success', 'history': history})
    
@app.route('/api/threat-analytics', methods=['GET'])
def get_threat_analytics():
    try:
        log_root = fetch_pa_threat_logs(count=150)
        entries = log_root.findall('.//entry')

        today_str = datetime.date.today().isoformat()
        conn = init_db()
        cursor = conn.cursor()
        cursor.execute("SELECT ip, mac, hostname FROM dhcp_leases WHERE record_date = ?", (today_str,))
        dhcp_map = {r[0]: {'mac': r[1], 'hostname': r[2]} for r in cursor.fetchall()}
        conn.close()

        records = []
        source_counter = {}
        threat_counter = {}
        severity_dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}

        for entry in entries:
            src = entry.findtext('src', default='').strip()
            dst = entry.findtext('dst', default='').strip()
            threat_name = entry.findtext('threatid', default=entry.findtext('threat_name', default='未知威脅')).strip()
            subtype = entry.findtext('subtype', default='-').strip()
            severity = (entry.findtext('severity', default='low') or 'low').lower()
            action = entry.findtext('action', default='deny').strip()
            log_time = entry.findtext('time_generated', default=entry.findtext('receive_time', default='-')).strip()
            app_name = entry.findtext('app', default='-').strip()

            if severity in severity_dist:
                severity_dist[severity] += 1
            else:
                severity_dist['low'] += 1

            source_counter[src] = source_counter.get(src, 0) + 1
            threat_counter[threat_name] = threat_counter.get(threat_name, 0) + 1

            dhcp_info = dhcp_map.get(src, {})
            records.append({
                'time': log_time,
                'src': src,
                'hostname': dhcp_info.get('hostname', '-'),
                'mac': dhcp_info.get('mac', '-'),
                'is_internal': src in dhcp_map,
                'dst': dst,
                'threat_name': threat_name,
                'subtype': subtype,
                'severity': severity,
                'action': action,
                'app': app_name
            })

        top_sources = sorted(source_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        top_sources_data = [{
            'ip': ip,
            'count': count,
            'hostname': dhcp_map.get(ip, {}).get('hostname', '外部/非DHCP'),
            'mac': dhcp_map.get(ip, {}).get('mac', '-')
        } for ip, count in top_sources]

        top_threats = sorted(threat_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        top_threats_data = [{'threat_name': name, 'count': count} for name, count in top_threats]

        return jsonify({
            'status': 'success',
            'total_threats': len(records),
            'severity_dist': severity_dist,
            'top_sources': top_sources_data,
            'top_threats': top_threats_data,
            'logs': records[:50]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/arp-analysis', methods=['GET'])
def get_arp_analysis():
    query_date = request.args.get('date', datetime.date.today().isoformat())
    try:
        arp_root = run_pa_command("<show><arp><entry name='all'/></arp></show>")
        arp_entries = arp_root.findall('.//entry')

        conn = init_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT ip, mac, hostname FROM dhcp_leases WHERE record_date = ?", (query_date,))
        dhcp_records = {row[0]: {'mac': row[1].lower(), 'hostname': row[2]} for row in cursor.fetchall()}

        cursor.execute("SELECT mac, hostname FROM dhcp_leases WHERE hostname != '' AND hostname IS NOT NULL ORDER BY id ASC")
        historical_mac_map = {row[0].lower(): row[1] for row in cursor.fetchall()}

        cursor.execute("SELECT ip, hostname FROM ip_hostname_cache")
        dns_cache_map = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()

        results = []
        static_ip_count = 0
        normal_dhcp_count = 0
        conflict_count = 0
        uncached_static_ips = []

        for entry in arp_entries:
            ip = entry.findtext('ip', default='').strip()
            mac = entry.findtext('mac', default='').strip().lower()
            interface = entry.findtext('interface', default='').strip()
            status = entry.findtext('status', default='').strip()

            if not ip or not mac or mac == '(incomplete)' or status == 'i':
                continue

            if ip in dhcp_records:
                dhcp_mac = dhcp_records[ip]['mac']
                hostname = dhcp_records[ip]['hostname'] or '(無主機名)'
                if dhcp_mac == mac:
                    dev_type = "DHCP 動態配發"
                    tag_class = "success"
                    normal_dhcp_count += 1
                else:
                    dev_type = "⚠️ IP 衝突/MAC變更"
                    tag_class = "danger"
                    conflict_count += 1
            else:
                dev_type = "🚨 私設/固定 IP (Static IP)"
                tag_class = "warning"
                static_ip_count += 1

                if ip in dns_cache_map:
                    hostname = f"<span class='text-primary fw-bold'><i class='bi bi-globe me-1'></i>{dns_cache_map[ip]}</span>"
                elif mac in historical_mac_map:
                    hostname = f"<span class='text-secondary'><i class='bi bi-clock-history me-1'></i>{historical_mac_map[mac]} (歷史)</span>"
                    uncached_static_ips.append(ip)
                else:
                    if dns_worker_status["is_running"]:
                        hostname = "<span class='text-muted'><div class='spinner-grow spinner-grow-sm text-secondary me-1'></div>解析中...</span>"
                    else:
                        hostname = "<span class='text-muted'>待解析</span>"
                    uncached_static_ips.append(ip)

            results.append({
                'ip': ip,
                'mac': mac,
                'interface': interface,
                'hostname': hostname,
                'dev_type': dev_type,
                'tag_class': tag_class
            })

        if uncached_static_ips and not dns_worker_status["is_running"]:
            t = threading.Thread(target=background_dns_worker, args=(uncached_static_ips,), daemon=True)
            t.start()

        results.sort(key=lambda x: int(ipaddress.IPv4Address(x['ip'])) if x['ip'].replace('.','').isdigit() else 0)

        return jsonify({
            'status': 'success',
            'date': query_date,
            'total_arp': len(results),
            'static_ip_count': static_ip_count,
            'normal_dhcp_count': normal_dhcp_count,
            'conflict_count': conflict_count,
            'dns_progress': {
                'is_running': dns_worker_status["is_running"],
                'total': dns_worker_status["total"],
                'done': dns_worker_status["done"]
            },
            'data': results
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

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
        success, duplicate, multi_lease, unique_ip_count = parse_and_insert_xml(file_bytes, record_date=upload_date)

        return jsonify({
            'status': 'success',
            'message': f'檔案已成功匯入至【{upload_date}】！',
            'success_count': success,
            'duplicate_count': duplicate,
            'multi_lease_count': multi_lease,
            'unique_ip_count': unique_ip_count,
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
# 定時排程器
# -------------------------------------------------------------
scheduler = BackgroundScheduler(timezone="Asia/Taipei")
# DHCP 每日排程抓取 (6 次/日)
scheduler.add_job(fetch_pa_dhcp_job, args=['auto'], trigger='cron', hour='1,5,9,13,17,21', minute=0)
# 系統效能每 1 分鐘自動寫入 DB 供圖表繪製
scheduler.add_job(log_system_health_job, trigger='interval', minutes=1)
scheduler.start()

if __name__ == '__main__':
    log_system_health_job()
    app.run(host='0.0.0.0', port=5006, debug=True, use_reloader=False)