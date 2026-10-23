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
import ctypes
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------------------------------------------
# PA-1420 設定檔路徑定位與防呆
# -------------------------------------------------------------
if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

PA_CONFIG_FILE = os.path.join(APP_DIR, "pa1420key.txt")

def ensure_pa_config_template():
    if not os.path.exists(PA_CONFIG_FILE):
        try:
            sample_content = (
                "# 第 1 行：PA-1420 防火牆 IP\n"
                "192.168.1.1\n"
                "# 第 2 行：監控介面 (例如 ethernet1/1 或 all)\n"
                "all\n"
                "# 第 3 行：PA-1420 XML API Key\n"
                "YOUR_API_KEY_HERE\n"
            )
            with open(PA_CONFIG_FILE, "w", encoding="utf-8") as f:
                f.write(sample_content)
            print(f"[提示] 已自動在同級目錄建立設定檔範本：{PA_CONFIG_FILE}")
        except Exception as e:
            print(f"建立設定檔範本失敗: {e}")

        if sys.platform == 'win32':
            try:
                msg = (
                    f"【系統提醒】未偵測到 PA-1420 設定檔案！\n\n"
                    f"系統已自動於以下路徑建立範本檔：\n{PA_CONFIG_FILE}\n\n"
                    f"請以文字編輯器開啟並填入真實的防火牆 IP、介面與 API Key，"
                    f"儲存後即可正常連線。"
                )
                ctypes.windll.user32.MessageBoxW(0, msg, "PA-1420 監控系統 - 缺少設定檔", 0x30)
            except Exception:
                pass

def get_pa_config():
    if not os.path.exists(PA_CONFIG_FILE):
        raise FileNotFoundError(f"找不到設定檔案：{PA_CONFIG_FILE}")

    with open(PA_CONFIG_FILE, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

    if len(lines) < 3:
        raise ValueError(f"{PA_CONFIG_FILE} 格式錯誤！必須包含三行有效內容。")
    if lines[0] == "192.168.1.1" or "YOUR_API_KEY" in lines[2]:
        raise ValueError("pa1420key.txt 仍為範本預設值，請填入實際的防火牆 IP 與 API Key！")

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

def fetch_pa_disk_space():
    try:
        root = run_pa_command("<show><system><disk-space/></system></show>")
        result_text = root.findtext('.//result', default='')
        partitions = []
        panlogs_info = None

        lines = result_text.strip().split('\n')
        for line in lines:
            parts = line.split()
            if len(parts) >= 6 and parts[0] != 'Filesystem':
                fs, size, used, avail, use_pct_str, mount = parts[:6]
                try:
                    use_pct = int(use_pct_str.replace('%', ''))
                except ValueError:
                    use_pct = 0
                part_info = {
                    'filesystem': fs, 'size': size, 'used': used,
                    'avail': avail, 'percent': use_pct, 'mount': mount
                }
                partitions.append(part_info)
                if mount == '/opt/panlogs':
                    panlogs_info = part_info

        if not panlogs_info:
            for p in partitions:
                if p['mount'] == '/':
                    panlogs_info = p
                    break

        if panlogs_info:
            return {
                'total': panlogs_info['size'], 'used': panlogs_info['used'],
                'avail': panlogs_info['avail'], 'percent': panlogs_info['percent'],
                'desc': f"{panlogs_info['used']} / {panlogs_info['size']}",
                'all_partitions': partitions
            }
    except Exception as e:
        print(f"SSD 容量解析異常: {e}")
    return {'total': '-', 'used': '-', 'avail': '-', 'percent': 0, 'desc': '-', 'all_partitions': []}

# -------------------------------------------------------------
# 資料庫操作 (未來將遷移至 DuckDB)
# -------------------------------------------------------------
def ip_collation(ip1, ip2):
    try:
        val1 = int(ipaddress.IPv4Address(ip1))
        val2 = int(ipaddress.IPv4Address(ip2))
        return (val1 > val2) - (val1 < val2)
    except ValueError:
        return (ip1 > ip2) - (ip1 < ip2)

def init_db(db_name="dhcp_records.db"):
    db_path = os.path.join(APP_DIR, db_name)
    conn = sqlite3.connect(db_path)
    conn.create_collation("IP_CMP", ip_collation)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dhcp_leases (
            id INTEGER PRIMARY KEY AUTOINCREMENT, record_date TEXT NOT NULL,
            ip TEXT NOT NULL, mac TEXT NOT NULL, hostname TEXT, state TEXT,
            duration INTEGER, leasetime TEXT
        )
    ''')
    cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_dhcp_lease_unique ON dhcp_leases(record_date, ip, mac, leasetime)')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_health_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, record_time TEXT NOT NULL,
            mp_cpu REAL, dp_cpu REAL, mem_usage_pct REAL, active_sessions INTEGER
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_hostname_cache (
            ip TEXT PRIMARY KEY, hostname TEXT NOT NULL, updated_at TEXT NOT NULL
        )
    ''')
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
    success_count, duplicate_count, multi_lease_count = 0, 0, 0

    for entry in entries:
        ip = entry.findtext('ip', default='').strip()
        mac = entry.findtext('mac', default='').strip()
        hostname = entry.findtext('hostname', default='').strip()
        state = entry.findtext('state', default='').strip()
        duration = entry.findtext('duration', default='0').strip()
        leasetime = entry.findtext('leasetime', default='').strip()

        if not ip or not mac: continue

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
                if ip_exists: multi_lease_count += 1
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
# 系統作業與狀態管理
# -------------------------------------------------------------
last_job_info = {
    "timestamp": 0, "type": "system", "status": "waiting",
    "message": "等待排程或手動更新...", "success_count": 0,
    "duplicate_count": 0, "multi_lease_count": 0, "date": ""
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
        print(f"[{datetime.datetime.now()}] PA-1420 抓取完成！新增：{success} 筆")
        
        last_job_info = {
            "timestamp": time.time(), "type": job_type, "status": "success", 
            "success_count": success, "duplicate_count": duplicate, 
            "multi_lease_count": multi_lease, "unique_ip_count": unique_ip_count,
            "date": today_str, "fw_ip": fw_ip, "interface": interface
        }
        return last_job_info
    except Exception as e:
        print(f"[{datetime.datetime.now()}] PA-1420 抓取失敗：{str(e)}")
        last_job_info = {"timestamp": time.time(), "type": job_type, "status": "error", "message": str(e)}
        return last_job_info

def fetch_pa_health_data():
    info_root = run_pa_command("<show><system><info/></system></show>")
    system_elem = info_root.find('.//system')
    hostname = system_elem.findtext('hostname', default='PA-1420') if system_elem is not None else 'PA-1420'
    model = system_elem.findtext('model', default='PA-1420') if system_elem is not None else 'PA-1420'
    sw_version = system_elem.findtext('sw-version', default='-') if system_elem is not None else '-'
    uptime = system_elem.findtext('uptime', default='-') if system_elem is not None else '-'

    session_root = run_pa_command("<show><session><info/></session></show>")
    active_sessions = int(session_root.findtext('.//num-active', default='0'))
    max_sessions = int(session_root.findtext('.//num-max', default='1'))
    session_usage_pct = round((active_sessions / max_sessions) * 100, 2) if max_sessions > 0 else 0.0

    mp_cpu, mem_usage_pct, mem_desc = 0.0, 0.0, ""
    try:
        res_root = run_pa_command("<show><system><resources/></system></show>")
        res_text = res_root.findtext('.//result', default='')
        
        cpu_match = re.search(r'(?:%?Cpu\(s\)|Cpu\(s\)):\s*[\d\.]+%?\s*us,.*?([\d\.]+)%?\s*id', res_text)
        if cpu_match:
            mp_cpu = round(max(0.0, 100.0 - float(cpu_match.group(1))), 1)

        mem_line_match = re.search(r'([^\n\r]*\bMem\b[^\n\r]*total[^\n\r]*)', res_text, re.IGNORECASE)
        if mem_line_match:
            line = mem_line_match.group(1)
            tot_m = re.search(r'([\d\.]+)\s*([kKmMgGtT]?i?B?)?\s*total', line, re.IGNORECASE)
            usd_m = re.search(r'([\d\.]+)\s*([kKmMgGtT]?i?B?)?\s*used', line, re.IGNORECASE)
            cache_m = re.search(r'([\d\.]+)\s*([kKmMgGtT]?i?B?)?\s*(?:buff/cache|cache|buffers)', line, re.IGNORECASE)

            if tot_m:
                tot_val, line_lower = float(tot_m.group(1)), line.lower()
                if 'mib' in line_lower: unit_factor = 1 / 1024
                elif 'gib' in line_lower: unit_factor = 1.0
                elif 'kib' in line_lower or 'k total' in line_lower: unit_factor = 1 / (1024 * 1024)
                else: unit_factor = 1 / (1024 * 1024) if tot_val > 1000000 else (1 / 1024 if tot_val > 1000 else 1.0)

                tot_g = round(tot_val * unit_factor, 1)
                usd_g = round(float(usd_m.group(1)) * unit_factor, 1) if usd_m else 0.0
                cache_g = round(float(cache_m.group(1)) * unit_factor, 1) if cache_m else 0.0

                if tot_g > 0:
                    mem_usage_pct = round((usd_g / tot_g) * 100, 1)
                    mem_desc = f"{usd_g}G + {cache_g}G快取 / {tot_g}G" if cache_g > 0 else f"{usd_g}G / {tot_g}G"
    except Exception as e:
        print("MP CPU/Mem 解析異常:", e)

    dp_cpu = 0.0
    try:
        dp_root = run_pa_command("<show><running><resource-monitor><second><last>1</last></second></resource-monitor></running></show>")
        vals = [float(e.text.strip()) for e in dp_root.findall('.//cpu-load-average//value') if e.text and e.text.strip().replace('.','',1).isdigit()]
        if not vals:
            dp_root = run_pa_command("<show><running><resource-monitor><minute><last>1</last></minute></resource-monitor></running></show>")
            vals = [float(e.text.strip()) for e in dp_root.findall('.//cpu-load-average//value') if e.text and e.text.strip().replace('.','',1).isdigit()]
        if vals: dp_cpu = round(sum(vals) / len(vals), 1)
    except Exception as e:
        print("DP CPU 解析異常:", e)

    disk_info = fetch_pa_disk_space()
    return {
        'hostname': hostname, 'model': model, 'sw_version': sw_version, 'uptime': uptime,
        'mp_cpu': mp_cpu, 'dp_cpu': dp_cpu, 'mem_usage_pct': mem_usage_pct, 'mem_desc': mem_desc,
        'active_sessions': active_sessions, 'max_sessions': max_sessions, 'session_usage_pct': session_usage_pct,
        'disk_usage_pct': disk_info['percent'], 'disk_desc': disk_info['desc'], 'disk_partitions': disk_info['all_partitions']
    }
    
def log_system_health_job():
    try:
        data = fetch_pa_health_data()
        conn = init_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO system_health_log (record_time, mp_cpu, dp_cpu, mem_usage_pct, active_sessions, disk_usage_pct)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (datetime.datetime.now().isoformat(), data['mp_cpu'], data['dp_cpu'], data['mem_usage_pct'], data['active_sessions'], data.get('disk_usage_pct', 0.0)))
        threshold = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
        cursor.execute("DELETE FROM system_health_log WHERE record_time < ?", (threshold,))
        conn.commit()
        conn.close()
    except Exception as e:
        print("背景記錄健康狀態失敗:", e)

# -------------------------------------------------------------
# DNS 工作與威脅日誌擷取
# -------------------------------------------------------------
dns_worker_status = {"is_running": False, "total": 0, "done": 0}
dns_lock = threading.Lock()

def background_dns_worker(target_ips):
    global dns_worker_status
    with dns_lock:
        dns_worker_status["is_running"] = True
        dns_worker_status["total"] = len(target_ips)
        dns_worker_status["done"] = 0

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
                db_path = os.path.join(APP_DIR, "dhcp_records.db")
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cur.execute("INSERT OR REPLACE INTO ip_hostname_cache (ip, hostname, updated_at) VALUES (?, ?, ?)",
                            (target_ip, name_found, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                conn.commit()
                conn.close()
            except Exception: pass
        with dns_lock: dns_worker_status["done"] += 1

    with ThreadPoolExecutor(max_workers=15) as executor:
        executor.map(resolve_single_ip, target_ips)
    with dns_lock: dns_worker_status["is_running"] = False

def fetch_pa_threat_logs(count=100):
    fw_ip, _, api_key, _ = get_pa_config()
    api_url = f"https://{fw_ip}/api/"
    query_params = {"type": "log", "log-type": "threat", "nlogs": str(count), "key": api_key}
    resp = requests.get(api_url, params=query_params, verify=False, timeout=15)
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    
    job_id = root.findtext('.//job')
    if not job_id: raise ValueError(root.findtext('.//msg') or "無法取得 Log Job ID")
    
    for _ in range(10):
        time.sleep(0.5)
        poll_params = {"type": "log", "action": "get", "job-id": job_id, "key": api_key}
        poll_resp = requests.get(api_url, params=poll_params, verify=False, timeout=15)
        poll_root = ET.fromstring(poll_resp.content)
        if poll_root.findtext('.//status') == 'FIN':
            return poll_root
    raise TimeoutError("查詢 PA-1420 威脅日誌逾時")