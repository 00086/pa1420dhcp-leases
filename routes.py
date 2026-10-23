import os
import datetime
import math
import ipaddress
import threading
from flask import Blueprint, render_template, request, jsonify

# 匯入核心模組邏輯
import core

# 宣告 Flask Blueprint，整合所有路由
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/api/config-status', methods=['GET'])
def get_config_status():
    if not os.path.exists(core.PA_CONFIG_FILE):
        return jsonify({
            'status': 'missing',
            'message': f'找不到設定檔案！系統已建立範本檔，請填寫：{core.PA_CONFIG_FILE}',
            'path': core.PA_CONFIG_FILE
        })
    try:
        fw_ip, interface, _, _ = core.get_pa_config()
        return jsonify({
            'status': 'ok',
            'message': '設定檔配置正確',
            'fw_ip': fw_ip,
            'interface': interface
        })
    except Exception as e:
        return jsonify({
            'status': 'invalid',
            'message': str(e),
            'path': core.PA_CONFIG_FILE
        })

@main_bp.route('/api/fetch-now', methods=['POST'])
def trigger_fetch_now():
    result = core.fetch_pa_dhcp_job(job_type="manual")
    return jsonify(result)

@main_bp.route('/api/latest-status', methods=['GET'])
def get_latest_status():
    return jsonify(core.last_job_info)

@main_bp.route('/api/system-health', methods=['GET'])
def get_system_health():
    try:
        data = core.fetch_pa_health_data()
        return jsonify({'status': 'success', **data})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@main_bp.route('/api/health-history', methods=['GET'])
def get_health_history():
    conn = core.init_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT record_time, mp_cpu, dp_cpu, mem_usage_pct, active_sessions, disk_usage_pct 
        FROM system_health_log 
        ORDER BY id DESC LIMIT 180
    ''')
    rows = cursor.fetchall()
    conn.close()

    history = [{
        'record_time': r[0], 'mp_cpu': r[1], 'dp_cpu': r[2],
        'mem_usage_pct': r[3], 'active_sessions': r[4], 
        'disk_usage_pct': r[5] if len(r) > 5 and r[5] is not None else 0.0
    } for r in reversed(rows)]

    return jsonify({'status': 'success', 'history': history})
    
@main_bp.route('/api/threat-analytics', methods=['GET'])
def get_threat_analytics():
    try:
        log_root = core.fetch_pa_threat_logs(count=150)
        entries = log_root.findall('.//entry')
        today_str = datetime.date.today().isoformat()
        
        conn = core.init_db()
        cursor = conn.cursor()
        cursor.execute("SELECT ip, mac, hostname FROM dhcp_leases WHERE record_date = ?", (today_str,))
        dhcp_map = {r[0]: {'mac': r[1], 'hostname': r[2]} for r in cursor.fetchall()}
        conn.close()

        records, source_counter, threat_counter = [], {}, {}
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

            severity_dist[severity] = severity_dist.get(severity, 0) + 1
            source_counter[src] = source_counter.get(src, 0) + 1
            threat_counter[threat_name] = threat_counter.get(threat_name, 0) + 1

            dhcp_info = dhcp_map.get(src, {})
            records.append({
                'time': log_time, 'src': src, 'hostname': dhcp_info.get('hostname', '-'),
                'mac': dhcp_info.get('mac', '-'), 'is_internal': src in dhcp_map,
                'dst': dst, 'threat_name': threat_name, 'subtype': subtype,
                'severity': severity, 'action': action, 'app': app_name
            })

        top_sources = sorted(source_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        top_sources_data = [{
            'ip': ip, 'count': count,
            'hostname': dhcp_map.get(ip, {}).get('hostname', '外部/非DHCP'),
            'mac': dhcp_map.get(ip, {}).get('mac', '-')
        } for ip, count in top_sources]

        top_threats = sorted(threat_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        top_threats_data = [{'threat_name': name, 'count': count} for name, count in top_threats]

        return jsonify({
            'status': 'success', 'total_threats': len(records),
            'severity_dist': severity_dist, 'top_sources': top_sources_data,
            'top_threats': top_threats_data, 'logs': records[:50]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@main_bp.route('/api/arp-analysis', methods=['GET'])
def get_arp_analysis():
    query_date = request.args.get('date', datetime.date.today().isoformat())
    try:
        arp_root = core.run_pa_command("<show><arp><entry name='all'/></arp></show>")
        arp_entries = arp_root.findall('.//entry')

        conn = core.init_db()
        cursor = conn.cursor()
        cursor.execute("SELECT ip, mac, hostname FROM dhcp_leases WHERE record_date = ?", (query_date,))
        dhcp_records = {row[0]: {'mac': row[1].lower(), 'hostname': row[2]} for row in cursor.fetchall()}
        cursor.execute("SELECT mac, hostname FROM dhcp_leases WHERE hostname != '' AND hostname IS NOT NULL ORDER BY id ASC")
        historical_mac_map = {row[0].lower(): row[1] for row in cursor.fetchall()}
        cursor.execute("SELECT ip, hostname FROM ip_hostname_cache")
        dns_cache_map = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()

        results, uncached_static_ips = [], []
        static_ip_count, normal_dhcp_count, conflict_count = 0, 0, 0

        for entry in arp_entries:
            ip = entry.findtext('ip', default='').strip()
            mac = entry.findtext('mac', default='').strip().lower()
            interface = entry.findtext('interface', default='').strip()
            status = entry.findtext('status', default='').strip()

            if not ip or not mac or mac == '(incomplete)' or status == 'i': continue

            if ip in dhcp_records:
                dhcp_mac = dhcp_records[ip]['mac']
                hostname = dhcp_records[ip]['hostname'] or '(無主機名)'
                if dhcp_mac == mac:
                    dev_type, tag_class = "DHCP 動態配發", "success"
                    normal_dhcp_count += 1
                else:
                    dev_type, tag_class = "⚠️ IP 衝突/MAC變更", "danger"
                    conflict_count += 1
            else:
                dev_type, tag_class = "🚨 私設/固定 IP (Static IP)", "warning"
                static_ip_count += 1

                if ip in dns_cache_map:
                    hostname = f"<span class='text-primary fw-bold'><i class='bi bi-globe me-1'></i>{dns_cache_map[ip]}</span>"
                elif mac in historical_mac_map:
                    hostname = f"<span class='text-secondary'><i class='bi bi-clock-history me-1'></i>{historical_mac_map[mac]} (歷史)</span>"
                    uncached_static_ips.append(ip)
                else:
                    if core.dns_worker_status["is_running"]:
                        hostname = "<span class='text-muted'><div class='spinner-grow spinner-grow-sm text-secondary me-1'></div>解析中...</span>"
                    else:
                        hostname = "<span class='text-muted'>待解析</span>"
                    uncached_static_ips.append(ip)

            results.append({
                'ip': ip, 'mac': mac, 'interface': interface,
                'hostname': hostname, 'dev_type': dev_type, 'tag_class': tag_class
            })

        if uncached_static_ips and not core.dns_worker_status["is_running"]:
            t = threading.Thread(target=core.background_dns_worker, args=(uncached_static_ips,), daemon=True)
            t.start()

        results.sort(key=lambda x: int(ipaddress.IPv4Address(x['ip'])) if x['ip'].replace('.','').isdigit() else 0)

        return jsonify({
            'status': 'success', 'date': query_date, 'total_arp': len(results),
            'static_ip_count': static_ip_count, 'normal_dhcp_count': normal_dhcp_count,
            'conflict_count': conflict_count,
            'dns_progress': core.dns_worker_status, 'data': results
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@main_bp.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': '沒有收到檔案'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': '未選擇檔案'})

    upload_date = request.form.get('record_date', datetime.date.today().isoformat())
    try:
        file_bytes = file.read()
        success, duplicate, multi_lease, unique_ip_count = core.parse_and_insert_xml(file_bytes, record_date=upload_date)
        return jsonify({
            'status': 'success',
            'message': f'檔案已成功匯入至【{upload_date}】！',
            'success_count': success, 'duplicate_count': duplicate,
            'multi_lease_count': multi_lease, 'unique_ip_count': unique_ip_count,
            'record_date': upload_date
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})
        
@main_bp.route('/api/leases', methods=['GET'])
def get_leases():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    query_date = request.args.get('date', datetime.date.today().isoformat())

    conn = core.init_db()
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
        'ip': row[0], 'mac': row[1], 'hostname': row[2], 'state': row[3],
        'duration': row[4], 'leasetime': row[5], 'record_date': row[6]
    } for row in rows]

    return jsonify({
        'data': data, 'current_page': page, 'total_pages': total_pages,
        'total_records': total_records, 'selected_date': query_date
    })