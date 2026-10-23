import sys
import os
from flask import Flask
from apscheduler.schedulers.background import BackgroundScheduler
import apscheduler.triggers.cron
import apscheduler.triggers.interval

# 1. 匯入核心邏輯 (core.py)
import core

# 2. 匯入 Web 路由 Blueprint (routes.py)
from routes import main_bp

# -------------------------------------------------------------
# 系統與 Flask 應用程式初始化
# -------------------------------------------------------------
if getattr(sys, 'frozen', False):
    base_dir = sys._MEIPASS
    template_folder = os.path.join(base_dir, 'templates')
    app = Flask(__name__, template_folder=template_folder)
else:
    app = Flask(__name__)

# 3. 註冊 Blueprint 路由
app.register_blueprint(main_bp)

# -------------------------------------------------------------
# 程式進入點與背景排程器啟動
# -------------------------------------------------------------
if __name__ == '__main__':
    # 檢查設定檔防呆機制
    core.ensure_pa_config_template()
    try:
        core.get_pa_config()
        core.log_system_health_job()
    except Exception as e:
        print(f"[啟動提示] {e}")

    # 啟動排程器 (使用核心層 core.py 的函數)
    scheduler = BackgroundScheduler(timezone="Asia/Taipei")
    scheduler.add_job(core.fetch_pa_dhcp_job, args=['auto'], trigger='cron', hour='1,5,9,13,17,21', minute=0)
    scheduler.add_job(core.log_system_health_job, trigger='interval', minutes=1)
    scheduler.start()

    print("[系統狀態] PA-1420 監控與 API 路由伺服器啟動中...")
    
    # 啟動 Web 伺服器
    app.run(host='0.0.0.0', port=5006, debug=True, use_reloader=False)