import pyinotify
import re
import requests
import os
import argparse
from datetime import datetime

# 正则表达式匹配 SSH 登录成功和失败
LOG_PATTERN_SUCCESS = re.compile(r'^(\w{3} \d{2} \d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Accepted (\w+) for (\w+) from ([\d\.]+)')
LOG_PATTERN_FAILURE = re.compile(r'^(\w{3} \d{2} \d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed (\w+) for (\w+) from ([\d\.]+)')
LOG_PATTERN_SUCCESS_ISO = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+[\+\-]\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+Accepted (\w+) for (\w+) from ([\d\.]+)')
LOG_PATTERN_FAILURE_ISO = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+[\+\-]\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+Failed (\w+) for (\w+) from ([\d\.]+)')

# IP 缓存
ip_cache = {}

def get_ip_info(ip):
    """获取 IP 地理位置信息并缓存"""
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?lang=zh-cn", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                ip_cache[ip] = f"{data['country']}->{data['regionName']}"
                return ip_cache[ip]
    except requests.RequestException:
        pass
    ip_cache[ip] = "unknown"
    return "unknown"

def send_alert(event_type, logintype, username, ip, timestamp, line, webhook_token):
    """发送 WeChat 警报"""
    if event_type not in ('login_success', 'login_failure'):
        return

    # 根据事件类型动态设置颜色和图标
    status_color = "info" if event_type == 'login_success' else "warning"
    status_icon = "✅ Accepted" if event_type == 'login_success' else "🚨 Failed"

    # 合并后的 payload
    payload = {
        "msgtype": "markdown",
        "markdown": {
            "content": (
                f"# **【WARNING】**<font color=\"critical\">**Login**</font>\n"
                f"<font color=\"{status_color}\">{status_icon} {logintype} alerts</font>\n"
                f"> <font color=\"comment\">User</font>: <font color=\"critical\">{username}</font>\n"
                f"> <font color=\"comment\">Address</font>: <font color=\"warning\">{ip}</font>\n"
                f"> <font color=\"comment\">City</font>: <font color=\"warning\">{get_ip_info(ip)}</font>\n"
                f"> <font color=\"comment\">Content</font>: <font color=\"critical\">{line}</font>"
            )
        }
    }

    try:
        response = requests.post(f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={webhook_token}", json=payload, timeout=5)
        print(f"Alert {'sent' if response.status_code == 200 else 'failed'}: {event_type} - {username} from {ip} at {timestamp}")
    except requests.RequestException as e:
        print(f"Error sending alert: {e}")

def process_line(line, webhook_token):
    """处理日志行并触发警报"""
    current_time = datetime.now().timestamp() - 60  # 最近 1 分钟
    patterns = [
        ('login_success', LOG_PATTERN_SUCCESS),
        ('login_failure', LOG_PATTERN_FAILURE),
        ('login_success', LOG_PATTERN_SUCCESS_ISO),
        ('login_failure', LOG_PATTERN_FAILURE_ISO)
    ]
    for event_type, pattern in patterns:
        match = pattern.search(line)
        if match:
            timestamp, logintype, username, ip = match.groups()
            try:
                if pattern in (LOG_PATTERN_SUCCESS, LOG_PATTERN_FAILURE):
                    dt = datetime.strptime(f"{datetime.now().year} {timestamp}", "%Y %b %d %H:%M:%S")
                else:
                    dt = datetime.strptime(timestamp.split('.')[0], "%Y-%m-%dT%H:%M:%S")
                if dt.timestamp() > current_time:
                    send_alert(event_type, logintype, username, ip, timestamp, line, webhook_token)
            except ValueError:
                print(f"Invalid timestamp in line: {line}")
            break

class LogWatcher(pyinotify.ProcessEvent):
    """监控日志文件修改"""
    def __init__(self, log_file, webhook_token):
        self.log_file = log_file
        self.webhook_token = webhook_token
        self.file = None
        self.last_position = 0
        self.open_file()

    def open_file(self):
        """打开或重新打开日志文件"""
        if self.file is not None:
            self.file.close()
        try:
            self.file = open(self.log_file, 'r')
            self.file.seek(self.last_position)
            print(f"Opened log file: {self.log_file}")
        except FileNotFoundError:
            print(f"Log file {self.log_file} not found, waiting for creation...")
            self.file = None

    def process_IN_MODIFY(self, event):
        """处理文件修改事件"""
        if self.file is None:
            self.open_file()
            return

        try:
            current_position = self.file.tell()
            if not os.path.exists(self.log_file) or current_position < self.last_position:
                print(f"Log file {self.log_file} deleted or rotated, reopening...")
                self.open_file()
                return

            self.file.seek(self.last_position)
            for line in self.file:
                process_line(line.strip(), self.webhook_token)
            self.last_position = self.file.tell()
        except Exception as e:
            print(f"Error processing log file: {e}")
            self.open_file()  # 在错误情况下尝试重新打开

    def process_IN_CREATE(self, event):
        """处理文件创建事件"""
        if event.pathname == self.log_file:
            print(f"Log file {self.log_file} created, initializing...")
            self.open_file()

def main():
    """主函数，设置日志监控"""
    parser = argparse.ArgumentParser(description='监控 SSH 日志文件')
    parser.add_argument('log_file', help='日志文件路径')
    parser.add_argument('webhook_token', help='WeChat Webhook 令牌')
    args = parser.parse_args()

    wm = pyinotify.WatchManager()
    handler = LogWatcher(args.log_file, args.webhook_token)
    notifier = pyinotify.Notifier(wm, handler)

    # 监控文件修改和创建事件
    wm.add_watch(os.path.dirname(args.log_file) or '.', pyinotify.IN_MODIFY | pyinotify.IN_CREATE, rec=True)
    print(f"Starting monitoring {args.log_file}...")

    notifier.loop()

if __name__ == "__main__":
    main()