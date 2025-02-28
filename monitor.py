import pyinotify
import re
import requests
import time
import datetime
import argparse

# Regular expressions for SSH login success and failure
LOG_PATTERN_SUCCESS = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+[\+\-]\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+Accepted (\w+) for (\w+) from ([\d\.]+)')
LOG_PATTERN_FAILURE = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+[\+\-]\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+Failed (\w+) for (\w+) from ([\d\.]+)')

# IP cache to store geolocation data
ip_cache = {}

def get_ip_info(ip):
    """Fetch IP geolocation info and cache the result."""
    if ip in ip_cache:
        return ip_cache[ip]

    url = f"http://ip-api.com/json/{ip}?lang=zh-cn"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                result = f"{data['country']}->{data['city']}"
                ip_cache[ip] = result
                return result
    except requests.RequestException as e:
        print(f"Error fetching IP info for {ip}: {e}")
    result = "unknown"
    ip_cache[ip] = result
    return result

def send_alert(event_type, logintype, username, ip, timestamp, line, webhook_token):
    """Send an alert to WeChat API based on login event type."""
    if event_type == 'login_success':
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "content": f"# **【WARNING】**<font color=\"critical\">**Login**</font>\n"
                           f"<font color=\"info\">✅ Accepted {logintype} alerts</font>\n"
                           f"> <font color=\"comment\">User</font>: <font color=\"critical\">{username}</font>\n"
                           f"> <font color=\"comment\">Address</font>: <font color=\"warning\">{ip}</font>\n"
                           f"> <font color=\"comment\">City</font>: <font color=\"warning\">{get_ip_info(ip)}</font>\n"
                           f"> <font color=\"comment\">Content</font>: <font color=\"critical\">{line}</font>"
            }
        }
    elif event_type == 'login_failure':
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "content": f"# **【WARNING】**<font color=\"critical\">**Login**</font>\n"
                           f"<font color=\"warning\">🚨 Failed {logintype} alerts</font>\n"
                           f"> <font color=\"comment\">User</font>: <font color=\"critical\">{username}</font>\n"
                           f"> <font color=\"comment\">Address</font>: <font color=\"warning\">{ip}</font>\n"
                           f"> <font color=\"comment\">City</font>: <font color=\"warning\">{get_ip_info(ip)}</font>\n"
                           f"> <font color=\"comment\">Content</font>: <font color=\"critical\">{line}</font>"
            }
        }
    else:
        return

    try:
        response = requests.post(f'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={webhook_token}', json=payload, timeout=5)
        if response.status_code == 200:
            print(f"Alert sent: {event_type} - {username} from {ip} at {timestamp}")
        else:
            print(f"Alert failed: {response.status_code} - {response.text}")
    except requests.RequestException as e:
        print(f"Error sending alert: {e}")

def process_line(line, webhook_token):
    """Process a log line and trigger alerts for recent events."""
    current_time = time.time()
    dt = datetime.datetime.fromtimestamp(current_time - 60)
    formatted_time = dt.strftime("%Y-%m-%dT%H:%M:%S")  # Time 1 minute ago

    try:
        match_success = LOG_PATTERN_SUCCESS.search(line)
        match_failure = LOG_PATTERN_FAILURE.search(line)

        if match_success:
            timestamp, logintype, username, ip = match_success.groups()
            # String comparison works because formats match (e.g., "2023-10-10T12:00:00")
            if formatted_time < timestamp:
                send_alert('login_success', logintype, username, ip, timestamp, line, webhook_token)
        elif match_failure:
            timestamp, logintype, username, ip = match_failure.groups()
            if formatted_time < timestamp:
                send_alert('login_failure', logintype, username, ip, timestamp, line, webhook_token)
    except Exception as e:
        print(f"Error processing line '{line}': {e}")

class LogWatcher(pyinotify.ProcessEvent):
    """Monitor log file modifications and process new entries."""
    def __init__(self, log_file, webhook_token):
        self.log_file = log_file
        self.webhook_token = webhook_token
        self.file = open(log_file, 'r')
        self.last_position = self.file.tell()

    def process_IN_MODIFY(self, event):
        """Handle file modification events."""
        try:
            current_position = self.file.tell()
            # Check for log rotation (file size decreased)
            if current_position < self.last_position:
                self.file.close()
                self.file = open(self.log_file, 'r')
                self.last_position = 0

            self.file.seek(self.last_position)
            for line in self.file:
                process_line(line.strip(), self.webhook_token)
            self.last_position = self.file.tell()
        except Exception as e:
            print(f"Error reading log file: {e}")

def main():
    """Set up log file monitoring and start the event loop."""
    parser = argparse.ArgumentParser(description='Monitor a log file for login events')
    parser.add_argument('log_file', type=str, help='Path to the log file')
    parser.add_argument('webhook_token', type=str, help='Webhook token for WeChat API')
    args = parser.parse_args()

    wm = pyinotify.WatchManager()
    handler = LogWatcher(args.log_file, args.webhook_token)
    notifier = pyinotify.Notifier(wm, handler)
    wm.add_watch(args.log_file, pyinotify.IN_MODIFY)
    print(f"Starting monitoring {args.log_file}...")

    # Start the event loop
    notifier.loop()

if __name__ == '__main__':
    main()
