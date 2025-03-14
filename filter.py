import time
import os
import sqlite3
import threading
import re
import subprocess
import requests
from flask import Flask, request, jsonify, render_template
from scapy.all import sniff, IP, TCP, Raw
from mitmproxy import http
import platform

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'filter_rules.db')
os_name = platform.system()

def get_db_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS filters (
                        id INTEGER PRIMARY KEY,
                        type TEXT,
                        value TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY,
                        src_ip TEXT,
                        dst_ip TEXT,
                        action TEXT,
                        reason TEXT)''')
        conn.commit()

def add_filter(filter_type, value):
    with get_db_connection() as conn:
        conn.execute('INSERT INTO filters (type, value) VALUES (?, ?)', (filter_type, value))
        conn.commit()

def get_filters():
    with get_db_connection() as conn:
        return conn.execute('SELECT * FROM filters').fetchall()

def log_action(src_ip, dst_ip, action, reason):
    with get_db_connection() as conn:
        conn.execute('INSERT INTO logs (src_ip, dst_ip, action, reason) VALUES (?, ?, ?, ?)', (src_ip, dst_ip, action, reason))
        conn.commit()

def check_external_threat(ip):
    try:
        response = requests.get(f'https://api.abuseipdb.com/api/v2/check', headers={
            'Key': 'YOUR_API_KEY_HERE',
            'Accept': 'application/json'
        }, params={'ipAddress': ip})
        data = response.json()
        return data['data']['abuseConfidenceScore'] > 80
    except Exception as e:
        #print(f"Error checking external threat: {e}")
        pass
    return False

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        payload = packet[Raw].load.decode('utf-8', errors='ignore') if packet.haslayer(Raw) else "No payload"

        for rule_type, value in [(r[1], r[2]) for r in get_filters()]:
            if (rule_type == 'url' and value in payload) or \
               (rule_type == 'keyword' and re.search(value, payload, re.IGNORECASE)) or \
               (rule_type == 'filetype' and value in payload) or \
               (rule_type == 'ip' and src_ip == value):

                log_action(src_ip, dst_ip, 'BLOCKED', f'{rule_type}: {value}')
                return

        threading.Thread(target=lambda: check_external_threat(src_ip)).start()

        if "HTTP" in payload:
            http_lines = payload.split('\r\n')
            for line in http_lines:
                if line.startswith("GET") or line.startswith("POST"):
                    log_action(src_ip, dst_ip, 'ALLOWED', f'HTTP: {line}')
                    break
        else:
            log_action(src_ip, dst_ip, 'ALLOWED', f'Payload: {payload[:50]}')

def setup_iptables(block_ip):
    if os_name == "Linux":
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", block_ip, "-j", "DROP"], check=True)
    elif os_name == 'Windows':
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                        "name=BlockIP", "dir=in", "action=block", f"remoteip={block_ip}"], check=True)

def start_sniffing():
    print("Starting packet inspection...")
    sniff(prn=packet_callback, store=0)

class ContentFilterAddon:
    def __init__(self):
        self.rules = get_filters()

    def request(self, flow: http.HTTPFlow):
        # Get the full URL
        full_url = flow.request.pretty_url

        # Check URL against filters
        for rule_type, value in [(r[1], r[2]) for r in self.rules]:
            if rule_type == 'url' and value.lower() in full_url.lower():
                print(f"Blocking request to {full_url} (URL filter: {value})")
                flow.response = http.Response.make(403, b"Blocked by Content Filter")
                log_action(flow.client_conn.address[0], flow.request.host, 'BLOCKED', f'URL: {value}')
                return

        # Check for keywords in the request body (if applicable)
        if flow.request.content:
            request_body = flow.request.content.decode('utf-8', errors='ignore')
            for rule_type, value in [(r[1], r[2]) for r in self.rules]:
                if rule_type == 'keyword' and value.lower() in request_body.lower():
                    print(f"Blocking request to {full_url} (Keyword filter: {value})")
                    flow.response = http.Response.make(403, b"Blocked by Content Filter")
                    log_action(flow.client_conn.address[0], flow.request.host, 'BLOCKED', f'Keyword: {value}')
                    return

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/add_filter', methods=['POST'])
def api_add_filter():
    data = request.get_json()
    add_filter(data['type'], data['value'])
    return jsonify({'message': 'Filter added successfully'}), 201

@app.route('/filters', methods=['GET'])
def api_get_filters():
    return jsonify(get_filters()), 200

@app.route('/logs', methods=['GET'])
def api_get_logs():
    with get_db_connection() as conn:
        logs = conn.execute('SELECT * FROM logs').fetchall()
    return jsonify(logs), 200

if __name__ == '__main__':
    init_db()

    filters = [
        ('url', 'malicious.com'),
        ('url', 'jailbreak.com'),
        ('keyword', 'jailbreak'),
        ('filetype', '.exe'),
        ('ip', '192.168.1.100')
    ]
    for f_type, f_value in filters:
        add_filter(f_type, f_value)

    setup_iptables('192.168.1.100')

    threading.Thread(target=start_sniffing).start()

    subprocess.Popen(["mitmdump", "-s", __file__])

    app.run(host='0.0.0.0', port=5000)
