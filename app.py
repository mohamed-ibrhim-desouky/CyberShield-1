from flask import Flask, render_template
from flask_socketio import SocketIO
import socket
import eventlet
from datetime import datetime

eventlet.monkey_patch()

app = Flask(__name__)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet"
)

# =========================
# STATE
# =========================
state = {
    "blocked_ips": {'127.0.0.2', '192.168.1.100'},
    "stats": {
        "total": 0,
        "accepted": 0,
        "blocked": 0
    }
}

# =========================
# CONNECT
# =========================
@socketio.on('connect')
def handle_connect():
    print("[+] Dashboard Connected")
    socketio.emit('update_blacklist', list(state["blocked_ips"]))
    socketio.emit('update_stats', state["stats"])

# =========================
# BLOCK IP
# =========================
@socketio.on('block_ip_request')
def handle_block(data):
    ip = data.get('ip')
    if ip:
        state["blocked_ips"].add(ip)
        socketio.emit('update_blacklist', list(state["blocked_ips"]))
        socketio.emit('new_log', {
            'type': 'SYSTEM',
            'ip': 'FIREWALL',
            'msg': f'IP {ip} added to blacklist manually',
            'time': datetime.now().strftime("%H:%M:%S")
        })

# =========================
# UNBLOCK IP
# =========================
@socketio.on('unblock_ip_request')
def handle_unblock(data):
    ip = data.get('ip')
    if ip and ip in state["blocked_ips"]:
        state["blocked_ips"].discard(ip)
        socketio.emit('update_blacklist', list(state["blocked_ips"]))
        socketio.emit('new_log', {
            'type': 'SYSTEM',
            'ip': 'FIREWALL',
            'msg': f'IP {ip} removed from blacklist',
            'time': datetime.now().strftime("%H:%M:%S")
        })

# =========================
# SMTP SERVER LOGIC
# =========================
def smtp_server_logic():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 9999))
    server.listen(5)

    print("[+] SMTP Server Running On Port 9999")

    while True:
        client, addr = server.accept()
        ip = addr[0]
        state["stats"]["total"] += 1
        socketio.emit('update_stats', state["stats"])

        if ip in state["blocked_ips"]:
            state["stats"]["blocked"] += 1
            socketio.emit('update_stats', state["stats"])
            socketio.emit('new_log', {
                'type': 'BLOCKED',
                'ip': ip,
                'msg': f'Connection blocked from {ip}',
                'time': datetime.now().strftime("%H:%M:%S")
            })
            client.send(b"554 Blocked by CyberShield Firewall\n")
            client.close()
            continue

        state["stats"]["accepted"] += 1
        socketio.emit('update_stats', state["stats"])
        socketio.emit('new_log', {
            'type': 'SUCCESS',
            'ip': ip,
            'msg': f'Connection established with {ip}',
            'time': datetime.now().strftime("%H:%M:%S")
        })

        try:
            client.send(b"220 CyberShield SMTP Ready\n")

            while True:
                data = client.recv(1024).decode(errors="ignore").strip()

                if not data or data.upper() == "QUIT":
                    break

                socketio.emit('new_log', {
                    'type': 'DATA',
                    'ip': ip,
                    'msg': f"CMD: {data.replace('<', '&lt;').replace('>', '&gt;')}",  # ← التعديل هنا
                    'time': datetime.now().strftime("%H:%M:%S")
                })

                client.send(b"250 OK\n")

        except Exception as e:
            print(f"Error handling {ip}: {e}")
            socketio.emit('new_log', {
                'type': 'SYSTEM',
                'ip': 'SERVER',
                'msg': f'Error: {str(e)}',
                'time': datetime.now().strftime("%H:%M:%S")
            })
        finally:
            client.close()
            socketio.emit('new_log', {
                'type': 'CLOSED',
                'ip': ip,
                'msg': f'Session closed for {ip}',
                'time': datetime.now().strftime("%H:%M:%S")
            })

# =========================
# ROUTES
# =========================
@app.route('/')
def index():
    return render_template('cyber-smtp.html')

# =========================
# START
# =========================
if __name__ == '__main__':
    socketio.start_background_task(smtp_server_logic)
    print("[+] Running Dashboard on http://127.0.0.1:5000")
    socketio.run(
        app,
        host='127.0.0.1',
        port=5000,
        debug=False
    )