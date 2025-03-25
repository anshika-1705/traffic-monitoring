from flask import Flask, jsonify, render_template
from scapy.all import sniff, IP
import threading
import time

app = Flask(__name__)

# Store network data
network_data = {'devices': {}, 'bandwidth': 0}

# Lock for thread safety
lock = threading.Lock()

# Function to capture network traffic
def capture_traffic():
    def packet_handler(packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                size = len(packet)

                # Update data safely with a lock
                with lock:
                    network_data['bandwidth'] += size
                    if src_ip not in network_data['devices']:
                        network_data['devices'][src_ip] = {'packets': 0, 'size': 0}
                    network_data['devices'][src_ip]['packets'] += 1
                    network_data['devices'][src_ip]['size'] += size
        except Exception as e:
            print(f"Error handling packet: {e}")

    sniff(prn=packet_handler, store=False)

# Start traffic capture in a background thread
thread = threading.Thread(target=capture_traffic)
thread.daemon = True
thread.start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def get_data():
    with lock:
        return jsonify(network_data)

# Reset bandwidth periodically
def reset_bandwidth():
    while True:
        time.sleep(5)
        with lock:
            network_data['bandwidth'] = 0

# Start reset thread
reset_thread = threading.Thread(target=reset_bandwidth)
reset_thread.daemon = True
reset_thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
