import os
import time
import threading
import json
from scapy.all import ARP, Ether, srp
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Função para realizar a varredura na rede
def scan_network(ip_range):
    devices = {}
    try:
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]

        for element in answered_list:
            devices[element[1].psrc] = element[1].hwsrc
    except Exception as e:
        print(f"Erro ao escanear a rede: {e}")
    return devices

# Função para salvar o histórico em um arquivo
def save_to_file(data, filename):
    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"Erro ao salvar o histórico: {e}")

# Função para carregar o histórico de um arquivo
def load_from_file(filename):
    try:
        if os.path.exists(filename):
            with open(filename, "r") as file:
                return json.load(file)
    except Exception as e:
        print(f"Erro ao carregar o histórico: {e}")
    return [] if filename == "timeline.json" else {}

# Monitoramento da rede
def monitor_network(ip_range, interval=10):
    known_devices = load_from_file("known_devices.json")
    disconnect_count = load_from_file("disconnect_count.json")
    timeline = load_from_file("timeline.json")

    while True:
        current_devices = scan_network(ip_range)

        # Detecta novos dispositivos
        new_devices = {ip: mac for ip, mac in current_devices.items() if ip not in known_devices}
        for ip, mac in new_devices.items():
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            timeline.append({"ip": ip, "mac": mac, "timestamp": timestamp})

        # Detecta dispositivos que saíram
        lost_devices = {ip: mac for ip, mac in known_devices.items() if ip not in current_devices}
        for ip in lost_devices.keys():
            disconnect_count[ip] = disconnect_count.get(ip, 0) + 1

        # Atualiza o estado conhecido
        known_devices.update(new_devices)
        for ip in lost_devices.keys():
            known_devices.pop(ip, None)

        # Salva os estados atualizados
        save_to_file(known_devices, "known_devices.json")
        save_to_file(disconnect_count, "disconnect_count.json")
        save_to_file(timeline, "timeline.json")

        time.sleep(interval)

# Rota para a página principal
@app.route("/")
def index():
    return render_template("index.html")

# Rota para obter os dados de desconexões
@app.route("/disconnect_data")
def disconnect_data():
    disconnect_count = load_from_file("disconnect_count.json")
    labels = list(disconnect_count.keys())
    counts = list(disconnect_count.values())
    return jsonify({"labels": labels, "data": counts})


# Rota para obter a linha do tempo
@app.route("/timeline_data")
def timeline_data():
    timeline = load_from_file("timeline.json")
    return jsonify(timeline)

if __name__ == "__main__":
    ip_range = "10.0.0.0/22"
    scan_interval = 15

    monitor_thread = threading.Thread(target=monitor_network, args=(ip_range, scan_interval), daemon=True)
    monitor_thread.start()

    app.run(debug=True, host="0.0.0.0", port=5000)
