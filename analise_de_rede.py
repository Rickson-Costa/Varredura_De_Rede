import os
import time
from scapy.all import ARP, Ether, srp
import threading
import json

# Função para realizar a varredura na rede
def scan_network(ip_range):
    devices = {}
    try:
        # Cria um pacote ARP para todos os IPs no intervalo
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        # Envia o pacote e captura as respostas
        answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]

        # Preenche o dicionário de dispositivos
        for element in answered_list:
            devices[element[1].psrc] = element[1].hwsrc  # IP -> MAC
    except Exception as e:
        print(f"Erro ao escanear a rede: {e}")
    return devices

# Função para salvar o histórico em um arquivo
def save_to_file(data, filename="network_history.json"):
    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"Erro ao salvar o histórico: {e}")

# Função para carregar o histórico de um arquivo
def load_from_file(filename="network_history.json"):
    try:
        if os.path.exists(filename):
            with open(filename, "r") as file:
                return json.load(file)
    except Exception as e:
        print(f"Erro ao carregar o histórico: {e}")
    return {}

# Função para monitorar mudanças na rede
def monitor_network(ip_range, interval=10):
    known_devices = load_from_file()

    while True:
        print("\nRealizando varredura na rede...")
        current_devices = scan_network(ip_range)

        # Detecta novos dispositivos
        new_devices = {ip: mac for ip, mac in current_devices.items() if ip not in known_devices}

        # Detecta dispositivos que saíram
        lost_devices = {ip: mac for ip, mac in known_devices.items() if ip not in current_devices}

        # Exibe mensagens de aviso
        for ip, mac in new_devices.items():
            print(f"[NOVO] Dispositivo conectado: IP {ip}, MAC {mac}")

        for ip, mac in lost_devices.items():
            print(f"[PERDIDO] Dispositivo desconectado: IP {ip}, MAC {mac}")

        # Atualiza o estado conhecido
        known_devices.update(new_devices)
        for ip in lost_devices.keys():
            known_devices.pop(ip, None)

        # Salva o estado atualizado
        save_to_file(known_devices)

        # Aguarda pelo próximo ciclo
        time.sleep(interval)

if __name__ == "__main__":
    # Substitua pelo intervalo de IPs da sua rede local, por exemplo, "192.168.1.0/24"
    ip_range = "10.0.0.0/22"

    # Intervalo de varredura em segundos
    scan_interval = 15

    # Inicia a monitoria em uma thread separada
    monitor_thread = threading.Thread(target=monitor_network, args=(ip_range, scan_interval), daemon=True)
    monitor_thread.start()

    # Mantenha o programa em execução
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado.")
