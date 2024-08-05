from scapy.all import sr1, send
from scapy.layers.inet import IP, TCP, ICMP

def scan(target):
    print("Iniciando escaneo SYN...")
    scan_results = []

    for port in range(1, 65535):  # Cambia esto para escanear todos los puertos (1-65535)
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        
        if resp is None:
            # No hay respuesta, puede estar filtrado o el paquete se perdió
            scan_results.append({"port": port, "state": "filtered or no response"})
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                # Puerto abierto
                scan_results.append({"port": port, "state": "open"})
                # Envía un paquete RST para cerrar la conexión
                send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
            elif resp.getlayer(TCP).flags == 0x14:  # RST
                # Puerto cerrado
                scan_results.append({"port": port, "state": "closed"})
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                # Puerto filtrado
                scan_results.append({"port": port, "state": "filtered"})

    return scan_results

