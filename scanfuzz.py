#!/usr/bin/env python3

from scapy.all import IP, TCP, sr1
import argparse
import socket
from colorama import Fore, Style, init
import json
import aiohttp
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Escaneo sigiloso con SYN (Half-Open Scan)
def escanear_puerto_syn(host, puerto, timeout=1):
    paquete = IP(dst=host) / TCP(dport=puerto, flags="S")  # Enviar SYN
    respuesta = sr1(paquete, timeout=timeout, verbose=0)  # Esperar respuesta

    if respuesta and respuesta.haslayer(TCP):
        if respuesta.getlayer(TCP).flags == 0x12:  # SYN-ACK recibido (puerto abierto)
            return puerto
    return None

def obtener_os(host):
    # Enviar un paquete TCP SYN
    paquete = IP(dst=host) / TCP(dport=80, flags="S")
    respuesta = sr1(paquete, timeout=2, verbose=0)

    if respuesta and respuesta.haslayer(TCP):
        ttl = respuesta[IP].ttl
        window_size = respuesta[TCP].window

        if ttl <= 64:
            return "Linux"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Desconocido"
    return "No se pudo detectar el OS"

def obtener_servicio(puerto):
    try:
        return socket.getservbyport(puerto)
    except OSError:
        return "Desconocido"

def escanear_puertos_syn(host, puertos, max_threads=50):
    print(Fore.CYAN + f"[*] Escaneando puertos sigilosamente en {host}..." + Style.RESET_ALL)
    abiertos = []
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = executor.map(lambda p: escanear_puerto_syn(host, p), puertos)

    for puerto in results:
        if puerto:
            servicio = obtener_servicio(puerto)
            print(Fore.GREEN + f"[+] Puerto abierto: {puerto} ({servicio})" + Style.RESET_ALL)
            abiertos.append(puerto)
    
    return abiertos

# Fuzzing asíncrono de directorios
async def fuzzear_directorio(session, url, palabra):
    if not palabra or palabra.startswith("#"):  # Evitar comentarios y líneas vacías
        return None
    full_url = f"{url}/{palabra}"
    try:
        async with session.get(full_url) as response:
            if response.status != 404:
                print(f"[+] {full_url} - Código: {response.status}")
                return {"url": full_url, "status": response.status}
    except Exception:
        return None
    return None

async def fuzzing(url, wordlist, max_concurrent=20):
    print(f"[*] Fuzzing en {url}")
    encontrados = []
    connector = aiohttp.TCPConnector(limit_per_host=max_concurrent)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fuzzear_directorio(session, url, palabra.strip()) for palabra in wordlist]
        results = await asyncio.gather(*tasks)
    for res in results:
        if res:
            encontrados.append(res)
    return encontrados

def guardar_resultados(host, puertos_abiertos, fuzz_results):
    data = {
        "host": host,
        "puertos_abiertos": puertos_abiertos,
        "fuzzing": fuzz_results
    }
    with open(f"{host}_resultados.json", "w") as f:
        json.dump(data, f, indent=4)
    print(f"[*] Resultados guardados en {host}_resultados.json")

import signal

def signal_handler(sig, frame):
    print("[!] Saliendo...")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

def main():
    parser = argparse.ArgumentParser(description="Escáner de puertos sigiloso y fuzzing para CTFs")
    parser.add_argument("host", help="IP o dominio a escanear")
    parser.add_argument("-p", "--puertos", type=str, default="80,443,22,21,8080,3306", help="Lista de puertos a escanear o -p- para todos los puertos")
    parser.add_argument("-w", "--wordlist", type=str, default="wordlist.txt", help="Lista de palabras para fuzzing")
    args = parser.parse_args()

    if args.puertos == "-":
        args.puertos = list(range(1, 65536))  # Escanear todos los puertos
    else:
        args.puertos = [int(p) for p in args.puertos.split(",")]

    init(autoreset=True)  # Inicializar colorama

    puertos_abiertos = escanear_puertos_syn(args.host, args.puertos)

    # Detectar el sistema operativo
    os_detectado = obtener_os(args.host)
    print(Fore.YELLOW + f"[*] Sistema operativo detectado: {os_detectado}" + Style.RESET_ALL)

    fuzz_results = []
    if 80 in puertos_abiertos or 443 in puertos_abiertos:
        url = f"https://{args.host}" if 443 in puertos_abiertos else f"http://{args.host}"
        try:
            with open(args.wordlist, "r", encoding="ISO-8859-1") as f:
                wordlist = f.readlines()
            fuzz_results = asyncio.run(fuzzing(url, wordlist))
        except FileNotFoundError:
            print("[!] No se encontró el archivo de wordlist.")

    guardar_resultados(args.host, puertos_abiertos, fuzz_results)

if __name__ == "__main__":
    main()
