#!/usr/bin/env python3

from scapy.all import IP, TCP, sr1
import argparse
import socket
from colorama import Fore, Style, init
import json
import aiohttp
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import psutil
import signal
import sys

# Inicializar colorama
init(autoreset=True)

# Variables globales para el temporizador
start_time = time.time()

# Función para calcular el tiempo transcurrido
def tiempo_transcurrido():
    elapsed = time.time() - start_time
    return f"[Tiempo: {elapsed:.2f}s]"

# Monitorear el uso de recursos del sistema
def monitorear_recursos():
    cpu_usage = psutil.cpu_percent(interval=0.1)
    memory_usage = psutil.virtual_memory().percent
    return f"[CPU: {cpu_usage}%, Memoria: {memory_usage}%]"

# Escaneo sigiloso con SYN (Half-Open Scan)
def escanear_puerto_syn(host, puerto, timeout=1, delay=0):
    time.sleep(delay)  # Introducir retraso
    paquete = IP(dst=host) / TCP(dport=puerto, flags="S")  # Enviar SYN
    respuesta = sr1(paquete, timeout=timeout, verbose=0)  # Esperar respuesta

    if respuesta and respuesta.haslayer(TCP):
        if respuesta.getlayer(TCP).flags == 0x12:  # SYN-ACK recibido (puerto abierto)
            return puerto
    return None

# Detección del sistema operativo
def obtener_os(host):
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

# Obtener el servicio asociado a un puerto
def obtener_servicio(puerto):
    try:
        return socket.getservbyport(puerto)
    except OSError:
        return "Desconocido"

# Escaneo de puertos con control de hilos y retraso
def escanear_puertos_syn(host, puertos, max_threads=10, delay=0):
    print(Fore.CYAN + "\n[*] Iniciando escaneo de puertos sigiloso..." + Style.RESET_ALL)
    abiertos = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(escanear_puerto_syn, host, puerto, 1, delay): puerto for puerto in puertos}

        for future in as_completed(futures):
            puerto = futures[future]
            try:
                resultado = future.result()
                if resultado:
                    servicio = obtener_servicio(resultado)
                    print(Fore.GREEN + f"[+] Puerto abierto: {resultado} ({servicio})" + Style.RESET_ALL)
                    abiertos.append(resultado)
            except Exception as e:
                print(Fore.RED + f"[-] Error al escanear el puerto {puerto}: {e}" + Style.RESET_ALL)

    print(Fore.CYAN + "\n[*] Escaneo de puertos completado." + Style.RESET_ALL)
    print(Fore.YELLOW + f"{tiempo_transcurrido()} {monitorear_recursos()}" + Style.RESET_ALL)
    return abiertos

# Fuzzing asíncrono de directorios
async def fuzzear_directorio(session, url, palabra, delay=0, timeout=5):
    if not palabra or palabra.startswith("#"):  # Evitar comentarios y líneas vacías
        return None
    full_url = f"{url}/{palabra}"
    try:
        await asyncio.sleep(delay)  # Introducir retraso
        async with session.get(full_url, timeout=timeout) as response:
            if response.status != 404:
                print(Fore.GREEN + f"[+] {full_url} - Código: {response.status}" + Style.RESET_ALL)
                return {"url": full_url, "status": response.status}
    except asyncio.TimeoutError:
        print(Fore.RED + f"[-] Timeout en {full_url}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Error en {full_url}: {e}" + Style.RESET_ALL)
    return None

async def fuzzing(url, wordlist, max_concurrent=20, delay=0, block_size=100):
    print(Fore.CYAN + "\n[*] Iniciando fuzzing de directorios..." + Style.RESET_ALL)
    encontrados = []
    connector = aiohttp.TCPConnector(limit_per_host=max_concurrent)

    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, len(wordlist), block_size):
            block = wordlist[i:i + block_size]
            tasks = [fuzzear_directorio(session, url, palabra.strip(), delay) for palabra in block]
            results = await asyncio.gather(*tasks)
            for res in results:
                if res:
                    encontrados.append(res)

    print(Fore.CYAN + "\n[*] Fuzzing completado." + Style.RESET_ALL)
    print(Fore.YELLOW + f"{tiempo_transcurrido()} {monitorear_recursos()}" + Style.RESET_ALL)
    return encontrados

# Guardar resultados en un archivo JSON
def guardar_resultados(host, puertos_abiertos, fuzz_results):
    data = {
        "host": host,
        "puertos_abiertos": puertos_abiertos,
        "fuzzing": fuzz_results
    }
    with open(f"{host}_resultados.json", "w") as f:
        json.dump(data, f, indent=4)
    print(Fore.CYAN + f"\n[*] Resultados guardados en {host}_resultados.json" + Style.RESET_ALL)

# Manejar la señal de interrupción (Ctrl+C)
def signal_handler(sig, frame):
    print("\n" + Fore.RED + "[!] Saliendo de SCANFUZZ..." + Style.RESET_ALL)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Función principal
def main():
    parser = argparse.ArgumentParser(description="Escáner de puertos sigiloso y fuzzing para CTFs (SCANFUZZ)")
    parser.add_argument("host", help="IP o dominio a escanear")
    parser.add_argument("-p", "--puertos", type=str, default="80,443,22,21,8080,3306", help="Lista de puertos a escanear o -p- para todos los puertos")
    parser.add_argument("-w", "--wordlist", type=str, default="wordlist.txt", help="Lista de palabras para fuzzing")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Número máximo de hilos para el escaneo (máximo 10)")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Retraso entre el envío de paquetes (en segundos)")
    parser.add_argument("-b", "--block-size", type=int, default=100, help="Tamaño del bloque para procesar la wordlist")
    args = parser.parse_args()

    if args.puertos == "-":
        args.puertos = list(range(1, 65536))  # Escanear todos los puertos
    else:
        args.puertos = [int(p) for p in args.puertos.split(",")]

    print(Fore.GREEN + "\n[*] Bienvenido a ScanFuzz \n" + Style.RESET_ALL)

    # Escanear puertos
    puertos_abiertos = escanear_puertos_syn(args.host, args.puertos, max_threads=args.threads, delay=args.delay)

    # Detectar el sistema operativo
    os_detectado = obtener_os(args.host)
    print()
    print(Fore.YELLOW + f"[*] Sistema operativo detectado: {os_detectado}" + Style.RESET_ALL)

    # Fuzzing de directorios
    fuzz_results = []
    if 80 in puertos_abiertos or 443 in puertos_abiertos:
        url = f"https://{args.host}" if 443 in puertos_abiertos else f"http://{args.host}"
        try:
            with open(args.wordlist, "r", encoding="ISO-8859-1") as f:
                wordlist = f.readlines()
            fuzz_results = asyncio.run(fuzzing(url, wordlist, max_concurrent=20, delay=args.delay, block_size=args.block_size))
        except FileNotFoundError:
            print(Fore.RED + "[!] No se encontró el archivo de wordlist." + Style.RESET_ALL)

    # Guardar resultados
    guardar_resultados(args.host, puertos_abiertos, fuzz_results)

if __name__ == "__main__":
    main()
