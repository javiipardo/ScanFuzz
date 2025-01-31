
# ScanFuzz

ScanFuzz es una herramienta de escaneo de puertos y fuzzing diseñada para entornos de CTF (Capture The Flag) y pruebas de seguridad. Combina técnicas de escaneo sigiloso (SYN scan) con fuzzing de directorios y subdominios para descubrir puertos abiertos, servicios y rutas ocultas en servidores web.

## Características Principales

### 1. Escaneo Sigiloso de Puertos (SYN Scan)
🔍 Escanea puertos TCP utilizando la técnica de escaneo SYN (Half-Open Scan), que es más sigilosa que un escaneo completo.
- Soporta escaneo de un rango de puertos personalizado o una lista específica de puertos.
- Detecta puertos abiertos y muestra el servicio asociado a cada puerto (si está disponible).

### 2. Fuzzing de Directorios
💻 Realiza fuzzing de directorios en servidores web para descubrir rutas ocultas o archivos sensibles.
- Utiliza una lista de palabras (wordlist) para probar múltiples rutas.
- Soporta múltiples conexiones concurrentes para acelerar el proceso.

### 3. Detección de Sistemas Operativos
🖥️ Detecta el sistema operativo del host remoto basándose en las respuestas TCP/IP.
- Analiza el TTL (Time to Live) y el tamaño de la ventana TCP para inferir el sistema operativo.

### 4. Exportación de Resultados
📊 Guarda los resultados del escaneo y el fuzzing en un archivo JSON para su posterior análisis.
- Los resultados incluyen puertos abiertos, servicios detectados, rutas descubiertas y el sistema operativo inferido.

### 5. Fácil de Usar
🛠️ Interfaz de línea de comandos (CLI) intuitiva con opciones personalizables.
- Soporta colores en la terminal para una mejor visualización de los resultados.

---

## Instalación

### Requisitos
- Python 3.7 o superior.
- Librerías requeridas: `scapy`, `colorama`, `aiohttp`, `asyncio`.

### Instalación de Dependencias
Puedes instalar las dependencias necesarias usando pip:

```bash
pip install scapy colorama aiohttp
```

### Clonar el Repositorio
```bash
git clone https://github.com/tuusuario/scanfuzz.git
cd scanfuzz
```

---

## Uso

### Escaneo de Puertos
Para escanear puertos en un host específico:

```bash
./scanfuzz.py <host> -p <puertos>
```

- `<host>`: IP o dominio del objetivo.
- `-p <puertos>`: Lista de puertos a escanear (por defecto: 80,443,22,21,8080,3306). Usa `-p-` para escanear todos los puertos (1-65535).

**Ejemplo:**

```bash
./scanfuzz.py 192.168.1.1 -p 80,443,8080
```

### Fuzzing de Directorios
Si se detecta un servidor web (puerto 80 o 443), la herramienta realiza automáticamente fuzzing de directorios usando una wordlist.

```bash
./scanfuzz.py 192.168.1.1 -p 80 -w wordlist.txt
```

- `-w <wordlist>`: Ruta al archivo de wordlist (por defecto: `wordlist.txt`).

### Detección de Sistemas Operativos
La herramienta detecta automáticamente el sistema operativo del host remoto después del escaneo de puertos.

---

## Ejemplo de Salida

```plaintext
[*] Escaneando puertos sigilosamente en 192.168.1.1...
[+] Puerto abierto: 80 (http)
[+] Puerto abierto: 443 (https)
[*] Sistema operativo detectado: Linux (Kernel 2.4/2.6)
[*] Fuzzing en http://192.168.1.1
[+] http://192.168.1.1/admin - Código: 200
[+] http://192.168.1.1/backup - Código: 403
[*] Resultados guardados en 192.168.1.1_resultados.json
```

---

## Archivo de Resultados (JSON)

Los resultados se guardan en un archivo JSON con el siguiente formato:

```json
{
  "host": "192.168.1.1",
  "puertos_abiertos": [80, 443],
  "servicios": {
    "80": "http",
    "443": "https"
  },
  "sistema_operativo": "Linux (Kernel 2.4/2.6)",
  "fuzzing": [
    {"url": "http://192.168.1.1/admin", "status": 200},
    {"url": "http://192.168.1.1/backup", "status": 403}
  ]
}
```

---

¡Gracias por usar ScanFuzz! 🚀
