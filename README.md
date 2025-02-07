# ScanFuzz

ScanFuzz es una herramienta avanzada de escaneo de puertos y fuzzing, diseñada para entornos de seguridad informática y competiciones de CTF (Capture The Flag). Su objetivo principal es detectar puertos abiertos, servicios en ejecución y rutas ocultas en servidores web de manera eficiente y sigilosa.

---

## 🚀 Características Principales

### 🔍 Escaneo Sigiloso de Puertos (SYN Scan)
- Utiliza la técnica de escaneo SYN (Half-Open Scan), más sigilosa que un escaneo TCP completo.
- Permite escanear un rango personalizado o una lista específica de puertos.
- Detecta puertos abiertos, cerrados y filtrados.

### 💻 Fuzzing de Directorios
- Descubre rutas ocultas en servidores web.
- Soporta listas de palabras personalizadas (wordlist).
- Usa múltiples conexiones concurrentes para mejorar la velocidad del escaneo.

### 🖥️ Detección de Sistemas Operativos
- Analiza el TTL (Time to Live) y la ventana TCP para inferir el sistema operativo del host.
- Distingue entre sistemas Linux, Windows u otros.

### 📊 Exportación de Resultados
- Guarda los resultados del escaneo en un archivo JSON estructurado.
- Incluye puertos abiertos, servicios detectados, rutas encontradas y sistema operativo inferido.

---

## 🏗 Instalación

### 📌 Requisitos
- Python 3.5 o superior.
- Sistema operativo Linux, macOS o Windows.

### 📥 Instalación de Dependencias
Clona el repositorio y ejecuta la instalación de dependencias:

```bash
# Clonar el repositorio
git clone https://github.com/javiipardo/scanfuzz.git
cd scanfuzz

# Instalar las dependencias
pip install -r requirements.txt
```

---

## ⚡ Uso

```bash
python3 scanfuzz.py <host> [opciones]
```

### 🌐 Escaneo de Puertos
```bash
python3 scanfuzz.py 192.168.1.1 -p 80,443,8080
```
- `<host>`: IP o dominio del objetivo.
- `-p <puertos>`: Lista de puertos a escanear (por defecto: 80,443,22,21,8080,3306, etc.).
- `-p -`: Escanea todos los puertos (1-65535).

### 📂 Fuzzing de Directorios
Si se detecta un servidor web (puerto 80, 443 o 8443), se ejecuta automáticamente el fuzzing:

```bash
python3 scanfuzz.py 192.168.1.1 -w wordlist.txt
```
- `-w <wordlist>`: Especifica una wordlist personalizada para el fuzzing.

### 🔎 Detección del Sistema Operativo
La herramienta detecta automáticamente el sistema operativo del host remoto después del escaneo de puertos.

---

## 📜 Ejemplo de Salida

```bash
[*] Escaneando puertos en 192.168.1.1...
[+] Puerto abierto: 80 (http)
[+] Puerto abierto: 443 (https)
[*] Sistema operativo detectado: Linux
[*] Fuzzing en http://192.168.1.1
[✔] http://192.168.1.1/admin - Código: 200
[✔] http://192.168.1.1/backup - Código: 403
[*] Resultados guardados en 192.168.1.1_resultados.json
```

---

## 📝 Formato de Resultados (JSON)

Los resultados se guardan en un archivo JSON con el siguiente formato:

```json
{
  "host": "192.168.1.1",
  "puertos_abiertos": [80, 443],
  "servicios": {
    "80": "http",
    "443": "https"
  },
  "sistema_operativo": "Linux",
  "fuzzing": [
    {"url": "http://192.168.1.1/admin", "status": 200},
    {"url": "http://192.168.1.1/backup", "status": 403}
  ]
}
```

---

## 🔥 Contacto y Contribuciones

- **Autor**: [javiipardo](https://github.com/javiipardo)
- **Repositorio**: [ScanFuzz en GitHub](https://github.com/javiipardo/scanfuzz)

¡Contribuciones y mejoras son bienvenidas! 🚀
