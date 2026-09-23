# FortiGate — Topología Avanzada de Seguridad de Redes

### Jose Gabriel Feliz Maria · Matrícula: 2025-0742

**Seguridad de Redes · ITLA**

---

## 🎥 Video Demostrativo

**[Ver demostración en YouTube](https://youtu.be/Wk61DpxzlOY)**

**Duración máxima:** 10 minutos
**Debe mostrar:** hora y fecha del sistema, rostro y voz del autor explicando, y la demostración de que la topología cumple sus objetivos de seguridad (NAT/Internet, Política 1 permitida, Política 2 bloqueada, DPI activo, ataque SQL Injection bloqueado y atacante en cuarentena, restricción WEB→DB solo puerto 3306, bloqueo de descarga .exe, y rate limiting/DoS).

---

## 📋 Tabla de Contenido

1. [Propósito del Laboratorio](#1-propósito-del-laboratorio)
2. [Topología y Direccionamiento](#2-topología-y-direccionamiento)
   - [Diagrama de Topología](#21-diagrama-de-topología)
   - [Tabla de Interfaces y VLANs](#22-tabla-de-interfaces-y-vlans)
   - [Tabla de Dispositivos](#23-tabla-de-dispositivos)
3. [Configuración del Switch (Seguridad Básica de Redes)](#3-configuración-del-switch-seguridad-básica-de-redes)
4. [Configuraciones en FortiGate (100% por GUI)](#4-configuraciones-en-fortigate-100-por-gui)
   - [4.1 Interfaces y VLANs](#41-interfaces-y-vlans)
   - [4.2 DHCP en VLAN de Usuarios](#42-dhcp-en-vlan-de-usuarios)
   - [4.3 Ruta por Defecto](#43-ruta-por-defecto)
   - [4.4 NAT](#44-nat)
   - [4.5 Política 1 — Permitir Usuarios → WEB-Server (443)](#45-política-1--permitir-usuarios--web-server-443)
   - [4.6 Política 2 — Bloquear Usuarios → DB-Server (3306)](#46-política-2--bloquear-usuarios--db-server-3306)
   - [4.7 DPI (Deep Packet Inspection / SSL Inspection)](#47-dpi-deep-packet-inspection--ssl-inspection)
   - [4.8 Detección y Cuarentena de SQL Injection](#48-detección-y-cuarentena-de-sql-injection)
   - [4.9 WEB-Server → DB-Server: solo puerto 3306](#49-web-server--db-server-solo-puerto-3306)
   - [4.10 Filtrado de Aplicaciones — Bloqueo de .exe](#410-filtrado-de-aplicaciones--bloqueo-de-exe)
   - [4.11 Rate Limiting / Protección Anti-DoS](#411-rate-limiting--protección-anti-dos)
5. [Prueba de Ataque: Inyección de Payloads SQLi](#5-prueba-de-ataque-inyección-de-payloads-sqli)
6. [Capturas de Pantalla](#6-capturas-de-pantalla)
7. [Scripts](#7-scripts)
8. [Running-Configs](#8-running-configs)
9. [Referencias](#9-referencias)

---

## 1. Propósito del Laboratorio

Este laboratorio implementa un **FortiGate como firewall perimetral y de segmentación interna** para una topología corporativa compuesta por tres segmentos de red aislados entre sí (Usuarios, Web y Base de Datos), con el objetivo de demostrar controles de seguridad de red de capa 3 a capa 7 configurados **íntegramente desde la GUI** de FortiOS.

Los objetivos de seguridad implementados son:

* Proveer acceso a Internet a la LAN de Usuarios mediante **NAT** y una **ruta por defecto**, con direccionamiento dinámico por **DHCP**.
* Permitir únicamente el tráfico **HTTPS (443)** de Usuarios hacia el WEB-Server (**Política 1**) y **bloquear explícitamente** cualquier intento de Usuarios hacia el DB-Server en el puerto **3306** (**Política 2**).
* Activar **DPI (Deep Packet Inspection)** con inspección SSL sobre el tráfico hacia el WEB-Server.
* Detectar y bloquear **intentos de SQL Injection** dirigidos al WEB-Server mediante un sensor IPS dedicado, **colocando al atacante en cuarentena** automáticamente y registrando el evento en los logs.
* Restringir la comunicación del **WEB-Server hacia el DB-Server exclusivamente al puerto 3306**, denegando cualquier otro tráfico entre ambos servidores.
* Aplicar **filtrado de aplicaciones/archivos** para bloquear la descarga de ejecutables `.exe` desde la navegación web.
* Implementar **rate limiting (DoS Policy)** para mitigar ataques de denegación de servicio.
* Segmentar la LAN de Usuarios en una **VLAN 10** dedicada, con **seguridad básica de red** aplicada en el switch de acceso (puertos sin uso apagados, BPDU Guard, PortFast y trunk sin negociación DTP).

---

## 2. Topología y Direccionamiento

Todo el direccionamiento IP de este laboratorio está basado en la matrícula del autor (**2025-0742**), siguiendo el esquema `10.7.42.0/24` para la red interna.

### 2.1 Diagrama de Topología

```
                         [ INTERNET ]
                              │
                        (DHCP - PNETLab/VMware NAT)
                              │
                           port1 (WAN)
                     ┌────────┴─────────┐
                     │     FortiGate     │
                     │  port1 : WAN      │  DHCP
                     │  port2 : TRUNK    │  802.1Q → VLAN 10 / 20 / 30
                     │  port3 : (libre)  │
                     └─────────┬─────────┘
                                │ port2 (trunk 10,20,30)
                          ┌─────┴─────┐
                          │  SW-LAB   │  Switch Cisco IOS
                          │ (Eth0/0)  │  spanning-tree + port-security
                          └──┬───┬────┘
                    Eth0/3 ┌─┘   │   └─┐ Eth0/1        Eth0/2 ┐
                           │     │      │                      │
                    ┌──────┴──┐  │  ┌───┴───────┐      ┌───────┴───┐
                    │USUARIO- │  │  │ Ubuntu-DB │      │ Kali-WEB  │
                    │  PC     │  │  │(DB-Server)│      │(WEB-Server)
                    │ (DHCP)  │  │  │           │      │  HTTPS    │
                    └─────────┘  │  └───────────┘      └───────────┘
                    VLAN10_USUARIOS  VLAN30_DB           VLAN20_WEB
                    10.7.42.0/25     10.7.42.144/28       10.7.42.128/28
                    GW .1            GW .145 · Srv .146   GW .129 · Srv .130

   Políticas de seguridad aplicadas:
   ┌───────────────────────────────────────────────────────────────┐
   │ USUARIOS → Internet   : NAT (Use Outgoing Interface Address)   │
   │ USUARIOS → WEB (443)  : ACCEPT + IPS SQLi/Cuarentena + DPI +   │
   │                         File Filter (bloqueo .exe)             │
   │ USUARIOS → DB (3306)  : DENY explícito                         │
   │ WEB → DB (3306)       : ACCEPT (único puerto permitido)        │
   │ WEB → DB (resto)      : DENY explícito                         │
   │ USUARIOS → WEB (DoS)  : DoS Policy — SYN flood bloqueado a     │
   │                         50 pps, resto de anomalías en Log      │
   └───────────────────────────────────────────────────────────────┘
```

> Ver evidencia visual: [`24_switch_topologia_diagrama.png`](screenshots/24_switch_topologia_diagrama.png) y [`01_topologia_final_pnetlab.png`](screenshots/01_topologia_final_pnetlab.png).

### 2.2 Tabla de Interfaces y VLANs

| Interfaz | Alias | Rol | Dirección IP | Máscara | Notas |
|---|---|---|---|---|---|
| **port1** | WAN | WAN | Dinámica (DHCP) | /24 | Acceso administrativo: PING, HTTP |
| **port2** | — | Trunk 802.1Q | Sin IP propia | — | Transporta VLAN 10, 20 y 30 hacia SW-LAB |
| **port3** | — | Sin uso | — | — | Interfaz reservada, no utilizada en esta topología |
| **VLAN10_USUARIOS** | USUARIOS | LAN | 10.7.42.1 | /25 (255.255.255.128) | Gateway de la LAN de Usuarios · red `10.7.42.0/25` |
| **VLAN20_WEB** | WEB | LAN | 10.7.42.129 | /28 (255.255.255.240) | Gateway de la LAN del WEB-Server · red `10.7.42.128/28` |
| **VLAN30_DB** | DB | LAN | 10.7.42.145 | /28 (255.255.255.240) | Gateway de la LAN del DB-Server · red `10.7.42.144/28` |

### 2.3 Tabla de Dispositivos

| Dispositivo | VLAN / Interfaz | Dirección IP | Método | Rol |
|---|---|---|---|---|
| **FortiGate** | port1 | DHCP (WAN) | Dinámica | Firewall perimetral |
| **FortiGate** | port2 (trunk) | — | — | Trunk 802.1Q hacia SW-LAB (VLAN 10/20/30) |
| **SW-LAB** (Cisco IOS) | Eth0/0 | — | — | Switch de acceso — trunk hacia FortiGate |
| **USUARIO-PC** | VLAN10 (Eth0/3) | 10.7.42.10 – 10.7.42.126 | **DHCP** | Cliente de la LAN de Usuarios |
| **Kali-WEB** (WEB-Server) | VLAN20 (Eth0/2) | **10.7.42.130** | Estática | Servidor Web (HTTPS) |
| **Ubuntu-DB** (DB-Server) | VLAN30 (Eth0/1) | **10.7.42.146** | Estática | Servidor de Base de Datos (MySQL, puerto 3306) |

> El rango DHCP disponible en `VLAN10_USUARIOS` es `10.7.42.10 – 10.7.42.126` (DNS: `1.1.1.1` / `8.8.8.8`). Los servidores Web y DB usan IP estática para que las políticas de firewall siempre apunten correctamente a ellos.

---

## 3. Configuración del Switch (Seguridad Básica de Redes)

Switch Cisco IOS, hostname `SW-LAB`, con seguridad básica de puertos y de administración aplicada. Running-config completo en [`running-configs/SW-LAB_switch_running-config_2026-09-23.txt`](running-configs/SW-LAB_switch_running-config_2026-09-23.txt).

| Puerto | Función | Configuración de seguridad |
|---|---|---|
| **Eth0/0** | Trunk hacia FortiGate (port2) | VLANs permitidas `10,20,30`, encapsulación `dot1q`, VLAN nativa `999` (no enrutada / "blackhole"), `switchport nonegotiate` (deshabilita DTP para evitar negociación de trunk no autorizada) |
| **Eth0/1** | Acceso — Ubuntu-DB | `switchport access vlan 30`, `spanning-tree portfast edge`, `spanning-tree bpduguard enable` |
| **Eth0/2** | Acceso — Kali-WEB | `switchport access vlan 20`, `portfast edge`, `bpduguard enable` |
| **Eth0/3** | Acceso — USUARIO-PC | `switchport access vlan 10`, `portfast edge`, `bpduguard enable` |
| **Eth1/0** | Acceso — VLAN10_USUARIOS (puerto adicional habilitado) | `switchport access vlan 10`, `portfast edge`, `bpduguard enable` |
| **Puertos sin uso** (Eth1/1–3, Eth2/0–3, Eth3/0–3) | Deshabilitados | `switchport access vlan 999` + `shutdown` — puertos físicos no utilizados quedan apagados y aislados en una VLAN no enrutada, siguiendo la práctica recomendada de "puertos no usados = puertos apagados" |

**Resumen de controles de seguridad básica aplicados:**
* **BPDU Guard + PortFast** en todos los puertos de acceso: si un puerto de usuario recibe una BPDU (señal de que se conectó un switch no autorizado), el puerto se bloquea automáticamente.
* **`switchport nonegotiate`** en el trunk: evita que un atacante conectado a ese puerto negocie un enlace trunk vía DTP (mitiga *VLAN hopping*).
* **VLAN nativa aislada (999)** en el trunk: la VLAN nativa no se usa para tráfico de datos real, reduciendo el riesgo de *double tagging*.
* **Puertos no utilizados apagados** (`shutdown`) y movidos a la VLAN 999: reduce la superficie de ataque física del switch.
* **Control de acceso administrativo**: `enable secret` (contraseña cifrada tipo 5 para modo privilegiado), `service password-encryption` habilitado, y contraseña + `login` en las líneas `console`, `vty 0 4` (acceso remoto) y `aux 0`, con `exec-timeout` para cerrar sesiones inactivas automáticamente. También se configuró un `banner motd` de advertencia legal en el acceso a la CLI.

---

## 4. Configuraciones en FortiGate (100% por GUI)

> Toda la configuración y demostración de esta sección se realizó desde la interfaz gráfica (GUI) de FortiGate. Las rutas de menú se indican en cada apartado. Ver evidencia completa en la [sección 6](#6-capturas-de-pantalla).

### 4.1 Interfaces y VLANs

**Ruta:** `Network → Interfaces → Create New → Interface`

Se crearon tres interfaces VLAN (tipo `802.1Q`) sobre `port2`, con Role `LAN`:

| Campo | VLAN10_USUARIOS | VLAN20_WEB | VLAN30_DB |
|---|---|---|---|
| Interface (padre) | port2 | port2 | port2 |
| VLAN ID | 10 | 20 | 30 |
| IP/Netmask | 10.7.42.1/255.255.255.128 | 10.7.42.129/255.255.255.240 | 10.7.42.145/255.255.255.240 |
| Administrative Access | PING | PING | PING |

> Ver evidencia: [`03_interfaces_port1_port2_port3.png`](screenshots/03_interfaces_port1_port2_port3.png), [`04_vlan10_usuarios_creacion.png`](screenshots/04_vlan10_usuarios_creacion.png), [`05_vlan20_web_vlan30_db_creacion.png`](screenshots/05_vlan20_web_vlan30_db_creacion.png), [`06_vlan30_db_ip_detalle.png`](screenshots/06_vlan30_db_ip_detalle.png)

### 4.2 DHCP en VLAN de Usuarios

**Ruta:** `Network → Interfaces → VLAN10_USUARIOS → Edit → DHCP Server`

| Campo | Valor |
|---|---|
| Address Range | `10.7.42.10` – `10.7.42.126` |
| Netmask | `255.255.255.128` |
| Default Gateway | `10.7.42.1` |
| DNS Server | `1.1.1.1` / `8.8.8.8` |

> Ver evidencia: [`07_dhcp_vlan10_usuarios.png`](screenshots/07_dhcp_vlan10_usuarios.png)

### 4.3 Ruta por Defecto

**Ruta:** `Network → Static Routes`

La ruta por defecto (`0.0.0.0/0`) se obtiene dinámicamente a través de `port1` (WAN configurado en modo **DHCP**, con "Retrieve default gateway from server" habilitado), visible en la tabla de enrutamiento de FortiGate.

> Ver evidencia: [`08_ruta_por_defecto.png`](screenshots/08_ruta_por_defecto.png)

### 4.4 NAT

El NAT se habilita directamente en la política de firewall que da salida a Internet a la LAN de Usuarios.

**Ruta:** `Policy & Objects → Firewall Policy → USUARIOS_INTERNET → Edit`

| Campo | Valor |
|---|---|
| Name | `USUARIOS_INTERNET` |
| Incoming Interface | `VLAN10_USUARIOS` |
| Outgoing Interface | `port1` |
| Source | `VLAN10_USUARIOS address` |
| Destination | `all` |
| Service | `DNS`, `HTTP`, `HTTPS`, `PING` |
| Action | `ACCEPT` |
| **NAT** | ✅ **Enable** — `Use Outgoing Interface Address` |

> Ver evidencia: [`09_nat_politica_usuarios_internet.png`](screenshots/09_nat_politica_usuarios_internet.png), [`10_nat_politica_usuarios_internet_2.png`](screenshots/10_nat_politica_usuarios_internet_2.png)

> También existió una política temporal `DB_INSTALACION_TEMPORAL` (VLAN30_DB → port1, con NAT) usada únicamente para instalar paquetes en el DB-Server durante el montaje del laboratorio. Siguiendo buenas prácticas de seguridad, esta política quedó **deshabilitada** una vez finalizada la instalación (el DB-Server no debe tener salida a Internet en producción).

### 4.5 Política 1 — Permitir Usuarios → WEB-Server (443)

**Ruta:** `Policy & Objects → Firewall Policy → Create New`

| Campo | Valor |
|---|---|
| Name | `USUARIOS_WEB_HTTPS` |
| Incoming Interface | `VLAN10_USUARIOS` |
| Outgoing Interface | `VLAN20_WEB` |
| Source | `VLAN10_USUARIOS address` |
| Destination | `WEB_SERVER` (10.7.42.130) |
| Service | `HTTPS` |
| Action | `ACCEPT` |
| NAT | Disabled (tráfico interno) |
| Security Profiles | SSL Inspection (`custom-deep-inspection`, Full SSL Inspection) + IPS (`IPS_SQLI_CUARENTENA`) + File Filter (`BLOQUEAR_EXE_WEB`) |

> Se agregó además una política auxiliar `LAB_HTTP_VALIDACION` (mismo origen/destino, servicio HTTP) para poder demostrar el bloqueo de los payloads de SQL Injection sin depender de la inspección SSL completa. Actualmente queda **deshabilitada** en el running-config final — la política principal (`USUARIOS_WEB_HTTPS`) ya realiza inspección SSL completa (Full SSL Inspection), por lo que el sensor IPS puede inspeccionar directamente el tráfico HTTPS sin necesidad de esta política auxiliar.

> Ver evidencia: [`11_politica1_usuarios_web_443.png`](screenshots/11_politica1_usuarios_web_443.png)

### 4.6 Política 2 — Bloquear Usuarios → DB-Server (3306)

**Ruta:** `Policy & Objects → Firewall Policy → Create New`

| Campo | Valor |
|---|---|
| Name | `BLOQUEAR_USUARIOS_DB_3306` |
| Incoming Interface | `VLAN10_USUARIOS` |
| Outgoing Interface | `VLAN30_DB` |
| Source | `VLAN10_USUARIOS address` |
| Destination | `DB_SERVER` (10.7.42.146) |
| Service | `DB_TCP_3306` (servicio personalizado, TCP/3306) |
| Action | **DENY** |
| Log Violation Traffic | Enabled |

> Ver evidencia: [`12_politica2_bloqueo_usuarios_db_3306.png`](screenshots/12_politica2_bloqueo_usuarios_db_3306.png)

### 4.7 DPI (Deep Packet Inspection / SSL Inspection)

**Ruta:** `Security Profiles → SSL/SSH Inspection`

Se creó y activó un perfil de **Full SSL Inspection** (`custom-deep-inspection`) sobre la política `USUARIOS_WEB_HTTPS`, habilitando **DPI real** (descifrado del tráfico HTTPS con el certificado de FortiGate) para que el resto de los perfiles de seguridad (IPS, File Filter) puedan inspeccionar el contenido — no solo el certificado — del tráfico hacia el WEB-Server. Esto requirió gestionar los certificados SSL de FortiGate (ver [`26_certificados_fortigate.png`](screenshots/26_certificados_fortigate.png)).

> Ver evidencia: [`13_dpi_ssl_inspection_perfil.png`](screenshots/13_dpi_ssl_inspection_perfil.png)

### 4.8 Detección y Cuarentena de SQL Injection

**Ruta:** `Security Profiles → Intrusion Prevention → Create New`

Se creó un sensor IPS personalizado:

| Campo | Valor |
|---|---|
| Nombre del sensor | `IPS_SQLI_CUARENTENA` |
| Firma agregada | `HTTP.URI.SQL.Injection` (rule 15621) |
| Action | `Block` |
| **Quarantine** | ✅ **Attacker's IP address** — expira en **1 día** (`quarantine-expiry 1d` en el running-config final) |

Este sensor se aplicó en las políticas `USUARIOS_WEB_HTTPS` y `LAB_HTTP_VALIDACION`. Cuando FortiGate detecta un payload de SQL Injection dirigido al WEB-Server:

1. Bloquea la petición (`action: dropped`) — ver [`20_ataque_sqli_log_ips_dropped.png`](screenshots/20_ataque_sqli_log_ips_dropped.png).
2. Coloca la IP de origen en cuarentena — ver [`21_cuarentena_ip_baneada.png`](screenshots/21_cuarentena_ip_baneada.png) y [`22_cuarentena_detalle_ip.png`](screenshots/22_cuarentena_detalle_ip.png) (IP `10.7.42.10`, Source: `IPS`, expira ~24h).
3. Registra el evento en `Log & Report → Security Events → Intrusion Prevention`.

> Los payloads utilizados para la prueba están documentados en [`scripts/sql_injection_payloads.sh`](scripts/sql_injection_payloads.sh) — ver también la [sección 5](#5-prueba-de-ataque-inyección-de-payloads-sqli).

> Ver evidencia de configuración: [`14_ips_sensor_sqli_creacion.png`](screenshots/14_ips_sensor_sqli_creacion.png), [`15_ips_sensor_sqli_quarantine_signature.png`](screenshots/15_ips_sensor_sqli_quarantine_signature.png)

### 4.9 WEB-Server → DB-Server: solo puerto 3306

Se implementó con **dos políticas complementarias**, en este orden (el orden importa: FortiGate evalúa top-down):

| # | Nombre | Origen | Destino | Servicio | Acción |
|---|---|---|---|---|---|
| 1 | `WEB_DB_3306` | `WEB_SERVER` | `DB_SERVER` | `DB_TCP_3306` | **ACCEPT** |
| 2 | `BLOQUEAR_WEB_DB_RESTO` | `WEB_SERVER` | `DB_SERVER` | `ALL` | **DENY** |

Con esta combinación, el WEB-Server puede iniciar conexiones al DB-Server **únicamente** por el puerto 3306; cualquier otro intento (SSH, ICMP, HTTP, etc.) es denegado explícitamente. Se verificó intentando una conexión SSH (puerto 22) desde el WEB-Server hacia el DB-Server, la cual fue bloqueada por `BLOQUEAR_WEB_DB_RESTO`.

> Ver evidencia: [`18_politicas_finales_web_db_3306.png`](screenshots/18_politicas_finales_web_db_3306.png), [`19_politicas_web_db_solo_3306_tabla.png`](screenshots/19_politicas_web_db_solo_3306_tabla.png)

### 4.10 Filtrado de Aplicaciones — Bloqueo de .exe

**Ruta:** `Security Profiles → File Filter → Create New`

| Campo | Valor |
|---|---|
| Nombre | `BLOQUEAR_EXE_WEB` |
| Filter | Tipo de archivo `exe`, Protocolo `HTTP`, Action `Block` |

Aplicado a la política `USUARIOS_WEB_HTTPS` (y `LAB_HTTP_VALIDACION`). Se verificó descargando un archivo `lab0742.exe` desde el WEB-Server; FortiGate bloqueó la descarga y la registró en `Log & Report → Security Events → Application Control / File Filter`.

> Ver evidencia: [`16_file_filter_bloqueo_exe_perfil.png`](screenshots/16_file_filter_bloqueo_exe_perfil.png), [`23_file_filter_log_bloqueo_exe.png`](screenshots/23_file_filter_log_bloqueo_exe.png)

### 4.11 Rate Limiting / Protección Anti-DoS

**Ruta:** `Policy & Objects → DoS Policy → Create New`

| Campo | Valor |
|---|---|
| Name | `DOS_USUARIOS_WEB` |
| Interface | `VLAN10_USUARIOS` (tráfico interno Usuarios → WEB) |
| Source / Destination | `VLAN10_USUARIOS address` → `WEB_SERVER` |
| Service | `HTTPS` |
| Anomalía `tcp_syn_flood` | Log **Enable** + **Action: Block** + Threshold `50` paquetes/seg |
| Resto de anomalías L3/L4 (`tcp_port_scan`, `udp_flood`, `icmp_flood`, etc.) | Quedan en modo **Log** (monitoreo) con sus umbrales por defecto |

Esta política limita específicamente el volumen de conexiones **SYN** hacia el WEB-Server (mitigando SYN flood / DoS volumétrico), bloqueando automáticamente al origen que supere 50 paquetes SYN por segundo, mientras el resto de anomalías queda visible en los logs para análisis.

> Ver evidencia: [`17_dos_policy_rate_limiting.png`](screenshots/17_dos_policy_rate_limiting.png)

---

## 5. Prueba de Ataque: Inyección de Payloads SQLi

**Metodología y herramienta:** desde la máquina atacante (Kali, VLAN10_USUARIOS, IP `10.7.42.10`) se usó `curl` para enviar el payload directamente como parámetro de consulta (query string) en una petición **HTTPS GET** contra un archivo de prueba publicado en el WEB-Server (`https://10.7.42.130/prueba.txt`), usando el script [`scripts/sql_injection_payloads.sh`](scripts/sql_injection_payloads.sh).

> **Nota importante:** el WEB-Server de este laboratorio no tiene un formulario de login ni un backend de base de datos real. Por eso el ataque no se hace vía `POST` contra un formulario, sino inyectando el payload como query string en la URL (`GET /prueba.txt?id=1' UNION SELECT 1,2,3--`). El sensor IPS de FortiGate (firma `HTTP.URI.SQL.Injection`, rule 15621) inspecciona el patrón directamente sobre la URI/query string de la petición HTTPS —gracias a que la política `USUARIOS_WEB_HTTPS` tiene Full SSL Inspection activa—, sin importar si existe o no un backend vulnerable detrás. Esto es suficiente y válido para demostrar la detección, el bloqueo y la cuarentena por parte del FortiGate.

**Resultado verificado directamente en el FortiGate por CLI** (`execute log filter category 4` / `field srcip 10.7.42.10` / `field dstip 10.7.42.130` / `execute log display`):

```
date=2026-09-22 time=10:54:10  type="utm" subtype="ips" eventtype="signature"
srcip=10.7.42.10  srcintf="VLAN10_USUARIOS"  dstip=10.7.42.130  dstintf="VLAN20_WEB"
service="HTTPS"  action="dropped"  policyid=2  policyname="USUARIOS_WEB_HTTPS"
attack="HTTP.URI.SQL.Injection"  attackid=15621  profile="IPS_SQLI_CUARENTENA"
url="/prueba.txt?id=1%27%20UNION%20SELECT%201,2,3--"  severity="high"
```

1. FortiGate identifica el patrón malicioso con la firma `HTTP.URI.SQL.Injection` (rule 15621) del sensor `IPS_SQLI_CUARENTENA`, aplicado sobre la política principal `USUARIOS_WEB_HTTPS` (Policy ID 2).
2. La petición se bloquea (`action: dropped`) — el atacante no recibe respuesta del servidor.
3. La IP atacante (`10.7.42.10`) es puesta en **cuarentena** automáticamente por 1 día (visible en `Dashboard → Quarantine`).
4. El evento queda registrado en `Log & Report → Security Events → Intrusion Prevention`, con Action `Blocked`/`dropped`, Attack Name `HTTP.URI.SQL.Injection`, Source `10.7.42.10`, Destination `WEB_SERVER`.

> Ver evidencia: [`20_ataque_sqli_log_ips_dropped.png`](screenshots/20_ataque_sqli_log_ips_dropped.png), [`21_cuarentena_ip_baneada.png`](screenshots/21_cuarentena_ip_baneada.png), [`22_cuarentena_detalle_ip.png`](screenshots/22_cuarentena_detalle_ip.png)

---

## 6. Capturas de Pantalla

Todas las capturas están en la carpeta [`screenshots/`](screenshots/), numeradas en el orden en que se citan en este documento.

| # | Archivo | Descripción |
|---|---|---|
| 00 | [`00_topologia_pnetlab_inicial.png`](screenshots/00_topologia_pnetlab_inicial.png) | Topología inicial del laboratorio en PNETLab |
| 01 | [`01_topologia_final_pnetlab.png`](screenshots/01_topologia_final_pnetlab.png) | Diagrama final de la topología completa |
| 02 | [`02_licencia_forticare_dashboard.png`](screenshots/02_licencia_forticare_dashboard.png) | Activación de licencia de evaluación FortiCare y dashboard |
| 03 | [`03_interfaces_port1_port2_port3.png`](screenshots/03_interfaces_port1_port2_port3.png) | Network → Interfaces: port1 (WAN), port2 (trunk), port3 |
| 04 | [`04_vlan10_usuarios_creacion.png`](screenshots/04_vlan10_usuarios_creacion.png) | Creación de interfaz VLAN10_USUARIOS |
| 05 | [`05_vlan20_web_vlan30_db_creacion.png`](screenshots/05_vlan20_web_vlan30_db_creacion.png) | Creación de interfaces VLAN20_WEB y VLAN30_DB |
| 06 | [`06_vlan30_db_ip_detalle.png`](screenshots/06_vlan30_db_ip_detalle.png) | Detalle de IP de VLAN30_DB |
| 07 | [`07_dhcp_vlan10_usuarios.png`](screenshots/07_dhcp_vlan10_usuarios.png) | Servidor DHCP en VLAN10_USUARIOS |
| 08 | [`08_ruta_por_defecto.png`](screenshots/08_ruta_por_defecto.png) | Ruta por defecto vía port1 |
| 09 | [`09_nat_politica_usuarios_internet.png`](screenshots/09_nat_politica_usuarios_internet.png) | NAT habilitado en política USUARIOS_INTERNET |
| 10 | [`10_nat_politica_usuarios_internet_2.png`](screenshots/10_nat_politica_usuarios_internet_2.png) | NAT — Use Outgoing Interface Address |
| 11 | [`11_politica1_usuarios_web_443.png`](screenshots/11_politica1_usuarios_web_443.png) | Política 1: USUARIOS_WEB_HTTPS |
| 12 | [`12_politica2_bloqueo_usuarios_db_3306.png`](screenshots/12_politica2_bloqueo_usuarios_db_3306.png) | Política 2: BLOQUEAR_USUARIOS_DB_3306 |
| 13 | [`13_dpi_ssl_inspection_perfil.png`](screenshots/13_dpi_ssl_inspection_perfil.png) | Perfil SSL Inspection (DPI) |
| 14 | [`14_ips_sensor_sqli_creacion.png`](screenshots/14_ips_sensor_sqli_creacion.png) | Creación del sensor IPS_SQLI_CUARENTENA |
| 15 | [`15_ips_sensor_sqli_quarantine_signature.png`](screenshots/15_ips_sensor_sqli_quarantine_signature.png) | Firma SQLi en modo Quarantine (1 día) |
| 16 | [`16_file_filter_bloqueo_exe_perfil.png`](screenshots/16_file_filter_bloqueo_exe_perfil.png) | Perfil File Filter BLOQUEAR_EXE_WEB |
| 17 | [`17_dos_policy_rate_limiting.png`](screenshots/17_dos_policy_rate_limiting.png) | DoS Policy DOS_USUARIOS_WEB |
| 18 | [`18_politicas_finales_web_db_3306.png`](screenshots/18_politicas_finales_web_db_3306.png) | Listado final de políticas (interface pair view) |
| 19 | [`19_politicas_web_db_solo_3306_tabla.png`](screenshots/19_politicas_web_db_solo_3306_tabla.png) | WEB_DB_3306 + BLOQUEAR_WEB_DB_RESTO |
| 20 | [`20_ataque_sqli_log_ips_dropped.png`](screenshots/20_ataque_sqli_log_ips_dropped.png) | Log IPS: SQL Injection bloqueado |
| 21 | [`21_cuarentena_ip_baneada.png`](screenshots/21_cuarentena_ip_baneada.png) | Dashboard de cuarentena — IP baneada |
| 22 | [`22_cuarentena_detalle_ip.png`](screenshots/22_cuarentena_detalle_ip.png) | Detalle de la IP en cuarentena |
| 23 | [`23_file_filter_log_bloqueo_exe.png`](screenshots/23_file_filter_log_bloqueo_exe.png) | Log de bloqueo de descarga .exe |
| 24 | [`24_switch_topologia_diagrama.png`](screenshots/24_switch_topologia_diagrama.png) | Diagrama del switch y los hosts conectados |
| 25 | [`25_cli_verificacion_interfaces.png`](screenshots/25_cli_verificacion_interfaces.png) | Verificación final por CLI |
| 26 | [`26_certificados_fortigate.png`](screenshots/26_certificados_fortigate.png) | Gestión de certificados SSL en FortiGate |

---

## 7. Scripts

| Archivo | Descripción |
|---|---|
| [`scripts/sql_injection_payloads.sh`](scripts/sql_injection_payloads.sh) | Script usado para enviar (vía `curl`, como query string en peticiones HTTPS GET) los payloads de SQL Injection contra el WEB-Server y verificar el bloqueo/cuarentena por parte de FortiGate. |

---

## 8. Running-Configs

| Archivo | Descripción |
|---|---|
| [`running-configs/FortiGate_running-config_2026-09-22.conf`](running-configs/FortiGate_running-config_2026-09-22.conf) | Backup **final** de configuración del FortiGate (incluye todas las políticas, el sensor IPS de cuarentena, el DoS Policy y el File Filter). |
| [`running-configs/FortiGate_running-config_2026-09-18.conf`](running-configs/FortiGate_running-config_2026-09-18.conf) | Backup intermedio (18 sept.) conservado solo por trazabilidad — reemplazado por el archivo anterior. |
| [`running-configs/SW-LAB_switch_running-config_2026-09-23.txt`](running-configs/SW-LAB_switch_running-config_2026-09-23.txt) | Running-config **final** del switch Cisco IOS (SW-LAB), con seguridad de administración aplicada (`enable secret`, contraseñas de línea, `banner motd`). |
| [`running-configs/SW-LAB_switch_running-config_2026-09-22.txt`](running-configs/SW-LAB_switch_running-config_2026-09-22.txt) | Backup intermedio (22 sept.) conservado solo por trazabilidad — reemplazado por el archivo anterior. |

---

## 9. Referencias

* Fortinet. (2026). *FortiGate Administration Guide 7.x — Firewall Policies*.
* Fortinet. (2026). *FortiGate Administration Guide 7.x — Intrusion Prevention System (IPS) y Quarantine*.
* Fortinet. (2026). *FortiGate Administration Guide 7.x — SSL/SSH Inspection*.
* Fortinet. (2026). *FortiGate Administration Guide 7.x — File Filter*.
* Fortinet. (2026). *FortiGate Administration Guide 7.x — DoS Policy*.
* Cisco. *Catalyst Switch — Spanning Tree PortFast y BPDU Guard, Configuration Guide*.
* OWASP. (2026). *OWASP Top 10 Web Application Security Risks — SQL Injection*.

---
