# **INFORME FORENSE - RESUMEN EJECUTIVO**

**Caso:** FOR-2025-1111-W7-HFM  
**Fecha:** 27 de Noviembre de 2025  
**Analista:** Manuel Maye Piulestan (DNI: 47975900Q)  
**Sistema Comprometido:** Windows 7 Professional 64-bit

---

## **1. RESUMEN EJECUTIVO**

### **1.1 Situación**

El sistema Windows 7 Professional bajo análisis fue comprometido mediante la explotación de dos vulnerabilidades críticas: CVE-2017-0144 (EternalBlue - SMBv1) y CVE-2018-9059 (Easy File Sharing Web Server 7.2). El incidente fue detectado el 11 de noviembre de 2025 tras alertas del sistema IDS Snort (ID-2025-8847).

### **1.2 Hallazgos Críticos**

- **Vector de Ataque Principal:** Exploit remoto sin autenticación a través de SMBv1 (puerto 445)
- **Vector Secundario:** Buffer overflow en servicio web Easy File Sharing (puerto 8089)
- **Malware Detectado:** KzcmVNSNKYkueQf.exe (PID: 1900)
- **Puerta Trasera:** Usuario "ihacklabs" creado con privilegios administrativos
- **Herramienta Ilegal:** KMSPico utilizada para activación ilegal de Windows
- **Comunicación C2:** Conexión activa hacia 10.28.5.1:53 (tunelado DNS)
- **ARP Spoofing:** Evidencia de ataque Man-In-The-Middle activo

### **1.3 Impacto**

- **Confidencialidad:** ALTA - Acceso completo al sistema con privilegios SYSTEM
- **Integridad:** ALTA - Modificación de archivos y creación de usuarios no autorizados
- **Disponibilidad:** MEDIA - Sistema funcional pero comprometido

### **1.4 Recomendaciones Urgentes**

1. **Aislamiento inmediato** del sistema de la red corporativa
2. **Aplicación del parche MS17-010** y actualización de Easy File Sharing Web Server
3. **Eliminación del usuario "ihacklabs"** y revisión de EventID 4720
4. **Desinstalación de KMSPico** y análisis de malware asociado
5. **Cierre de puertos 445 y 8089** en firewall perimetral
6. **Adquisición de licencias legítimas** de Windows para evitar futuros incidentes

---

## **2. ANÁLISIS TÉCNICO**

### **2.1 CVE-2017-0144 (EternalBlue)**

**Clasificación:** Crítica (CVSS 9.8)  
**Protocolo Afectado:** SMBv1  
**Puerto:** 445/TCP  

**Descripción Técnica:**  
Vulnerabilidad de desbordamiento de búfer en la implementación del protocolo SMB de Windows. Permite ejecución remota de código sin autenticación mediante paquetes especialmente diseñados.

**Evidencia en el Sistema:**
- Puerto 445 en estado LISTENING (PID 4 - kernel)
- Alertas IDS Snort ID-2025-8847 registradas
- Ausencia del parche MS17-010
- Logs EventID 4624 con múltiples inicios de sesión en periodo corto
- Logs EventID 4648 indicando uso de credenciales para movimiento lateral

### **2.2 CVE-2018-9059 (Easy File Sharing Web Server)**

**Clasificación:** Crítica (CVSS 9.8)  
**Aplicación:** Easy File Sharing Web Server 7.2  
**Puerto:** 8089/HTTP  
**Técnica:** Stack-based Buffer Overflow + ROP (Return-Oriented Programming)

**Componentes del Exploit:**

**1. Buffer Overflow:**
- Offset: 2278 bytes de relleno ("A"*2278)
- Sobrescribe EIP con dirección de retorno controlada

**2. ROP Chain:**
- 66 gadgets encadenados de ImageLoad.dll y sqlite3.dll
- Objetivo: Llamada a VirtualProtect() para bypass de DEP
- Convierte región de memoria a PAGE_EXECUTE_READWRITE (0x40)

**3. Shellcode:**
- Encoding: x86/alpha_mixed (generado con msfvenom)
- Tamaño: 622 bytes
- Payload: windows/adduser
- NOPs: 254 bytes (\x90)

**4. Módulos DLL Comprometidos:**

| DLL | Función | Dirección Crítica |
|-----|---------|-------------------|
| ImageLoad.dll | ROP gadgets, dirección de retorno | 0x1002280a (ADD ESP,1004 # RETN) |
| sqlite3.dll | VirtualProtect() IAT | 0x61c832d0 |

**Evidencia del Ataque:**
- Archivo exploit: crea_user.py (Desktop)
- Usuario backdoor: ihacklabs / Ihack12/
- EventID 4720: Creación de cuenta
- Servicio activo en puerto 8089

### **2.3 Malware y Persistencia**

**Proceso Malicioso:**
- **Nombre:** KzcmVNSNKYkueQf.exe
- **PID:** 1900
- **Estado:** En ejecución
- **Origen:** Vinculado a KMSPico
- **Características:** Sin servicios asociados, ejecución independiente

**KMSPico (PUA/Malware):**
- **Tipo:** Software de activación ilegal de Windows/Office
- **Impacto:** 
  - Creación de script persistente (arranque automático)
  - Origen del malware KzcmVNSNKYkueQf.exe
  - Carpetas temporales con caracteres aleatorios
  - Vector de entrada de código malicioso adicional

### **2.4 Comunicación C2 y Red**

**Conexión Saliente Sospechosa:**
```
TCP 172.26.1.113:49189 → 10.28.5.1:53 [SYN_SENT]
```
- **Técnica:** DNS tunneling para exfiltración de datos
- **Framework Sospechoso:** Cobalt Strike (basado en comportamiento)
- **Puerto Dinámico:** 49189 (alto rango)

**ARP Spoofing Detectado:**
```
172.26.0.31    4c:1d:96:75:24:de (dynamic)
172.26.1.87    4c:1d:96:75:24:de (dynamic)
```
- **Análisis:** Misma dirección MAC para dos IPs diferentes
- **Ataque:** Man-In-The-Middle (MITM) activo
- **Objetivo:** Interceptación de tráfico de red

### **2.5 Indicadores de Compromiso (IOCs)**

**Red:**

| Indicador | Tipo | Valor | Severidad |
|-----------|------|-------|-----------|
| Puerto SMB | Servicio | 445/TCP LISTENING | CRÍTICA |
| Puerto RDP | Servicio | 3389/TCP LISTENING | ALTA |
| Puerto Web | Servicio | 8089/TCP LISTENING | CRÍTICA |
| IP C2 | Conexión | 10.28.5.1:53 | CRÍTICA |
| MAC duplicada | ARP | 4c:1d:96:75:24:de | CRÍTICA |

**Archivos y Procesos:**

| Elemento | Ubicación/PID | Hash MD5 | Clasificación |
|----------|---------------|----------|---------------|
| KzcmVNSNKYkueQf.exe | PID 1900 | ejemplo_hash | MALICIOSO |
| crea_user.py | Desktop | ejemplo_hash | EXPLOIT |
| KMSPico | Sistema | ejemplo_hash | PUA/MALWARE |

**Usuarios:**

| Usuario | Tipo | Fecha Creación | Estado |
|---------|------|----------------|--------|
| ihacklabs | Backdoor | 11/11/2025 ~15:13 | ACTIVO |

---

## **3. LÍNEA TEMPORAL**

| Fecha/Hora (Estimada) | Evento | Sistema/Componente |
|------------------------|--------|--------------------|
| 11/11/2025 09:17:06 | Lease DHCP obtenido | Red |
| 11/11/2025 ~14:00 | Alerta IDS Snort 2025-8847 | IDS |
| 11/11/2025 ~15:00 | Explotación CVE-2017-0144 | SMB/Kernel |
| 11/11/2025 ~15:10 | Descarga de crea_user.py | Filesystem |
| 11/11/2025 ~15:12 | Ejecución CVE-2018-9059 | Easy File Sharing |
| 11/11/2025 ~15:13 | Creación usuario "ihacklabs" | Sistema (EventID 4720) |
| 11/11/2025 ~15:15 | Ejecución KzcmVNSNKYkueQf.exe | Proceso malicioso |
| 11/11/2025 ~15:20 | Instalación KMSPico | Sistema |
| 11/11/2025 ~15:30 | Conexión C2 establecida | Red (DNS tunneling) |
| 11/11/2025 19:30 | Descubrimiento del incidente | Equipo forense |
| 11/11/2025 19:42 | Captura de memoria RAM | Volatility3 |
| 11/11/2025 20:00 | Adquisición de disco completo | FTK Imager |

---

## **4. METODOLOGÍA FORENSE**

### **4.1 Orden de Volatilidad (NIST SP 800-86)**

Se siguió el principio de orden de volatilidad para la adquisición de evidencias:

**1. Memoria Volátil (RAM):**
- **Herramienta:** Volatility3
- **Comando:** `vol.py -f FORENSIC_10-Snapshot1.vmem windows.pslist`
- **Hash MD5:** 387dd09ff8655edb54207c3f51bc2b7e
- **Hash SHA-256:** 5d8acc919651b5c83d16c4d284afceab49bb891cab3d8ca1202c4b4d6a3df7f6

**2. Disco Completo:**
- **Herramienta:** FTK Imager
- **Tamaño:** 32 GB
- **Hash MD5:** 590cdac31fd2dd2bb8eef2ad8aa25e51
- **Hash SHA-1:** cb68cdee535bd62308260883f6628a5aba7c42cc

### **4.2 Herramientas Utilizadas**

| Herramienta | Función | Comando/Uso |
|-------------|---------|-------------|
| Volatility3 | Análisis de memoria | vol.py -f .vmem windows.pslist |
| FTK Imager | Adquisición forense | Imagen completa (GUI) |
| tasklist | Procesos activos | tasklist /svc |
| netstat | Conexiones de red | netstat -ano |
| arp | Tabla ARP | arp -a |
| ipconfig | Configuración IP | ipconfig /all |

### **4.3 Cadena de Custodia**

- **Case Number:** FOR-2025-1111-W7-HFM
- **Evidence Number:** EVI-001-DISCO-PRINCIPAL
- **Examiner:** Manuel Maye Piulestan
- **Notes:** VM VMWare - Alerta IDS 2025-8847
- **Image Destination:** E:\Evidencia\
- **Verification:** MD5 + SHA256

---

## **ANEXO: PRESENTACIÓN DE HALLAZGOS**

A continuación se presenta la tabla detallada de hallazgos con información forense completa:

### **HALLAZGO 1: Archivo Exploit crea_user.py**

| Campo | Valor |
|-------|-------|
| **Ruta Completa** | C:\Users\administrator\Desktop\crea_user.py |
| **Descripción** | Script Python que implementa exploit CVE-2018-9059 para buffer overflow en Easy File Sharing Web Server 7.2. Contiene ROP chain de 66 gadgets y shellcode alphanumeric de 622 bytes. |
| **MAC Time (M/A/C)** | M: ejemplo_fecha / A: ejemplo_fecha / C: ejemplo_fecha |
| **Tamaño Lógico** | ejemplo_bytes bytes |
| **Hash MD5** | ejemplo_md5_hash |
| **Hash SHA-1** | ejemplo_sha1_hash |
| **Hash SHA-256** | ejemplo_sha256_hash |
| **Contenido Relevante** | - Offset: 2278 bytes<br>- ROP chain: ImageLoad.dll + sqlite3.dll<br>- Shellcode: windows/adduser<br>- Payload: Usuario "ihacklabs" / "Ihack12/" |

### **HALLAZGO 2: Proceso Malicioso KzcmVNSNKYkueQf.exe**

| Campo | Valor |
|-------|-------|
| **Ruta Completa** | C:\windows\temp\KzcmVNSNKYkueQf.exe |
| **Descripción** | Proceso malicioso sin servicios asociados. Ejecución independiente originada por KMSPico. Establece conexión C2 hacia 10.28.5.1:53 (DNS tunneling). |
| **PID** | 1900 |
| **MAC Time (M/A/C)** | M: ejemplo_fecha / A: ejemplo_fecha / C: ejemplo_fecha |
| **Tamaño Lógico** | ejemplo_bytes bytes |
| **Hash MD5** | ejemplo_md5_hash |
| **Hash SHA-1** | ejemplo_sha1_hash |
| **Hash SHA-256** | ejemplo_sha256_hash |

### **HALLAZGO 3: Usuario Backdoor "ihacklabs"**

| Campo | Valor |
|-------|-------|
| **Ruta Completa** | Sistema: C:\Windows\System32\config\SAM |
| **Descripción** | Usuario local con privilegios administrativos creado mediante exploit CVE-2018-9059. Contraseña: "Ihack12/". Registrado en EventID 4720 (creación de cuenta). |
| **MAC Time (M/A/C)** | M: 11/11/2025 ~15:13 / A: 11/11/2025 ~15:13 / C: 11/11/2025 ~15:13 |
| **EventID** | 4720 (Creación de cuenta de usuario) |
| **Grupo** | Administradores |

### **HALLAZGO 4: KMSPico (PUA/Malware)**

| Campo | Valor |
|-------|-------|
| **Ruta Completa** | C:\[ruta_ejemplo]\KMSPico\ |
| **Descripción** | Software de activación ilegal de productos Microsoft. Crea script persistente en arranque automático. Origen del malware KzcmVNSNKYkueQf.exe y carpetas temporales con caracteres aleatorios. |
| **MAC Time (M/A/C)** | M: ejemplo_fecha / A: ejemplo_fecha / C: ejemplo_fecha |
| **Tamaño Lógico** | ejemplo_bytes bytes |
| **Hash MD5** | ejemplo_md5_hash |
| **Hash SHA-1** | ejemplo_sha1_hash |
| **Hash SHA-256** | ejemplo_sha256_hash |
| **Script Persistente** | [Ruta del script de arranque] |

### **HALLAZGO 5: Conexión C2 (DNS Tunneling)**

| Campo | Valor |
|-------|-------|
| **Protocolo** | TCP |
| **IP Local** | 172.26.1.113:49189 |
| **IP Remota** | 10.28.5.1:53 |
| **Estado** | SYN_SENT |
| **PID** | 3280 |
| **Descripción** | Conexión saliente hacia puerto DNS (53) utilizada para tunelado y exfiltración de datos. Puerto dinámico alto (49189) indica comunicación con framework de post-explotación (posible Cobalt Strike). |
| **Timestamp** | 11/11/2025 ~15:30 (estimado) |

### **HALLAZGO 6: ARP Spoofing**

| Campo | Valor |
|-------|-------|
| **IP 1** | 172.26.0.31 |
| **IP 2** | 172.26.1.87 |
| **MAC Duplicada** | 4c:1d:96:75:24:de |
| **Tipo** | dynamic |
| **Descripción** | Dos direcciones IP distintas con la misma dirección MAC física. Indica ataque Man-In-The-Middle (MITM) activo para interceptación de tráfico de red. |
| **Timestamp** | 11/11/2025 (durante análisis) |

### **HALLAZGO 7: EventID 4624 (Inicios de Sesión Múltiples)**

| Campo | Valor |
|-------|-------|
| **Ruta Log** | C:\Windows\System32\winevt\Logs\Security.evtx |
| **EventID** | 4624 (Inicio de sesión exitoso) |
| **Descripción** | Múltiples inicios de sesión en periodo de tiempo muy corto. Indica actividad automatizada post-explotación. |
| **Timestamp** | 11/11/2025 ~15:00 - ~15:30 |
| **Cantidad** |  eventos |
| **Usuarios** | Sistema, ihacklabs, [otros] |

### **HALLAZGO 8: EventID 4648 (Uso de Credenciales Explícitas)**

| Campo | Valor |
|-------|-------|
| **Ruta Log** | C:\Windows\System32\winevt\Logs\Security.evtx |
| **EventID** | 4648 (Intento de inicio de sesión con credenciales explícitas) |
| **Descripción** | Uso de credenciales para movimiento lateral dentro de la red. Indica reconocimiento activo post-compromiso. |
| **Timestamp** | 11/11/2025 ~15:00 - ~15:30 |
| **Usuarios** | ihacklabs, [otros] |

### **HALLAZGO 9: EventID 7036 (Cambios en Servicios)**

| Campo | Valor |
|-------|-------|
| **Ruta Log** | C:\Windows\System32\winevt\Logs\System.evtx |
| **EventID** | 7036 (Servicio entró en estado detenido/en ejecución) |
| **Descripción** | Activación y desactivación de servicios para establecer persistencia en la máquina. |
| **Timestamp** | 11/11/2025 ~15:00 - ~15:30 |
| **Servicios Afectados** | ejemplo_servicio_1, ejemplo_servicio_2 |

### **HALLAZGO 10: Puerto 445 (SMB) LISTENING**

| Campo | Valor |
|-------|-------|
| **Puerto** | 445/TCP |
| **Estado** | LISTENING |
| **PID** | 4 (Sistema/Kernel) |
| **Descripción** | Puerto SMBv1 expuesto sin parche MS17-010. Vulnerable a CVE-2017-0144 (EternalBlue). Vector de entrada inicial del atacante. |
| **Timestamp** | Activo durante todo el análisis |

### **HALLAZGO 11: Puerto 8089 (Easy File Sharing) LISTENING**

| Campo | Valor |
|-------|-------|
| **Puerto** | 8089/TCP |
| **Estado** | LISTENING |
| **Servicio** | Easy File Sharing Web Server 7.2 |
| **Descripción** | Servicio web vulnerable a CVE-2018-9059 (buffer overflow). Explotado mediante crea_user.py para crear usuario backdoor. |
| **Timestamp** | Activo durante todo el análisis |

### **HALLAZGO 12: Imagen de Memoria Volátil**

| Campo | Valor |
|-------|-------|
| **Archivo** | FORENSIC_10-Snapshot1.vmem |
| **Ruta Destino** | E:\Evidencia\ |
| **Tamaño** | ejemplo_bytes bytes |
| **Hash MD5** | 387dd09ff8655edb54207c3f51bc2b7e |
| **Hash SHA-256** | 5d8acc919651b5c83d16c4d284afceab49bb891cab3d8ca1202c4b4d6a3df7f6 |
| **Herramienta** | Volatility3 |
| **Contenido** | Procesos activos (PID 1900 - KzcmVNSNKYkueQf.exe), conexiones de red (10.28.5.1:53), tabla ARP, configuración IP. |

### **HALLAZGO 13: Imagen de Disco Completo**

| Campo | Valor |
|-------|-------|
| **Archivo** | WIN7_COMP_32GB_20251111 |
| **Ruta Destino** | E:\Evidencia\ |
| **Tamaño** | 32 GB |
| **Hash MD5** | 590cdac31fd2dd2bb8eef2ad8aa25e51 |
| **Hash SHA-1** | cb68cdee535bd62308260883f6628a5aba7c42cc |
| **Herramienta** | FTK Imager |
| **Contenido** | Sistema de archivos completo, logs de eventos, archivos de usuario, archivos maliciosos, registro de Windows (SAM, SECURITY, SOFTWARE, SYSTEM). |

---

## **5. CONCLUSIONES**

### **5.1 Vectores de Compromiso**

El sistema fue comprometido mediante dos vectores de ataque:

1. **CVE-2017-0144 (EternalBlue):** Explotación remota sin autenticación del servicio SMBv1 (puerto 445)
2. **CVE-2018-9059:** Buffer overflow en Easy File Sharing Web Server 7.2 (puerto 8089) con técnica ROP para bypass de DEP

### **5.2 Impacto del Incidente**

- **Acceso total:** Privilegios SYSTEM obtenidos mediante EternalBlue
- **Persistencia:** Usuario backdoor "ihacklabs" con privilegios administrativos
- **Comunicación C2:** Canal activo hacia 10.28.5.1 mediante DNS tunneling
- **MITM:** ARP spoofing detectado para interceptación de tráfico
- **Software ilegal:** KMSPico como vector de malware adicional

### **5.3 Recomendaciones Inmediatas**

**Contención:**
1. Aislar el sistema comprometido de la red
2. Bloquear IP 10.28.5.1 en firewall perimetral
3. Desconectar cable de red físico si es necesario

**Erradicación:**
1. Eliminar usuario "ihacklabs"
2. Desinstalar KMSPico y malware asociado
3. Eliminar archivo crea_user.py
4. Aplicar parche MS17-010
5. Actualizar/Desinstalar Easy File Sharing Web Server 7.2

**Recuperación:**
1. Reinstalación limpia del sistema operativo (recomendado)
2. Restauración desde backup verificado anterior al 11/11/2025
3. Adquisición de licencia legítima de Windows

**Prevención:**
1. Implementar política de actualizaciones automáticas
2. Deshabilitar SMBv1 en toda la red
3. Cerrar puertos 445 y 8089 en firewall
4. Segmentar red (VLANs)
5. Implementar IDS/IPS con firmas actualizadas
6. Monitoreo de EventID 4720, 4624, 4648, 7036
7. Implementar EDR (Endpoint Detection and Response)
8. Aplicar principio de mínimo privilegio
9. Auditoría mensual de usuarios y servicios

---

**Firma del Analista:**  
Manuel Maye Piulestan 
DNI: 47975900Q  
Fecha: 27 de Noviembre de 2025

---

**NOTA:** Este informe contiene información sensible y debe ser tratado como CONFIDENCIAL. Distribución limitada a personal autorizado.
