# Informe de Recolección y Almacenamiento de Evidencias Digitales

## 1. Datos Generales

- **Nombre del proyecto/incidente:**  Proyecto 2.1
- **Fecha de inicio:** 16/11/2025 
- **Analista responsable:**  Manuel Maye Piulestan
- **Ubicación de la adquisición:**  
- **Dispositivo afectado (tipo/identificador):**  Sobremesa

## 2. Metodología Aplicada

- **Referencia de procedimiento:**  
  La recolección de evidencias se realizó siguiendo los principios de la norma ISO/IEC 27037:2012, priorizando la identificación, adquisición y preservación de la evidencia digital. Se documentaron todos los pasos y se mantuvo la cadena de custodia para garantizar la integridad de los datos.



## 3. Recolección de Evidencias

- Primero hacemos un clonado del disco duro en .raw
![Clonado](/img/img2.png)

- En el escritorio encontramos un archivo que tras analizarlo es un buffer overflow
![buffer](/img/img3.png)
- comando systeminfo guardado en systeminfo.txt

- comando netstat guardado en netstat.txt

- Luego Cogeremos los archivos de los logs los meteremos dentro de evidencias 
  - Application.evtx
  - System.evtx
  - Security.evtx


- 



## 4. Listado y Descripción de Evidencias

| Nombre del archivo | Tipo de evidencia | Hash calculado | Herramienta utilizada | Características relevantes | Fecha y hora de recolección |
|--------------------|------------------|---------------|-----------------------|---------------------------|-----------------------------|
|                    |                  |               |                       |                           |                             |
| crear_user.py | Archivo python | e3b0c44298fc1...| FTK Imager| Buffer OverFlow| 17/11/2025 |
| systeminfo.txt |txt | 0873d391e9879... | cmd | comando | 17/11/2025 |
| Application.evtx | logs | 267388768432c...| cmd | logs | 17/11/2025 |
| System.evtx | logs |  8e3fb94d27b99...| eventos | logs | 17/11/2025 |
| Security.evtx | logs  | 07013e65b44e4... | eventos | logs |17/11/2025  |
| HoVgcPUXNBk.vbs | script | 3f31e930b9f86... | FTK Imager | script malicioso | 17/11/2025 |
| forensic_10.raw | raw | 4f1b2b0b822cd... | FTK Imager | disco duro | 17/11/2025 |

## 5. Acta de Adquisición

- **Quién realiza el procedimiento:**  Manuel Maye Piulestan
- **Fecha y hora de los pasos clave:**  17/11/2025
- **Detalles del estado inicial del sistema:**  
  ![Imagen estado inicial](/img/img1.png)
  Encontramos lo siguiente:
  - Mensaje para reiniciar el sistema.
  - Panel de configuración de red
  - Error en un script de VB en c:\windows\temp

## 6. Cadena de Custodia

- **Fecha y hora de descubrimiento:**  17/11/2025
- **Ubicación física y digital de almacenamiento inicial:**  c:\proyecto2
- **Custodio/s de la evidencia (nombres y roles):**  Manuel Maye Piulestan Perito forense

## 7. Almacenamiento de la Evidencia

- **Método de almacenamiento aplicado:** Almacenamiento en repositorio de github.
- **Ubicación final de las evidencias:** https://github.com/retewee11/AFI.git
- **Controles de acceso implementados:** Repositorio privado, y llevado por una unica persona.

## 8. Encargado sobre la Metodología

- **Identificación y preservación de la escena:** Manuel Maye Piulestan
- **Recolección forense:**  Manuel Maye Piulestan
- **Documentación y registro:**  Manuel Maye Piulestan
- **Custodia y almacenamiento:**  Manuel Maye Piulestan

## 9. Enlace al Repositorio de Evidencias

Las evidencias se encuentran en el siguiente repositorio:  
[\[Enlace aquí\]](https://github.com/retewee11/AFI.git)

