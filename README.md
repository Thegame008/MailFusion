# 🚀 MailFusion - Generador Avanzado de Correos Electrónicos

            ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
           ▓ ░▒▓███████▓▒░ MAILFUSION ░▒▓███████▓▒░ ▓
            ▓                                      ▓
           ▓  [✓] Email Combinations: ∞             ▓
            ▓ [✓] Security Mode: ENCRYPTED         ▓
           ▓  [✓] Pentester: Thegame008             ▓
            ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
                           \  📧   /
                          ▄▄███████▄▄
                          ██░░░░░░░██
                          ██░░░░░░░██

**MailFusion** es una herramienta poderosa para generar combinaciones ilimitadas de direcciones de correo electrónico mediante patrones personalizados. Perfecto para pruebas de seguridad, marketing o creación de bases de datos.

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

## 🌟 Características Principales
- 🔧 **Sistema de Payloads** avanzado con múltiples tokens
- 📁 Soporte para **TXT, CSV y JSON**
- 🛡️ Modo de enmascaramiento de datos sensible
- 🔄 Plantillas predefinidas para uso rápido
- 📊 Generación con estadísticas en tiempo real
- 💻 Compatible con **Windows, Linux y macOS**

## 📦 Instalación

### Requisitos Previos
- Python 3.8+
- pip (Gestor de paquetes Python)

### Linux/macOS
```bash
# Clonar repositorio
git clone https://github.com/tuusuario/mailfusion.git
cd mailfusion

# Instalar dependencias
pip install -r requirements.txt

# Dar permisos de ejecución
chmod +x mailfusion.py
```

🚀 Uso Básico
```bash
# Mostrar ayuda completa
python mailfusion.py -h
```
# Ejemplo básico con apellidos
```bash
python mailfusion.py -l apellidos.txt -d empresa.com -p '[ABC][lastname]'
```
# Usar plantilla predefinida
python mailfusion.py -n nombres.txt -l apellidos.txt -d empresa.com -t first.last

🎯 Ejemplos Avanzados
1. Generar usuarios corporativos
```bash
python mailfusion.py -n empleados.txt -d corporacion.com -p '[name][".123"]' --case lower -o usuarios.csv
```
2. Combinaciones con seguridad
```bash
python mailfusion.py -l clientes.txt -d prueba.com --mask --max-results 1000 --csv-delimiter "|"
```
3. Generación masiva con múltiples elementos
```bash
python mailfusion.py -d sistema.com -p '[ABC:2][year]["_"][123:4]' -o datos.json
```

🔧 Parámetros Principales


-n/--names	Archivo con nombres (uno por línea)

-l/--lastnames	Archivo con apellidos

-d/--domain	Dominio para los correos (requerido)

-p/--payload	Formato personalizado (ej: [ABC][lastname])

-t/--template	Plantilla predefinida (firstlast, first.last)

-o/--output	Archivo de salida (.txt, .csv, .json)

--mask	Enmascara los correos generados

--max-results	Límite de resultados a generar

