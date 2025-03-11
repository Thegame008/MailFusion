#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import itertools
import string
import sys
import os
from datetime import datetime
import csv
import json
import re
import tldextract
import unicodedata
import hashlib
import logging
from typing import Generator, List, Tuple

# Configuración inicial de logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def imprimir_banner():
    banner = r"""
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
    """
    print("\033[92m" + banner + "\033[0m")

class EmailGenerator:
    def __init__(self):
        self.start_time = datetime.now()
        self.stats = {
            'total_generated': 0,
            'duplicates': 0,
            'invalid_emails': 0
        }

    def _normalize_text(self, text: str, case: str = None) -> str:
        """Normaliza texto y maneja casos especiales"""
        text = unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('utf-8')
        if case == 'lower':
            return text.lower()
        if case == 'upper':
            return text.upper()
        if case == 'capitalize':
            return text.capitalize()
        return text

    def _validar_dominio(self, dominio: str) -> str:
        """Valida y normaliza el dominio usando tldextract"""
        extracted = tldextract.extract(dominio)
        if not extracted.suffix or not extracted.domain:
            raise ValueError(f"Dominio inválido: {dominio}")
        return f"{extracted.domain}.{extracted.suffix}".lower()

    def leer_archivo(self, archivo: str, required: bool = False) -> List[str]:
        """Lee y valida archivos de entrada"""
        try:
            with open(archivo, 'r', encoding='utf-8') as f:
                lineas = [line.strip() for line in f if line.strip()]
            if not lineas and required:
                raise ValueError(f"Archivo vacío: {archivo}")
            return lineas
        except FileNotFoundError:
            if required:
                logger.error(f"Archivo requerido no encontrado: {archivo}")
                sys.exit(1)
            return []

    def parse_payload(self, payload: str, templates: dict) -> List[Tuple]:
        """Parsea el payload con soporte para templates y tokens avanzados"""
        if payload in templates:
            payload = templates[payload]

        pattern = r'\[(.*?)\]'
        tokens = re.findall(pattern, payload)
        parsed = []
        
        for token in tokens:
            if token.startswith('ABC'):
                length = 1
                if ':' in token:
                    length = int(token.split(':')[1])
                parsed.append(('abc', [''.join(c) for c in itertools.product(string.ascii_lowercase, repeat=length)]))
            elif token.startswith('123'):
                # Genera combinaciones numéricas con cantidad fija o rango.
                if ':' in token:
                    param = token.split(':', 1)[1]
                    if '-' in param:
                        low, high = param.split('-')
                        low = int(low)
                        high = int(high)
                        combos = []
                        for n in range(low, high + 1):
                            combos.extend([''.join(p) for p in itertools.product(string.digits, repeat=n)])
                    else:
                        n = int(param)
                        combos = [''.join(p) for p in itertools.product(string.digits, repeat=n)]
                else:
                    combos = list(string.digits)
                parsed.append(('digits', combos))
            elif token == 'name':
                parsed.append(('name', None))
            elif token == 'lastname':
                parsed.append(('lastname', None))
            elif re.match(r'^[\'"].*?[\'"]$', token):
                # Se toma cualquier cadena entre comillas de forma literal.
                literal = token[1:-1]
                parsed.append(('delimiter', [literal]))
            # Si el token es un único carácter no alfanumérico se interpreta como literal.
            elif len(token) == 1 and not token.isalnum():
                parsed.append(('delimiter', [token]))
            elif token == 'year':
                parsed.append(('year', [str(datetime.now().year)]))
            else:
                logger.error(f"Token desconocido: [{token}]")
                sys.exit(1)
        return parsed

    def validar_payload(self, parsed_payload: List[Tuple], args: argparse.Namespace):
        """Valida la consistencia del payload con los argumentos"""
        present_tokens = {t[0] for t in parsed_payload}
        
        if 'name' in present_tokens and not args.names:
            logger.error("Se requiere el argumento -n/--names para usar [name]")
            sys.exit(1)
        if 'lastname' in present_tokens and not args.lastnames:
            logger.error("Se requiere el argumento -l/--lastnames para usar [lastname]")
            sys.exit(1)

    def generar_combinaciones(self, names: List[str], lastnames: List[str], 
                               parsed_payload: List[Tuple], args: argparse.Namespace) -> Generator[str, None, None]:
        """Genera combinaciones con manejo eficiente de memoria"""
        components = []
        seen = set()
        max_results = args.max_results if args.max_results else float('inf')
        
        for token_type, values in parsed_payload:
            if token_type == 'abc':
                components.append(values)
            elif token_type == 'digits':
                components.append(values)
            elif token_type == 'name':
                components.append([self._normalize_text(n, args.case) for n in names])
            elif token_type == 'lastname':
                components.append([self._normalize_text(l, args.case) for l in lastnames])
            elif token_type == 'delimiter':
                components.append(values)
            elif token_type == 'year':
                components.append(values)

        for combination in itertools.product(*components):
            if self.stats['total_generated'] >= max_results:
                return
            local_part = ''.join(combination)
            # Se considera inválido si la parte local excede 64 caracteres.
            if len(local_part) > 64:
                self.stats['invalid_emails'] += 1
                continue
            if local_part in seen:
                self.stats['duplicates'] += 1
                if not args.allow_duplicates:
                    continue
            else:
                seen.add(local_part)
            yield local_part
            self.stats['total_generated'] += 1

    def generar_correos(self, args: argparse.Namespace) -> List[str]:
        """Flujo principal de generación de correos"""
        templates = {
            'firstlast': '[name][lastname]',
            'first.last': '[name]["."][lastname]',
            'abc.last': '[ABC][lastname]',
            'f.last': '[ABC:1][lastname]'
        }

        domain = self._validar_dominio(args.domain)
        names = self.leer_archivo(args.names, required='name' in args.payload) if args.names else ['']
        lastnames = self.leer_archivo(args.lastnames, required='lastname' in args.payload) if args.lastnames else ['']
        
        parsed_payload = self.parse_payload(args.payload, templates)
        self.validar_payload(parsed_payload, args)

        combinaciones = self.generar_combinaciones(names, lastnames, parsed_payload, args)
        
        if args.mask:
            return [f"{hashlib.sha256(local.encode()).hexdigest()[:8]}@{domain}" for local in combinaciones]
        
        return [f"{local}@{domain}" for local in combinaciones]

    def exportar_resultados(self, correos: List[str], args: argparse.Namespace):
        """Exporta resultados en múltiples formatos"""
        if not correos:
            logger.warning("No se generaron correos electrónicos")
            return

        if not args.output:
            timestamp = self.start_time.strftime("%Y%m%d-%H%M%S")
            args.output = f"emails_{timestamp}.txt"

        try:
            if args.output.endswith('.csv'):
                with open(args.output, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f, delimiter=args.csv_delimiter)
                    if args.csv_header:
                        writer.writerow([args.csv_header])
                    writer.writerows([[email] for email in correos])
            elif args.output.endswith('.json'):
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump({"emails": correos}, f)
            else:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(correos))
                    
            logger.info(f"Archivo generado exitosamente: {os.path.abspath(args.output)}")
            
        except Exception as e:
            logger.error(f"Error al escribir archivo: {str(e)}")
            sys.exit(1)

    def mostrar_estadisticas(self, output_file: str):
        duration = (datetime.now() - self.start_time).total_seconds()
        correos_generados = format(self.stats['total_generated'], ",").replace(",", ".")
        stats = (
            f"\nEstadísticas finales:"
            f"\n- Tiempo total: {duration:.2f}s"
            f"\n- Correos generados: {correos_generados}"
            f"\n- Archivo guardado en: {os.path.abspath(output_file)}"
        )
        logger.info(stats)

def parse_args():
    parser = argparse.ArgumentParser(
        description='🚀 GENERADOR AVANZADO DE CORREOS ELECTRÓNICOS - Ayuda Completa 🚀',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        epilog="""
📘 GUÍA COMPLETA DE USO 📘

💡 CONCEPTOS CLAVE:
• Payload: Molde para crear correos usando tokens entre []
• Tokens disponibles:
  → [ABC]         : Letras del abecedario (a-z)
  → [ABC:2]       : Combinaciones de 2 letras (aa, ab, ..., zz)
  → [123]         : Dígitos numéricos (0-9)
  → [123:2]       : Combinaciones de 2 dígitos (00, 01, …, 99)
  → [123:1-2]     : Combinaciones de 1 y 2 dígitos (0-9 y 00-99)
  → ['literal']   : Cualquier carácter o cadena literal (se toma tal cual, por ejemplo: . - , * + _ etc.)
  → [name]        : Nombres del archivo (-n)
  → [lastname]    : Apellidos del archivo (-l)
  → [year]        : Año actual

Ejemplos:
1. python mailfusion.py -l apellidos.txt -d empresa.com -p '[ABC][lastname]'
2. python mailfusion.py -n nombres.txt -l apellidos.txt -d empresa.com -p '[name]["."][lastname]'
3. python mailfusion.py -n empleados.txt -l apellidos.txt -d empresa.com -t first.last
4. python mailfusion.py -d sistema.com -p '[ABC:2][123:3]' -o usuarios.csv
5. python mailfusion.py -l clientes.txt -d test.com --mask --max-results 100

Opciones avanzadas:
• --case (lower/upper/capitalize)
• --max-results
• --dry-run (muestra primeros 5 correos)
• --verbose

Formatos de salida: .txt, .csv, .json

TIPS:
• --mask enmascara los correos
• Verifique con --dry-run antes de generar
        """
    )

    grupo_principal = parser.add_argument_group('🚩 OPCIONES PRINCIPALES')
    grupo_principal.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                                 help='Muestra esta ayuda completa y sale')
    grupo_principal.add_argument('-n', '--names', metavar='ARCHIVO', 
                                help='▼ Archivo con nombres (uno por línea)\nEjemplo: nombres.txt con:\n  Juan\n  Maria\n  Pedro')
    grupo_principal.add_argument('-l', '--lastnames', metavar='ARCHIVO',
                                help='▼ Archivo con apellidos (uno por línea)\nEjemplo: apellidos.txt con:\n  Gomez\n  Rodriguez\n  Perez')
    grupo_principal.add_argument('-d', '--domain', required=True, metavar='DOMINIO',
                                help='▼ Dominio para los correos (requerido)\nEjemplo: empresa.com')
    grupo_principal.add_argument('-p', '--payload', metavar='FORMATO',
                                help='▼ Formato personalizado usando tokens\nEjemplo: "[ABC][123][lastname]"\nGeneraría: a1Gomez, b1Gomez,... z9Perez')
    grupo_principal.add_argument('-t', '--template', metavar='PLANTILLA',
                                choices=['firstlast', 'first.last', 'abc.last', 'f.last'],
                                help='▼ Plantilla predefinida (alternativa a -p)\nOpciones:\n  • firstlast  → [name][lastname]\n  • first.last → [name]["."][lastname]\n  • abc.last   → [ABC][lastname]\n  • f.last     → [ABC:1][lastname]')
    grupo_principal.add_argument('-o', '--output', metavar='ARCHIVO',
                                help='▼ Archivo de salida (extensiones válidas: .txt, .csv, .json)\nEjemplos:\n  correos.txt\n  datos.csv\n  emails.json')

    grupo_formato = parser.add_argument_group('🎨 OPCIONES DE FORMATO')
    grupo_formato.add_argument('--case', choices=['lower', 'upper', 'capitalize'], 
                             help='▼ Normalización de mayúsculas\n• lower: juanperez@...\n• upper: JUANPEREZ@...\n• capitalize: Juanperez@...')
    grupo_formato.add_argument('--csv-delimiter', default=',', metavar='CARACTER',
                             help='▼ Delimitador para CSV (default: ,)\nEjemplo: ";" para Excel en español')
    grupo_formato.add_argument('--csv-header', metavar='TEXTO',
                             help='▼ Encabezado para columna CSV\nEjemplo: "Correo Electrónico"')
    grupo_formato.add_argument('--max-results', type=int, metavar='NUMERO',
                             help='▼ Límite máximo de correos a generar\nEjemplo: 100 → genera solo primeros 100')

    grupo_seguridad = parser.add_argument_group('🔐 OPCIONES DE SEGURIDAD')
    grupo_seguridad.add_argument('--mask', action='store_true',
                               help='▼ Enmascara los correos generados\nEjemplo: juan@... → a1b2c3d4@...')
    grupo_seguridad.add_argument('--allow-duplicates', action='store_true',
                               help='▼ Permite correos duplicados (por defecto se eliminan duplicados)')

    grupo_diag = parser.add_argument_group('🔧 HERRAMIENTAS DE DIAGNÓSTICO')
    grupo_diag.add_argument('-v', '--verbose', action='store_true',
                          help='▼ Modo detallado (muestra el progreso)')
    grupo_diag.add_argument('--dry-run', action='store_true',
                          help='▼ Previsualización sin guardar (muestra primeros 5 correos)')

    return parser.parse_args()

def main():
    # Imprime el banner ASCII al inicio
    imprimir_banner()
    
    args = parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    generator = EmailGenerator()
    
    try:
        if args.template and args.payload:
            logger.error("Usar --template o --payload, no ambos")
            sys.exit(1)
            
        if args.template:
            args.payload = args.template

        if not args.payload:
            logger.error("Se requiere --payload o --template")
            sys.exit(1)

        correos = generator.generar_correos(args)
        
        if args.dry_run:
            print("\nPrevisualización (primeros 5 correos):")
            print('\n'.join(correos[:5]))
            return
            
        generator.exportar_resultados(correos, args)
        generator.mostrar_estadisticas(args.output)

    except Exception as e:
        logger.error(f"Error crítico: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
