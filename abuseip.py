import random
import pandas as pd
import ipaddress
import requests
import os
import json
from cryptography.fernet import Fernet
import emoji
import pyfiglet

class AbuseIPHunter:
    def __init__(self):
        self.config_file = "abuseip_hunter_config.enc"
        self.key_file = "abuseip_hunter_key.key"
        self.api_key = None
        self.load_or_request_api_key()
        self.show_banner()
        
    def show_banner(self):
        """Muestra el banner ASCII art"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(pyfiglet.figlet_format("AbuseIP Hunter", font="slant"))
        print(emoji.emojize(":shield: Herramienta profesional de análisis de IPs con AbuseIPDB"))
        print(emoji.emojize(":keyboard: Creado por @ivancastl | Telegram: t.me/+_g4DIczsuI9hOWZh"))
        print("="*60 + "\n")
    
    def get_encryption_key(self):
        """Genera o recupera la clave de encriptación"""
        if not os.path.exists(self.key_file):
            with open(self.key_file, "wb") as f:
                f.write(Fernet.generate_key())
        with open(self.key_file, "rb") as f:
            return f.read()
    
    def load_or_request_api_key(self):
        """Carga o solicita la API key"""
        if os.path.exists(self.config_file):
            try:
                cipher_suite = Fernet(self.get_encryption_key())
                with open(self.config_file, "rb") as f:
                    encrypted_data = f.read()
                self.api_key = cipher_suite.decrypt(encrypted_data).decode()
            except Exception as e:
                print(emoji.emojize(f":warning: Error cargando API key: {e}"))
                self.request_and_save_api_key()
        else:
            self.request_and_save_api_key()
    
    def request_and_save_api_key(self):
        """Solicita y guarda la API key de forma segura"""
        self.api_key = input(emoji.emojize(":key: Ingresa tu API key de AbuseIPDB: ")).strip()
        cipher_suite = Fernet(self.get_encryption_key())
        encrypted_data = cipher_suite.encrypt(self.api_key.encode())
        with open(self.config_file, "wb") as f:
            f.write(encrypted_data)
        print(emoji.emojize(":white_check_mark: API key guardada de forma segura"))
    
    def generate_random_ips(self, start_ip, end_ip, count):
        """Genera IPs aleatorias dentro de un rango"""
        start = int(ipaddress.IPv4Address(start_ip))
        end = int(ipaddress.IPv4Address(end_ip))
        return [str(ipaddress.IPv4Address(start + random.randint(0, end - start))) for _ in range(count)]
    
    def check_ip(self, ip, days=30):
        """Consulta información de una IP en AbuseIPDB"""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": self.api_key}
        params = {"ipAddress": ip, "maxAgeInDays": days}
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=15)
            response.raise_for_status()
            return response.json() if response.status_code != 403 else None
        except requests.exceptions.RequestException as e:
            print(emoji.emojize(f":red_circle: Error en la solicitud: {e}"))
            return None
    
    def pretty_print_report(self, report):
        """Muestra un reporte formateado con emojis"""
        if not report or "data" not in report:
            print(emoji.emojize(":x: No se pudo obtener información para esta IP"))
            return
            
        data = report["data"]
        print(emoji.emojize("\n:detective: Reporte Detallado de IP"))
        print("-"*60)
        print(emoji.emojize(f":globe_with_meridians: IP: {data.get('ipAddress', 'N/A')}"))
        print(emoji.emojize(f":shield: Pública: {'Sí' if data.get('isPublic', False) else 'No'}"))
        print(emoji.emojize(f":abacus: Puntuación Abuso: {data.get('abuseConfidenceScore', 'N/A')}/100"))
        print(emoji.emojize(f":earth_americas: País: {data.get('countryCode', 'N/A')}"))
        print(emoji.emojize(f":office: ISP: {data.get('isp', 'N/A')}"))
        print(emoji.emojize(f":speech_balloon: Reportes: {data.get('totalReports', 'N/A')}"))
        print(emoji.emojize(f":calendar: Último Reporte: {data.get('lastReportedAt', 'N/A')}"))
        print("-"*60)
    
    def check_multiple_ips(self, file_path, days=30):
        """Procesa múltiples IPs desde un archivo"""
        if not os.path.exists(file_path):
            print(emoji.emojize(f":x: Archivo no encontrado: {file_path}"))
            return []

        try:
            with open(file_path, "r") as f:
                ips = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(emoji.emojize(f":x: Error leyendo archivo: {e}"))
            return []

        if not ips:
            print(emoji.emojize(":x: No se encontraron IPs válidas en el archivo"))
            return []

        results = []
        print(emoji.emojize(f":hourglass_flowing_sand: Analizando {len(ips)} IPs..."))
        
        for ip in ips:
            print(emoji.emojize(f":mag: Procesando IP: {ip}"))
            report = self.check_ip(ip, days)
            
            if report and "data" in report:
                data = report["data"]
                results.append({
                    "IP": ip,
                    "Pública": "Sí" if data.get("isPublic") else "No",
                    "Puntuación": data.get("abuseConfidenceScore", "N/A"),
                    "País": data.get("countryCode", "N/A"),
                    "ISP": data.get("isp", "N/A"),
                    "Reportes": data.get("totalReports", "N/A"),
                    "Último Reporte": data.get("lastReportedAt", "N/A")
                })
            else:
                results.append({"IP": ip, "Estado": "Error"})

        output_file = "resultados_ips.xlsx"
        pd.DataFrame(results).to_excel(output_file, index=False)
        print(emoji.emojize(f":floppy_disk: Resultados guardados en {output_file}"))
        return results

    def menu(self):
        """Menú interactivo principal"""
        while True:
            self.show_banner()
            print(emoji.emojize("1 :detective: Consultar IP individual"))
            print(emoji.emojize("2 :file_folder: Analizar IPs desde archivo"))
            print(emoji.emojize("3 :game_die: Generar IPs aleatorias"))
            print(emoji.emojize("4 :key: Cambiar API Key"))
            print(emoji.emojize("5 :door: Salir\n"))
            
            choice = input(emoji.emojize(":triangular_flag: Selecciona una opción: ")).strip()
            
            if choice == "1":
                self.consultar_ip_individual()
            elif choice == "2":
                self.analizar_ips_archivo()
            elif choice == "3":
                self.generar_ips_aleatorias()
            elif choice == "4":
                self.cambiar_api_key()
            elif choice == "5":
                print(emoji.emojize("\n:wave: ¡Hasta pronto!"))
                break
            else:
                print(emoji.emojize("\n:x: Opción no válida"))
                input("\nPresiona Enter para continuar...")

    def consultar_ip_individual(self):
        """Maneja la consulta de IP individual"""
        self.show_banner()
        ip = input(emoji.emojize(":globe_with_meridians: Ingresa la IP a consultar: ")).strip()
        days = input(emoji.emojize(":calendar: Días a consultar (opcional, default 30): ")).strip()
        days = int(days) if days.isdigit() else 30
        
        report = self.check_ip(ip, days)
        self.pretty_print_report(report)
        input("\nPresiona Enter para continuar...")

    def analizar_ips_archivo(self):
        """Maneja el análisis de IPs desde archivo"""
        self.show_banner()
        file_path = input(emoji.emojize(":file_folder: Ruta del archivo con IPs (una por línea): ")).strip()
        days = input(emoji.emojize(":calendar: Días a consultar (opcional, default 30): ")).strip()
        days = int(days) if days.isdigit() else 30
        
        self.check_multiple_ips(file_path, days)
        input("\nPresiona Enter para continuar...")

    def generar_ips_aleatorias(self):
        """Genera y analiza IPs aleatorias"""
        self.show_banner()
        print(emoji.emojize(":game_die: Generador de IPs aleatorias\n"))
        start_ip = input("IP de inicio del rango: ").strip()
        end_ip = input("IP de fin del rango: ").strip()
        num_ips = int(input("Cantidad de IPs a generar: ").strip())
        
        ips = self.generate_random_ips(start_ip, end_ip, num_ips)
        random_file = "ips_aleatorias.txt"
        with open(random_file, "w") as f:
            f.write("\n".join(ips))
        
        print(emoji.emojize(f"\n:white_check_mark: {num_ips} IPs generadas en {random_file}"))
        self.check_multiple_ips(random_file)
        input("\nPresiona Enter para continuar...")

    def cambiar_api_key(self):
        """Permite cambiar la API key"""
        os.remove(self.config_file) if os.path.exists(self.config_file) else None
        self.load_or_request_api_key()
        input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    try:
        hunter = AbuseIPHunter()
        hunter.menu()
    except KeyboardInterrupt:
        print(emoji.emojize("\n:stop_sign: Programa interrumpido por el usuario"))
    except Exception as e:
        print(emoji.emojize(f"\n:red_circle: Error crítico: {e}"))