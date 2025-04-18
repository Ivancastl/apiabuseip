import random
import pandas as pd
import ipaddress
import requests
import os
import json
from cryptography.fernet import Fernet
import emoji

class IPChecker:
    def __init__(self):
        self.config_file = "ip_checker_config.enc"
        self.api_key = None
        self.load_or_request_api_key()
        
    def load_or_request_api_key(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "rb") as f:
                    encrypted_key = f.read()
                key = self.get_encryption_key()
                cipher_suite = Fernet(key)
                self.api_key = cipher_suite.decrypt(encrypted_key).decode()
            except:
                print("Error al leer la clave API guardada. Se solicitará una nueva.")
                self.request_and_save_api_key()
        else:
            self.request_and_save_api_key()
    
    def get_encryption_key(self):
        key_file = "ip_checker_key.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
        return key
    
    def request_and_save_api_key(self):
        self.api_key = input("Por favor, ingresa tu API key de AbuseIPDB: ").strip()
        key = self.get_encryption_key()
        cipher_suite = Fernet(key)
        encrypted_key = cipher_suite.encrypt(self.api_key.encode())
        with open(self.config_file, "wb") as f:
            f.write(encrypted_key)
        print("API key guardada de forma segura.")
    
    def generate_random_ips(self, start_ip, end_ip, count):
        start = int(ipaddress.IPv4Address(start_ip))
        end = int(ipaddress.IPv4Address(end_ip))

        ips = []
        for _ in range(count):
            random_ip = start + random.randint(0, end - start)
            ips.append(str(ipaddress.IPv4Address(random_ip)))
        return ips
    
    def check_ip(self, ip, days=30):
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": self.api_key}
        params = {"ipAddress": ip, "maxAgeInDays": days}
        
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            if response.status_code == 403:
                print(emoji.emojize(":warning: Error 403: Prohibido. Verifica tu clave API o restricciones de la cuenta."))
                return None
                
            return response.json()
        except requests.exceptions.RequestException as e:
            print(emoji.emojize(f":red_circle: Error en la solicitud: {e}"))
            return None
    
    def pretty_print_report(self, report):
        if not report or "data" not in report:
            print(emoji.emojize(":x: No se pudo obtener información para esta IP"))
            return
            
        data = report["data"]
        
        print(emoji.emojize("\n:mag: Reporte de IP :mag:"))
        print("-" * 40)
        print(emoji.emojize(f":globe_with_meridians: IP: {data.get('ipAddress', 'N/A')}"))
        print(emoji.emojize(f":shield: Es pública: {'Sí' if data.get('isPublic', False) else 'No'}"))
        print(emoji.emojize(f":triangular_flag: Versión IP: {data.get('ipVersion', 'N/A')}"))
        print(emoji.emojize(f":white_check_mark: Es whitelisted: {'Sí' if data.get('isWhitelisted', False) else 'No'}"))
        print(emoji.emojize(f":1234: Puntuación de abuso: {data.get('abuseConfidenceScore', 'N/A')}/100"))
        print(emoji.emojize(f":earth_americas: País: {data.get('countryCode', 'N/A')}"))
        print(emoji.emojize(f":desktop_computer: Uso: {data.get('usageType', 'N/A')}"))
        print(emoji.emojize(f":office: ISP: {data.get('isp', 'N/A')}"))
        print(emoji.emojize(f":domain: Dominio: {data.get('domain', 'N/A')}"))
        print(emoji.emojize(f":house: Hostnames: {', '.join(data.get('hostnames', [])) or 'N/A'}"))
        print(emoji.emojize(f":speech_balloon: Total reportes: {data.get('totalReports', 'N/A')}"))
        print(emoji.emojize(f":busts_in_silhouette: Usuarios distintos: {data.get('numDistinctUsers', 'N/A')}"))
        print(emoji.emojize(f":calendar: Último reporte: {data.get('lastReportedAt', 'N/A')}"))
        print("-" * 40)
    
    def check_multiple_ips(self, file_path, days=30):
        if not os.path.exists(file_path):
            print(emoji.emojize(f":x: Archivo no encontrado: {file_path}"))
            return
            
        try:
            with open(file_path, "r") as f:
                ips = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(emoji.emojize(f":x: Error al leer el archivo: {e}"))
            return
            
        if not ips:
            print(emoji.emojize(":x: No se encontraron IPs en el archivo."))
            return
            
        results = []
        print(emoji.emojize(f":hourglass_flowing_sand: Comprobando {len(ips)} IPs..."))
        
        for ip in ips:
            print(emoji.emojize(f":mag_right: Comprobando IP: {ip}"))
            report = self.check_ip(ip, days)
            
            if report and "data" in report:
                data = report["data"]
                results.append({
                    "IP": ip,
                    "Pública": "Sí" if data.get("isPublic", False) else "No",
                    "Versión IP": data.get("ipVersion", "N/A"),
                    "Whitelisted": "Sí" if data.get("isWhitelisted", False) else "No",
                    "Puntuación Abuso": data.get("abuseConfidenceScore", "N/A"),
                    "País": data.get("countryCode", "N/A"),
                    "ISP": data.get("isp", "N/A"),
                    "Dominio": data.get("domain", "N/A"),
                    "Total Reportes": data.get("totalReports", "N/A"),
                    "Último Reporte": data.get("lastReportedAt", "N/A")
                })
            else:
                results.append({
                    "IP": ip,
                    "Estado": "Error al obtener datos"
                })
        
        # Guardar resultados en Excel
        output_file = "resultados_ips.xlsx"
        df = pd.DataFrame(results)
        df.to_excel(output_file, index=False)
        print(emoji.emojize(f":white_check_mark: Resultados guardados en {output_file}"))
    
    def menu(self):
        while True:
            print("\n" + "=" * 50)
            print(emoji.emojize(":shield: IP Checker con AbuseIPDB :shield:"))
            print("=" * 50)
            print(emoji.emojize("1 :mag: Consultar reporte de una IP"))
            print(emoji.emojize("2 :file_folder: Consultar múltiples IPs desde archivo"))
            print(emoji.emojize("3 :game_die: Generar IPs aleatorias y consultar"))
            print(emoji.emojize("4 :key: Cambiar API key"))
            print(emoji.emojize("5 :door: Salir"))
            
            choice = input("\nSelecciona una opción: ").strip()
            
            if choice == "1":
                ip = input("Ingresa la IP a consultar: ").strip()
                report = self.check_ip(ip)
                self.pretty_print_report(report)
                input("\nPresiona Enter para continuar...")
                
            elif choice == "2":
                file_path = input("Ingresa la ruta del archivo con las IPs (una por línea): ").strip()
                days = input("Días a consultar (opcional, default 30): ").strip()
                days = int(days) if days.isdigit() else 30
                self.check_multiple_ips(file_path, days)
                input("\nPresiona Enter para continuar...")
                
            elif choice == "3":
                start_ip = input("Ingrese la IP de inicio del rango: ").strip()
                end_ip = input("Ingrese la IP de fin del rango: ").strip()
                num_ips = int(input("Ingrese el número de IPs aleatorias a generar: ").strip())
                
                random_ips = self.generate_random_ips(start_ip, end_ip, num_ips)
                random_file = "ips_aleatorias.txt"
                with open(random_file, "w") as f:
                    f.write("\n".join(random_ips))
                
                print(emoji.emojize(f":white_check_mark: {num_ips} IPs generadas y guardadas en {random_file}"))
                self.check_multiple_ips(random_file)
                input("\nPresiona Enter para continuar...")
                
            elif choice == "4":
                os.remove(self.config_file) if os.path.exists(self.config_file) else None
                self.load_or_request_api_key()
                
            elif choice == "5":
                print(emoji.emojize(":wave: ¡Hasta luego!"))
                break
                
            else:
                print(emoji.emojize(":x: Opción no válida. Intenta nuevamente."))

if __name__ == "__main__":
    checker = IPChecker()
    checker.menu()