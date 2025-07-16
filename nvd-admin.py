#!/usr/bin/env python3
"""
NVD Vulnerability Monitor - Comandos de Administración
"""

import argparse
import configparser
import mysql.connector
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
from datetime import datetime
import sys
import os
from tabulate import tabulate

class NVDAdmin:
    def __init__(self, config_file='/etc/nvd-monitor/config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()
    
    def load_config(self):
        """Cargar configuración"""
        try:
            self.config.read(self.config_file)
        except Exception as e:
            print(f"❌ Error cargando configuración: {e}")
            sys.exit(1)
    
    def get_database_connection(self):
        """Obtener conexión a base de datos"""
        try:
            connection = mysql.connector.connect(
                host=self.config.get('database', 'host'),
                database=self.config.get('database', 'database'),
                user=self.config.get('database', 'user'),
                password=self.config.get('database', 'password'),
                port=self.config.getint('database', 'port', fallback=3306)
            )
            return connection
        except Exception as e:
            print(f"❌ Error conectando a la base de datos: {e}")
            return None
    
    def test_database(self):
        """Probar conexión a base de datos"""
        print("🔍 Probando conexión a base de datos...")
        
        connection = self.get_database_connection()
        if not connection:
            return False
        
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            vuln_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM monitoring_logs")
            log_count = cursor.fetchone()[0]
            
            print(f"✅ Conexión exitosa")
            print(f"📊 Versión: {version}")
            print(f"🔍 Vulnerabilidades almacenadas: {vuln_count}")
            print(f"📝 Logs de monitoreo: {log_count}")
            
            cursor.close()
            connection.close()
            return True
            
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def test_nvd_api(self):
        """Probar conexión con NVD API"""
        print("🔍 Probando conexión con NVD API...")
        
        try:
            api_key = self.config.get('nvd', 'api_key')
            headers = {
                'apiKey': api_key,
                'User-Agent': 'NVD-Monitor/1.0'
            }
            
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=headers,
                params={'resultsPerPage': 1},
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            total_results = data.get('totalResults', 0)
            
            print(f"✅ Conexión con NVD API exitosa")
            print(f"📊 Total de CVEs en NVD: {total_results:,}")
            
            # Verificar límites de rate
            if results:
                headers = ['CVE ID', 'Publicado', 'CVSS', 'Severidad', 'Descripción', 'Detectado']
                
                formatted_results = []
                for row in results:
                    formatted_results.append([
                        row[0],  # CVE ID
                        row[1].strftime('%Y-%m-%d') if row[1] else 'N/A',  # Fecha publicación
                        f"{row[2]:.1f}" if row[2] else 'N/A',  # CVSS Score
                        row[3] or 'N/A',  # Severidad
                        row[4] or 'N/A',  # Descripción corta
                        row[5].strftime('%Y-%m-%d %H:%M') if row[5] else 'N/A'  # Fecha detección
                    ])
                
                print(f"\n📊 Últimas {len(results)} vulnerabilidades:")
                print(tabulate(formatted_results, headers=headers, tablefmt='grid'))
            else:
                print("ℹ️  No se encontraron vulnerabilidades")
            
            cursor.close()
            connection.close()
            
        except Exception as e:
            print(f"❌ Error consultando vulnerabilidades: {e}")
    
    def show_statistics(self):
        """Mostrar estadísticas del sistema"""
        connection = self.get_database_connection()
        if not connection:
            return
        
        try:
            cursor = connection.cursor()
            
            # Estadísticas generales
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            total_vulns = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cvss_severity = 'CRITICAL'")
            critical_vulns = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cvss_severity = 'HIGH'")
            high_vulns = cursor.fetchone()[0]
            
            cursor.execute("SELECT AVG(cvss_score) FROM vulnerabilities WHERE cvss_score IS NOT NULL")
            avg_score = cursor.fetchone()[0]
            
            # Vulnerabilidades por mes
            cursor.execute("""
                SELECT DATE_FORMAT(created_at, '%Y-%m') as month, COUNT(*) as count
                FROM vulnerabilities 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY month 
                ORDER BY month DESC
            """)
            monthly_stats = cursor.fetchall()
            
            # Top productos afectados
            cursor.execute("""
                SELECT affected_products, COUNT(*) as count
                FROM vulnerabilities 
                WHERE affected_products IS NOT NULL AND affected_products != ''
                GROUP BY affected_products 
                ORDER BY count DESC 
                LIMIT 10
            """)
            top_products = cursor.fetchall()
            
            print("\n📊 ESTADÍSTICAS DEL SISTEMA")
            print("=" * 50)
            print(f"🔍 Total vulnerabilidades: {total_vulns}")
            print(f"🔴 Críticas: {critical_vulns}")
            print(f"🟠 Altas: {high_vulns}")
            print(f"📈 Puntuación CVSS promedio: {avg_score:.2f}" if avg_score else "📈 Puntuación CVSS promedio: N/A")
            
            if monthly_stats:
                print(f"\n📅 Vulnerabilidades por mes:")
                for month, count in monthly_stats:
                    print(f"  {month}: {count}")
            
            if top_products:
                print(f"\n🎯 Productos más afectados:")
                for i, (product, count) in enumerate(top_products[:5], 1):
                    short_product = product[:50] + "..." if len(product) > 50 else product
                    print(f"  {i}. {short_product} ({count} CVEs)")
            
            cursor.close()
            connection.close()
            
        except Exception as e:
            print(f"❌ Error obteniendo estadísticas: {e}")
    
    def show_logs(self, limit=20):
        """Mostrar logs de monitoreo"""
        connection = self.get_database_connection()
        if not connection:
            return
        
        try:
            cursor = connection.cursor()
            
            cursor.execute("""
                SELECT timestamp, vulnerabilities_found, status, message
                FROM monitoring_logs 
                ORDER BY timestamp DESC 
                LIMIT %s
            """, (limit,))
            
            results = cursor.fetchall()
            
            if results:
                headers = ['Timestamp', 'Vulnerabilidades', 'Estado', 'Mensaje']
                
                formatted_results = []
                for row in results:
                    formatted_results.append([
                        row[0].strftime('%Y-%m-%d %H:%M:%S'),  # Timestamp
                        row[1] if row[1] is not None else 'N/A',  # Vulnerabilidades encontradas
                        row[2] or 'N/A',  # Estado
                        (row[3][:60] + "...") if row[3] and len(row[3]) > 60 else (row[3] or 'N/A')  # Mensaje
                    ])
                
                print(f"\n📝 Últimos {len(results)} logs de monitoreo:")
                print(tabulate(formatted_results, headers=headers, tablefmt='grid'))
            else:
                print("ℹ️  No se encontraron logs de monitoreo")
            
            cursor.close()
            connection.close()
            
        except Exception as e:
            print(f"❌ Error consultando logs: {e}")
    
    def show_config(self):
        """Mostrar configuración actual (sin contraseñas)"""
        print("\n⚙️  CONFIGURACIÓN ACTUAL")
        print("=" * 50)
        
        try:
            # Base de datos
            print("📊 Base de datos:")
            print(f"  Host: {self.config.get('database', 'host')}")
            print(f"  Puerto: {self.config.get('database', 'port')}")
            print(f"  Base de datos: {self.config.get('database', 'database')}")
            print(f"  Usuario: {self.config.get('database', 'user')}")
            print("  Contraseña: ****")
            
            # NVD API
            print("\n🔑 NVD API:")
            api_key = self.config.get('nvd', 'api_key')
            masked_key = api_key[:8] + "*" * (len(api_key) - 12) + api_key[-4:] if len(api_key) > 12 else "****"
            print(f"  API Key: {masked_key}")
            
            # Email
            print("\n📧 Email:")
            print(f"  Servidor SMTP: {self.config.get('email', 'smtp_server')}")
            print(f"  Puerto: {self.config.get('email', 'smtp_port')}")
            print(f"  Remitente: {self.config.get('email', 'sender_email')}")
            print("  Contraseña: ****")
            print(f"  Destinatario: {self.config.get('email', 'recipient_email')}")
            
            # Monitoreo
            print("\n⏰ Monitoreo:")
            print(f"  Intervalo: {self.config.get('monitoring', 'check_interval_hours')} horas")
            
            # Logging
            print("\n📝 Logging:")
            print(f"  Nivel: {self.config.get('logging', 'level')}")
            print(f"  Archivo: {self.config.get('logging', 'file')}")
            
        except Exception as e:
            print(f"❌ Error mostrando configuración: {e}")
    
    def run_manual_check(self):
        """Ejecutar verificación manual"""
        print("🔍 Ejecutando verificación manual...")
        
        try:
            import subprocess
            result = subprocess.run([
                '/usr/local/bin/nvd-monitor', '--run-once'
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print("✅ Verificación manual completada exitosamente")
                if result.stdout:
                    print(f"📄 Salida:\n{result.stdout}")
            else:
                print("❌ Error en la verificación manual")
                if result.stderr:
                    print(f"🔴 Error:\n{result.stderr}")
            
        except subprocess.TimeoutExpired:
            print("⏰ La verificación manual excedió el tiempo límite (5 minutos)")
        except Exception as e:
            print(f"❌ Error ejecutando verificación manual: {e}")
    
    def backup_database(self, output_file=None):
        """Crear respaldo de la base de datos"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"/var/lib/nvd-monitor/backup_nvd_monitor_{timestamp}.sql"
        
        print(f"💾 Creando respaldo en: {output_file}")
        
        try:
            import subprocess
            
            # Crear directorio de respaldos si no existe
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Comando mysqldump
            cmd = [
                'mysqldump',
                f"--host={self.config.get('database', 'host')}",
                f"--port={self.config.get('database', 'port')}",
                f"--user={self.config.get('database', 'user')}",
                f"--password={self.config.get('database', 'password')}",
                '--single-transaction',
                '--routines',
                '--triggers',
                self.config.get('database', 'database')
            ]
            
            with open(output_file, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                print(f"✅ Respaldo creado exitosamente: {output_file}")
                
                # Mostrar tamaño del archivo
                size = os.path.getsize(output_file)
                size_mb = size / (1024 * 1024)
                print(f"📊 Tamaño del respaldo: {size_mb:.2f} MB")
            else:
                print(f"❌ Error creando respaldo: {result.stderr}")
                
        except Exception as e:
            print(f"❌ Error en el respaldo: {e}")

def main():
    parser = argparse.ArgumentParser(description='NVD Monitor - Comandos de Administración')
    parser.add_argument('--config', default='/etc/nvd-monitor/config.ini', help='Archivo de configuración')
    
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')
    
    # Test commands
    subparsers.add_parser('test-db', help='Probar conexión a base de datos')
    subparsers.add_parser('test-nvd', help='Probar conexión NVD API')
    subparsers.add_parser('test-email', help='Probar envío de email')
    subparsers.add_parser('test-all', help='Probar todas las conexiones')
    
    # Info commands
    vuln_parser = subparsers.add_parser('show-vulns', help='Mostrar vulnerabilidades')
    vuln_parser.add_argument('--limit', type=int, default=10, help='Número de vulnerabilidades a mostrar')
    vuln_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH'], help='Filtrar por severidad')
    
    stats_parser = subparsers.add_parser('stats', help='Mostrar estadísticas')
    
    logs_parser = subparsers.add_parser('logs', help='Mostrar logs de monitoreo')
    logs_parser.add_argument('--limit', type=int, default=20, help='Número de logs a mostrar')
    
    subparsers.add_parser('config', help='Mostrar configuración actual')
    
    # Action commands
    subparsers.add_parser('check', help='Ejecutar verificación manual')
    
    backup_parser = subparsers.add_parser('backup', help='Crear respaldo de base de datos')
    backup_parser.add_argument('--output', help='Archivo de salida para el respaldo')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    admin = NVDAdmin(args.config)
    
    if args.command == 'test-db':
        success = admin.test_database()
        sys.exit(0 if success else 1)
    
    elif args.command == 'test-nvd':
        success = admin.test_nvd_api()
        sys.exit(0 if success else 1)
    
    elif args.command == 'test-email':
        success = admin.test_email()
        sys.exit(0 if success else 1)
    
    elif args.command == 'test-all':
        print("🔍 Probando todas las conexiones...\n")
        db_ok = admin.test_database()
        print()
        nvd_ok = admin.test_nvd_api()
        print()
        email_ok = admin.test_email()
        print()
        
        if db_ok and nvd_ok and email_ok:
            print("✅ Todas las pruebas pasaron correctamente")
            sys.exit(0)
        else:
            print("❌ Algunas pruebas fallaron")
            sys.exit(1)
    
    elif args.command == 'show-vulns':
        admin.show_vulnerabilities(args.limit, args.severity)
    
    elif args.command == 'stats':
        admin.show_statistics()
    
    elif args.command == 'logs':
        admin.show_logs(args.limit)
    
    elif args.command == 'config':
        admin.show_config()
    
    elif args.command == 'check':
        admin.run_manual_check()
    
    elif args.command == 'backup':
        admin.backup_database(args.output)

if __name__ == "__main__":
    main() 'X-RateLimit-Remaining' in response.headers:
                remaining = response.headers['X-RateLimit-Remaining']
                print(f"🚦 Requests restantes: {remaining}")
            
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Error de conexión: {e}")
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def test_email(self):
        """Probar envío de email"""
        print("🔍 Probando configuración de email...")
        
        try:
            smtp_server = self.config.get('email', 'smtp_server')
            smtp_port = self.config.getint('email', 'smtp_port')
            sender_email = self.config.get('email', 'sender_email')
            sender_password = self.config.get('email', 'sender_password')
            recipient_email = self.config.get('email', 'recipient_email')
            
            # Probar conexión SMTP
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            
            # Crear mensaje de prueba
            message = MIMEMultipart()
            message["From"] = sender_email
            message["To"] = recipient_email
            message["Subject"] = "NVD Monitor - Test de Configuración"
            
            body = f"""
            <html>
            <body>
                <h2>Prueba de configuración de NVD Monitor</h2>
                <p>Este es un email de prueba del sistema de monitoreo de vulnerabilidades.</p>
                <p><strong>Fecha:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Estado:</strong> ✅ Configuración exitosa</p>
            </body>
            </html>
            """
            
            message.attach(MIMEText(body, "html"))
            
            # Enviar email
            server.send_message(message)
            server.quit()
            
            print(f"✅ Email de prueba enviado exitosamente")
            print(f"📧 Destinatario: {recipient_email}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error enviando email: {e}")
            return False
    
    def show_vulnerabilities(self, limit=10, severity=None):
        """Mostrar vulnerabilidades almacenadas"""
        connection = self.get_database_connection()
        if not connection:
            return
        
        try:
            cursor = connection.cursor()
            
            query = """
            SELECT cve_id, published_date, cvss_score, cvss_severity, 
                   LEFT(description, 80) as short_desc, created_at
            FROM vulnerabilities
            """
            
            params = []
            if severity:
                query += " WHERE cvss_severity = %s"
                params.append(severity)
            
            query += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            
            if