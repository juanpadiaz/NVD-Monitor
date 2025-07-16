#!/usr/bin/env python3
"""
NVD Vulnerability Monitor - Script de Configuración
"""

import mysql.connector
from mysql.connector import Error
import configparser
import getpass
import sys
import os

class NVDConfigurator:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config_file = '/etc/nvd-monitor/config.ini'
        
    def print_banner(self):
        print("="*60)
        print("     NVD Vulnerability Monitor - Configuración")
        print("="*60)
        print()
    
    def get_database_info(self):
        """Solicitar información de la base de datos"""
        print("📊 CONFIGURACIÓN DE BASE DE DATOS")
        print("-" * 40)
        
        db_host = input("Host de la base de datos [localhost]: ").strip() or "localhost"
        db_port = input("Puerto [3306]: ").strip() or "3306"
        db_name = input("Nombre de la base de datos [nvd_monitor]: ").strip() or "nvd_monitor"
        db_user = input("Usuario de la base de datos: ").strip()
        db_password = getpass.getpass("Contraseña de la base de datos: ")
        
        return {
            'host': db_host,
            'port': int(db_port),
            'database': db_name,
            'user': db_user,
            'password': db_password
        }
    
    def test_db_connection(self, db_config):
        """Probar conexión a la base de datos"""
        try:
            connection = mysql.connector.connect(**db_config)
            cursor = connection.cursor()
            
            # Verificar versión
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            print(f"✅ Conexión exitosa - Versión: {version}")
            
            # Verificar si es MySQL o MariaDB
            if 'MariaDB' in version:
                print("📋 Detectado: MariaDB")
            else:
                print("📋 Detectado: MySQL")
            
            cursor.close()
            connection.close()
            return True
            
        except Error as e:
            print(f"❌ Error de conexión: {e}")
            return False
    
    def create_database_tables(self, db_config):
        """Crear tablas necesarias en la base de datos"""
        try:
            connection = mysql.connector.connect(**db_config)
            cursor = connection.cursor()
            
            # Crear tabla de vulnerabilidades
            create_table_sql = """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INT AUTO_INCREMENT PRIMARY KEY,
                cve_id VARCHAR(50) UNIQUE NOT NULL,
                published_date DATETIME,
                last_modified DATETIME,
                cvss_score DECIMAL(3,1),
                cvss_severity VARCHAR(20),
                description TEXT,
                references TEXT,
                affected_products TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_cve_id (cve_id),
                INDEX idx_severity (cvss_severity),
                INDEX idx_published (published_date)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
            
            cursor.execute(create_table_sql)
            
            # Crear tabla de logs de monitoreo
            create_log_table_sql = """
            CREATE TABLE IF NOT EXISTS monitoring_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                vulnerabilities_found INT,
                status VARCHAR(50),
                message TEXT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
            
            cursor.execute(create_log_table_sql)
            
            connection.commit()
            print("✅ Tablas creadas correctamente")
            
            cursor.close()
            connection.close()
            return True
            
        except Error as e:
            print(f"❌ Error creando tablas: {e}")
            return False
    
    def get_nvd_api_key(self):
        """Solicitar API key de NVD"""
        print("\n🔑 CONFIGURACIÓN DE NVD API")
        print("-" * 40)
        print("Para obtener una API key de NVD:")
        print("1. Visita: https://nvd.nist.gov/developers/request-an-api-key")
        print("2. Completa el formulario de registro")
        print("3. Recibirás la API key por email")
        print()
        
        api_key = input("Ingresa tu API key de NVD: ").strip()
        return api_key
    
    def get_email_config(self):
        """Solicitar configuración de email"""
        print("\n📧 CONFIGURACIÓN DE EMAIL")
        print("-" * 40)
        
        smtp_server = input("Servidor SMTP [smtp.gmail.com]: ").strip() or "smtp.gmail.com"
        smtp_port = input("Puerto SMTP [587]: ").strip() or "587"
        sender_email = input("Email del remitente: ").strip()
        sender_password = getpass.getpass("Contraseña del remitente: ")
        recipient_email = input("Email del destinatario: ").strip()
        
        return {
            'smtp_server': smtp_server,
            'smtp_port': int(smtp_port),
            'sender_email': sender_email,
            'sender_password': sender_password,
            'recipient_email': recipient_email
        }
    
    def get_monitoring_config(self):
        """Solicitar configuración de monitoreo"""
        print("\n⏰ CONFIGURACIÓN DE MONITOREO")
        print("-" * 40)
        
        interval = input("Intervalo de revisión en horas [4]: ").strip() or "4"
        try:
            interval = int(interval)
            if interval < 1:
                interval = 4
        except ValueError:
            interval = 4
        
        return {'check_interval_hours': interval}
    
    def save_config(self, db_config, nvd_config, email_config, monitoring_config):
        """Guardar configuración en archivo"""
        # Configuración de base de datos
        self.config.add_section('database')
        self.config.set('database', 'host', db_config['host'])
        self.config.set('database', 'port', str(db_config['port']))
        self.config.set('database', 'database', db_config['database'])
        self.config.set('database', 'user', db_config['user'])
        self.config.set('database', 'password', db_config['password'])
        
        # Configuración de NVD
        self.config.add_section('nvd')
        self.config.set('nvd', 'api_key', nvd_config['api_key'])
        
        # Configuración de email
        self.config.add_section('email')
        self.config.set('email', 'smtp_server', email_config['smtp_server'])
        self.config.set('email', 'smtp_port', str(email_config['smtp_port']))
        self.config.set('email', 'sender_email', email_config['sender_email'])
        self.config.set('email', 'sender_password', email_config['sender_password'])
        self.config.set('email', 'recipient_email', email_config['recipient_email'])
        
        # Configuración de monitoreo
        self.config.add_section('monitoring')
        self.config.set('monitoring', 'check_interval_hours', str(monitoring_config['check_interval_hours']))
        
        # Configuración de logging
        self.config.add_section('logging')
        self.config.set('logging', 'level', 'INFO')
        self.config.set('logging', 'file', '/var/log/nvd-monitor/nvd-monitor.log')
        
        # Crear directorio de configuración si no existe
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        
        # Guardar archivo
        with open(self.config_file, 'w') as f:
            self.config.write(f)
        
        # Establecer permisos seguros
        os.chmod(self.config_file, 0o600)
        
        print(f"✅ Configuración guardada en {self.config_file}")
    
    def run(self):
        """Ejecutar configuración completa"""
        self.print_banner()
        
        # Configurar base de datos
        while True:
            db_config = self.get_database_info()
            if self.test_db_connection(db_config):
                if self.create_database_tables(db_config):
                    break
            print("\n⚠️  Reintenta la configuración de base de datos\n")
        
        # Configurar NVD API
        nvd_config = {'api_key': self.get_nvd_api_key()}
        
        # Configurar email
        email_config = self.get_email_config()
        
        # Configurar monitoreo
        monitoring_config = self.get_monitoring_config()
        
        # Guardar configuración
        self.save_config(db_config, nvd_config, email_config, monitoring_config)
        
        print("\n" + "="*60)
        print("✅ CONFIGURACIÓN COMPLETADA")
        print("="*60)
        print(f"📁 Archivo de configuración: {self.config_file}")
        print(f"⏰ Intervalo de monitoreo: {monitoring_config['check_interval_hours']} horas")
        print("\nComandos útiles:")
        print("  nvd-monitor --test-db     # Probar conexión a BD")
        print("  nvd-monitor --test-email  # Probar envío de email")
        print("  nvd-monitor --test-nvd    # Probar conexión NVD API")
        print("  nvd-monitor --run-once    # Ejecutar una vez")
        print("  systemctl start nvd-monitor  # Iniciar servicio")
        print()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse como root")
        sys.exit(1)
    
    configurator = NVDConfigurator()
    configurator.run()
