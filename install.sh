#!/bin/bash

# NVD Vulnerability Monitor - Script de Instalación
# Para Ubuntu 24.04

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Funciones de utilidad
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar que se ejecuta como root
if [[ $EUID -ne 0 ]]; then
   log_error "Este script debe ejecutarse como root"
   exit 1
fi

# Verificar Ubuntu 24.04
if ! grep -q "Ubuntu 24.04" /etc/os-release; then
    log_warn "Este script está diseñado para Ubuntu 24.04"
    read -p "¿Desea continuar? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

log_info "Iniciando instalación de NVD Vulnerability Monitor"

# Actualizar sistema
log_info "Actualizando sistema..."
apt update && apt upgrade -y

# Instalar dependencias del sistema
log_info "Instalando dependencias del sistema..."
apt install -y python3 python3-pip python3-venv curl wget git systemd mysql-server

# Crear usuario del sistema
log_info "Creando usuario del sistema..."
useradd -r -s /bin/false -d /opt/nvd-monitor nvd-monitor || true

# Crear directorios
log_info "Creando estructura de directorios..."
mkdir -p /opt/nvd-monitor
mkdir -p /etc/nvd-monitor
mkdir -p /var/log/nvd-monitor
mkdir -p /var/lib/nvd-monitor

# Crear entorno virtual de Python
log_info "Configurando entorno virtual de Python..."
python3 -m venv /opt/nvd-monitor/venv
source /opt/nvd-monitor/venv/bin/activate

# Instalar dependencias de Python
log_info "Instalando dependencias de Python..."
pip install --upgrade pip
pip install requests mysql-connector-python schedule configparser

# Crear archivo requirements.txt
cat > /opt/nvd-monitor/requirements.txt << EOF
requests>=2.31.0
mysql-connector-python>=8.0.33
schedule>=1.2.0
configparser>=5.3.0
EOF

# Copiar aplicación principal
log_info "Instalando aplicación principal..."
cat > /opt/nvd-monitor/nvd-monitor.py << 'EOF'
#!/usr/bin/env python3
"""
NVD Vulnerability Monitor
Sistema de monitoreo de vulnerabilidades críticas desde la National Vulnerability Database
"""

import requests
import json
import mysql.connector
from mysql.connector import Error
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import configparser
import logging
import time
import schedule
from datetime import datetime, timedelta
import sys
import os
import argparse
from typing import List, Dict, Optional

class NVDMonitor:
    def __init__(self, config_file: str = '/etc/nvd-monitor/config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()
        self.setup_logging()
        
    def load_config(self):
        """Cargar configuración desde archivo"""
        try:
            self.config.read(self.config_file)
        except Exception as e:
            print(f"Error cargando configuración: {e}")
            sys.exit(1)
    
    def setup_logging(self):
        """Configurar sistema de logging"""
        log_level = self.config.get('logging', 'level', fallback='INFO')
        log_file = self.config.get('logging', 'file', fallback='/var/log/nvd-monitor/nvd-monitor.log')
        
        # Crear directorio de logs si no existe
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def get_database_connection(self):
        """Obtener conexión a la base de datos"""
        try:
            connection = mysql.connector.connect(
                host=self.config.get('database', 'host'),
                database=self.config.get('database', 'database'),
                user=self.config.get('database', 'user'),
                password=self.config.get('database', 'password'),
                port=self.config.getint('database', 'port', fallback=3306)
            )
            return connection
        except Error as e:
            self.logger.error(f"Error conectando a la base de datos: {e}")
            return None
    
    def test_database_connection(self) -> bool:
        """Probar conexión a la base de datos"""
        connection = self.get_database_connection()
        if connection:
            connection.close()
            self.logger.info("Conexión a base de datos exitosa")
            return True
        return False
    
    def fetch_nvd_vulnerabilities(self) -> List[Dict]:
        """Obtener vulnerabilidades desde NVD API"""
        api_key = self.config.get('nvd', 'api_key')
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Calcular fecha desde la última consulta
        hours_back = self.config.getint('monitoring', 'check_interval_hours', fallback=4)
        start_date = (datetime.now() - timedelta(hours=hours_back)).strftime('%Y-%m-%dT%H:%M:%S.000')
        
        headers = {
            'apiKey': api_key,
            'User-Agent': 'NVD-Monitor/1.0'
        }
        
        params = {
            'lastModStartDate': start_date,
            'resultsPerPage': 500
        }
        
        try:
            response = requests.get(base_url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = []
            
            for cve in data.get('vulnerabilities', []):
                cve_data = cve.get('cve', {})
                
                # Extraer información de CVSS
                cvss_score = None
                cvss_severity = None
                
                metrics = cve_data.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    cvss_v31 = metrics['cvssMetricV31'][0]
                    cvss_score = cvss_v31.get('cvssData', {}).get('baseScore')
                    cvss_severity = cvss_v31.get('cvssData', {}).get('baseSeverity')
                elif 'cvssMetricV30' in metrics:
                    cvss_v30 = metrics['cvssMetricV30'][0]
                    cvss_score = cvss_v30.get('cvssData', {}).get('baseScore')
                    cvss_severity = cvss_v30.get('cvssData', {}).get('baseSeverity')
                
                # Filtrar por severidad (CRITICAL, HIGH) y zero-day
                if cvss_severity in ['CRITICAL', 'HIGH']:
                    # Verificar si es zero-day (publicado recientemente)
                    published_date = cve_data.get('published', '')
                    
                    vulnerability = {
                        'cve_id': cve_data.get('id', ''),
                        'published_date': published_date,
                        'last_modified': cve_data.get('lastModified', ''),
                        'cvss_score': cvss_score,
                        'cvss_severity': cvss_severity,
                        'description': self.get_description(cve_data),
                        'references': self.get_references(cve_data),
                        'affected_products': self.get_affected_products(cve_data)
                    }
                    vulnerabilities.append(vulnerability)
            
            self.logger.info(f"Encontradas {len(vulnerabilities)} vulnerabilidades críticas/altas")
            return vulnerabilities
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error consultando NVD API: {e}")
            return []
    
    def get_description(self, cve_data: Dict) -> str:
        """Extraer descripción del CVE"""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        return ''
    
    def get_references(self, cve_data: Dict) -> str:
        """Extraer referencias del CVE"""
        references = cve_data.get('references', [])
        ref_urls = [ref.get('url', '') for ref in references[:5]]  # Limitar a 5 referencias
        return ', '.join(ref_urls)
    
    def get_affected_products(self, cve_data: Dict) -> str:
        """Extraer productos afectados"""
        configurations = cve_data.get('configurations', [])
        products = []
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    if cpe.get('vulnerable', False):
                        cpe_name = cpe.get('criteria', '').split(':')
                        if len(cpe_name) >= 5:
                            product = f"{cpe_name[3]}:{cpe_name[4]}"
                            products.append(product)
        
        return ', '.join(list(set(products))[:10])  # Limitar a 10 productos únicos
    
    def save_to_database(self, vulnerabilities: List[Dict]):
        """Guardar vulnerabilidades en la base de datos"""
        connection = self.get_database_connection()
        if not connection:
            return
        
        cursor = connection.cursor()
        
        try:
            for vuln in vulnerabilities:
                # Verificar si ya existe
                check_query = "SELECT id FROM vulnerabilities WHERE cve_id = %s"
                cursor.execute(check_query, (vuln['cve_id'],))
                
                if cursor.fetchone() is None:
                    # Insertar nueva vulnerabilidad
                    insert_query = """
                    INSERT INTO vulnerabilities 
                    (cve_id, published_date, last_modified, cvss_score, cvss_severity, 
                     description, references, affected_products, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    
                    cursor.execute(insert_query, (
                        vuln['cve_id'],
                        vuln['published_date'],
                        vuln['last_modified'],
                        vuln['cvss_score'],
                        vuln['cvss_severity'],
                        vuln['description'][:2000],  # Limitar longitud
                        vuln['references'][:1000],
                        vuln['affected_products'][:1000],
                        datetime.now()
                    ))
                    
                    self.logger.info(f"Guardada vulnerabilidad: {vuln['cve_id']}")
            
            connection.commit()
            self.logger.info(f"Guardadas {len(vulnerabilities)} vulnerabilidades en la base de datos")
            
        except Error as e:
            self.logger.error(f"Error guardando en base de datos: {e}")
            connection.rollback()
        finally:
            cursor.close()
            connection.close()
    
    def send_email_notification(self, vulnerabilities: List[Dict]):
        """Enviar notificación por email"""
        if not vulnerabilities:
            return
        
        smtp_server = self.config.get('email', 'smtp_server')
        smtp_port = self.config.getint('email', 'smtp_port')
        sender_email = self.config.get('email', 'sender_email')
        sender_password = self.config.get('email', 'sender_password')
        recipient_email = self.config.get('email', 'recipient_email')
        
        try:
            # Crear mensaje
            message = MIMEMultipart()
            message["From"] = sender_email
            message["To"] = recipient_email
            message["Subject"] = f"Alertas de Vulnerabilidades Críticas - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            
            # Crear cuerpo del mensaje
            body = self.create_email_body(vulnerabilities)
            message.attach(MIMEText(body, "html"))
            
            # Enviar email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
            server.quit()
            
            self.logger.info(f"Email enviado con {len(vulnerabilities)} vulnerabilidades")
            
        except Exception as e:
            self.logger.error(f"Error enviando email: {e}")
    
    def create_email_body(self, vulnerabilities: List[Dict]) -> str:
        """Crear cuerpo del email en HTML"""
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #dc3545; color: white; padding: 10px; text-align: center; }}
                .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; }}
                .critical {{ border-left: 5px solid #dc3545; }}
                .high {{ border-left: 5px solid #fd7e14; }}
                .cve-id {{ font-weight: bold; font-size: 18px; }}
                .score {{ font-weight: bold; }}
                .description {{ margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>Alertas de Vulnerabilidades Críticas</h2>
                <p>Reporte generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <p>Se han detectado <strong>{len(vulnerabilities)}</strong> nuevas vulnerabilidades críticas/altas.</p>
        """
        
        for vuln in vulnerabilities:
            severity_class = "critical" if vuln['cvss_severity'] == 'CRITICAL' else "high"
            html += f"""
            <div class="vulnerability {severity_class}">
                <div class="cve-id">{vuln['cve_id']}</div>
                <div class="score">CVSS: {vuln['cvss_score']} ({vuln['cvss_severity']})</div>
                <div class="description">{vuln['description'][:500]}...</div>
                <div><strong>Fecha publicación:</strong> {vuln['published_date']}</div>
                <div><strong>Productos afectados:</strong> {vuln['affected_products'][:200]}...</div>
            </div>
            """
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def test_email_connection(self) -> bool:
        """Probar conexión de email"""
        try:
            smtp_server = self.config.get('email', 'smtp_server')
            smtp_port = self.config.getint('email', 'smtp_port')
            sender_email = self.config.get('email', 'sender_email')
            sender_password = self.config.get('email', 'sender_password')
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.quit()
            
            self.logger.info("Conexión de email exitosa")
            return True
            
        except Exception as e:
            self.logger.error(f"Error probando conexión de email: {e}")
            return False
    
    def test_nvd_connection(self) -> bool:
        """Probar conexión con NVD API"""
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
            
            self.logger.info("Conexión con NVD API exitosa")
            return True
            
        except Exception as e:
            self.logger.error(f"Error probando conexión con NVD: {e}")
            return False
    
    def run_monitoring_cycle(self):
        """Ejecutar un ciclo completo de monitoreo"""
        self.logger.info("Iniciando ciclo de monitoreo")
        
        # Obtener vulnerabilidades
        vulnerabilities = self.fetch_nvd_vulnerabilities()
        
        if vulnerabilities:
            # Guardar en base de datos
            self.save_to_database(vulnerabilities)
            
            # Enviar notificación
            self.send_email_notification(vulnerabilities)
        
        self.logger.info("Ciclo de monitoreo completado")
    
    def start_scheduler(self):
        """Iniciar el programador de tareas"""
        interval_hours = self.config.getint('monitoring', 'check_interval_hours', fallback=4)
        
        schedule.every(interval_hours).hours.do(self.run_monitoring_cycle)
        
        self.logger.info(f"Programador iniciado - Ejecutando cada {interval_hours} horas")
        
        # Ejecutar inmediatamente
        self.run_monitoring_cycle()
        
        while True:
            schedule.run_pending()
            time.sleep(60)  # Verificar cada minuto

def main():
    parser = argparse.ArgumentParser(description='NVD Vulnerability Monitor')
    parser.add_argument('--config', default='/etc/nvd-monitor/config.ini', help='Archivo de configuración')
    parser.add_argument('--test-db', action='store_true', help='Probar conexión a base de datos')
    parser.add_argument('--test-email', action='store_true', help='Probar conexión de email')
    parser.add_argument('--test-nvd', action='store_true', help='Probar conexión con NVD API')
    parser.add_argument('--run-once', action='store_true', help='Ejecutar una sola vez')
    parser.add_argument('--daemon', action='store_true', help='Ejecutar como daemon')
    
    args = parser.parse_args()
    
    monitor = NVDMonitor(args.config)
    
    if args.test_db:
        success = monitor.test_database_connection()
        sys.exit(0 if success else 1)
    
    if args.test_email:
        success = monitor.test_email_connection()
        sys.exit(0 if success else 1)
    
    if args.test_nvd:
        success = monitor.test_nvd_connection()
        sys.exit(0 if success else 1)
    
    if args.run_once:
        monitor.run_monitoring_cycle()
        sys.exit(0)
    
    if args.daemon:
        monitor.start_scheduler()
    else:
        print("Uso: nvd-monitor --daemon para ejecutar como servicio")
        print("     nvd-monitor --test-db para probar conexión a BD")
        print("     nvd-monitor --test-email para probar email")
        print("     nvd-monitor --test-nvd para probar NVD API")
        print("     nvd-monitor --run-once para ejecutar una vez")

if __name__ == "__main__":
    main()
EOF

# Hacer ejecutable
chmod +x /opt/nvd-monitor/nvd-monitor.py

# Crear enlaces simbólicos para comandos globales
log_info "Creando comandos globales..."
ln -sf /opt/nvd-monitor/venv/bin/python /opt/nvd-monitor/venv/bin/python3
cat > /usr/local/bin/nvd-monitor << 'EOF'
#!/bin/bash
cd /opt/nvd-monitor
exec ./venv/bin/python nvd-monitor.py "$@"
EOF
chmod +x /usr/local/bin/nvd-monitor

# Crear archivo de servicio systemd
log_info "Creando servicio systemd..."
cat > /etc/systemd/system/nvd-monitor.service << 'EOF'
[Unit]
Description=NVD Vulnerability Monitor
After=network.target mysql.service

[Service]
Type=simple
User=nvd-monitor
Group=nvd-monitor
WorkingDirectory=/opt/nvd-monitor
ExecStart=/opt/nvd-monitor/venv/bin/python /opt/nvd-monitor/nvd-monitor.py --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Configurar permisos
log_info "Configurando permisos..."
chown -R nvd-monitor:nvd-monitor /opt/nvd-monitor
chown -R nvd-monitor:nvd-monitor /var/log/nvd-monitor
chown -R nvd-monitor:nvd-monitor /var/lib/nvd-monitor
chmod 755 /opt/nvd-monitor
chmod 644 /opt/nvd-monitor/nvd-monitor.py
chmod 755 /opt/nvd-monitor/venv/bin/*

# Recargar systemd
systemctl daemon-reload

log_info "Instalación completada exitosamente"
echo
echo "=========================================="
echo "   INSTALACIÓN COMPLETADA"
echo "=========================================="
echo
echo "Próximos pasos:"
echo "1. Ejecutar el script de configuración:"
echo "   sudo python3 /opt/nvd-monitor/configure.py"
echo
echo "2. Probar las conexiones:"
echo "   nvd-monitor --test-db"
echo "   nvd-monitor --test-email"
echo "   nvd-monitor --test-nvd"
echo
echo "3. Iniciar el servicio:"
echo "   sudo systemctl enable nvd-monitor"
echo "   sudo systemctl start nvd-monitor"
echo
echo "4. Verificar estado:"
echo "   sudo systemctl status nvd-monitor"
echo "   sudo journalctl -u nvd-monitor -f"
echo
echo "Archivos importantes:"
echo "  Aplicación: /opt/nvd-monitor/"
echo "  Configuración: /etc/nvd-monitor/config.ini"
echo "  Logs: /var/log/nvd-monitor/"
echo "  Servicio: /etc/systemd/system/nvd-monitor.service"
echo
echo "¿Desea ejecutar la configuración ahora? (y/N)"
read -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Ejecutando configuración..."
    python3 /opt/nvd-monitor/configure.py
fi

log_info "Script de instalación finalizado"
