#!/usr/bin/env python3
"""
NVD Critical Vulnerability Monitor
Monitorea la National Vulnerability Database para vulnerabilidades críticas
"""

import os
import sys
import json
import time
import logging
import smtplib
import requests
import schedule
import argparse
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass
from typing import List, Dict, Optional
import mysql.connector
from mysql.connector import Error
import configparser

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nvd_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Clase para representar una vulnerabilidad"""
    cve_id: str
    description: str
    severity: str
    base_score: float
    vector_string: str
    published_date: str
    last_modified: str
    references: List[str]
    cwe_id: Optional[str] = None
    exploit_code: bool = False
    
class DatabaseManager:
    """Gestor de base de datos MySQL"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.connection = None
        
    def connect(self):
        """Establece conexión con la base de datos"""
        try:
            self.connection = mysql.connector.connect(
                host=self.config['host'],
                database=self.config['database'],
                user=self.config['user'],
                password=self.config['password'],
                port=self.config.get('port', 3306)
            )
            logger.info("Conexión exitosa a MySQL")
            return True
        except Error as e:
            logger.error(f"Error conectando a MySQL: {e}")
            return False
    
    def create_tables(self):
        """Crea las tablas necesarias"""
        create_table_query = """
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INT AUTO_INCREMENT PRIMARY KEY,
            cve_id VARCHAR(20) UNIQUE NOT NULL,
            description TEXT,
            severity VARCHAR(20),
            base_score DECIMAL(3,1),
            vector_string TEXT,
            published_date DATETIME,
            last_modified DATETIME,
            references TEXT,
            cwe_id VARCHAR(20),
            exploit_code BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
        """
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(create_table_query)
            self.connection.commit()
            logger.info("Tablas creadas exitosamente")
        except Error as e:
            logger.error(f"Error creando tablas: {e}")
    
    def insert_vulnerability(self, vuln: Vulnerability) -> bool:
        """Inserta una vulnerabilidad en la base de datos"""
        query = """
        INSERT INTO vulnerabilities 
        (cve_id, description, severity, base_score, vector_string, 
         published_date, last_modified, references, cwe_id, exploit_code)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        description = VALUES(description),
        severity = VALUES(severity),
        base_score = VALUES(base_score),
        vector_string = VALUES(vector_string),
        last_modified = VALUES(last_modified),
        references = VALUES(references),
        cwe_id = VALUES(cwe_id),
        exploit_code = VALUES(exploit_code)
        """
        
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, (
                vuln.cve_id,
                vuln.description,
                vuln.severity,
                vuln.base_score,
                vuln.vector_string,
                vuln.published_date,
                vuln.last_modified,
                json.dumps(vuln.references),
                vuln.cwe_id,
                vuln.exploit_code
            ))
            self.connection.commit()
            return True
        except Error as e:
            logger.error(f"Error insertando vulnerabilidad {vuln.cve_id}: {e}")
            return False
    
    def get_recent_vulnerabilities(self, hours: int = 6) -> List[Dict]:
        """Obtiene vulnerabilidades recientes"""
        query = """
        SELECT * FROM vulnerabilities 
        WHERE created_at >= NOW() - INTERVAL %s HOUR
        ORDER BY base_score DESC, published_date DESC
        """
        
        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(query, (hours,))
            return cursor.fetchall()
        except Error as e:
            logger.error(f"Error obteniendo vulnerabilidades recientes: {e}")
            return []
    
    def close(self):
        """Cierra la conexión a la base de datos"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            logger.info("Conexión MySQL cerrada")

class NVDClient:
    """Cliente para la API de NVD"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({'apiKey': api_key})
    
    def get_recent_vulnerabilities(self, hours: int = 6) -> List[Vulnerability]:
        """Obtiene vulnerabilidades recientes de la NVD"""
        end_date = datetime.now()
        start_date = end_date - timedelta(hours=hours)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': 2000
        }
        
        vulnerabilities = []
        
        try:
            response = self.session.get(self.base_url, params=params)
            response.raise_for_status()
            
            # Respetar rate limits
            time.sleep(2)
            
            data = response.json()
            
            for item in data.get('vulnerabilities', []):
                vuln = self._parse_vulnerability(item)
                if vuln and self._is_critical_vulnerability(vuln):
                    vulnerabilities.append(vuln)
                    
        except requests.exceptions.RequestException as e:
            logger.error(f"Error consultando NVD API: {e}")
        
        return vulnerabilities
    
    def _parse_vulnerability(self, item: Dict) -> Optional[Vulnerability]:
        """Parsea una vulnerabilidad de la respuesta de la API"""
        try:
            cve = item['cve']
            
            # Obtener descripción
            descriptions = cve.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d['lang'] == 'en'), 'No description')
            
            # Obtener métricas CVSS
            metrics = cve.get('metrics', {})
            cvss_data = None
            
            # Buscar CVSS v3.1 primero, luego v3.0, luego v2.0
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    cvss_data = metrics[version][0]
                    break
            
            if not cvss_data:
                return None
            
            cvss_info = cvss_data.get('cvssData', {})
            base_score = cvss_info.get('baseScore', 0.0)
            vector_string = cvss_info.get('vectorString', '')
            
            # Determinar severidad
            severity = self._get_severity(base_score)
            
            # Obtener referencias
            references = [ref.get('url', '') for ref in cve.get('references', [])]
            
            # Obtener CWE
            weaknesses = cve.get('weaknesses', [])
            cwe_id = None
            if weaknesses:
                cwe_descriptions = weaknesses[0].get('description', [])
                if cwe_descriptions:
                    cwe_id = cwe_descriptions[0].get('value', '')
            
            # Detectar si es zero-day (aproximación)
            exploit_code = self._detect_exploit_code(cve, references)
            
            return Vulnerability(
                cve_id=cve['id'],
                description=description,
                severity=severity,
                base_score=base_score,
                vector_string=vector_string,
                published_date=cve.get('published', ''),
                last_modified=cve.get('lastModified', ''),
                references=references,
                cwe_id=cwe_id,
                exploit_code=exploit_code
            )
            
        except Exception as e:
            logger.error(f"Error parseando vulnerabilidad: {e}")
            return None
    
    def _get_severity(self, base_score: float) -> str:
        """Determina la severidad basada en el score CVSS"""
        if base_score >= 9.0:
            return "CRITICAL"
        elif base_score >= 7.0:
            return "HIGH"
        elif base_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _is_critical_vulnerability(self, vuln: Vulnerability) -> bool:
        """Determina si una vulnerabilidad es crítica según nuestros criterios"""
        return (vuln.severity in ["CRITICAL", "HIGH"] or 
                vuln.exploit_code or 
                "zero" in vuln.description.lower())
    
    def _detect_exploit_code(self, cve: Dict, references: List[str]) -> bool:
        """Detecta si hay código de exploit disponible"""
        # Buscar en descripción
        description = str(cve.get('descriptions', []))
        exploit_indicators = ['exploit', 'zero-day', 'zero day', 'poc', 'proof of concept']
        
        for indicator in exploit_indicators:
            if indicator in description.lower():
                return True
        
        # Buscar en referencias
        exploit_domains = ['exploit-db.com', 'github.com', 'metasploit.com']
        for ref in references:
            for domain in exploit_domains:
                if domain in ref.lower():
                    return True
        
        return False

class EmailNotifier:
    """Notificador por email"""
    
    def __init__(self, config: Dict):
        self.smtp_server = config['smtp_server']
        self.smtp_port = config['smtp_port']
        self.username = config['username']
        self.password = config['password']
        self.from_email = config['from_email']
        self.to_emails = config['to_emails']
    
    def send_vulnerability_report(self, vulnerabilities: List[Dict]):
        """Envía reporte de vulnerabilidades por email"""
        if not vulnerabilities:
            return
        
        subject = f"🚨 Reporte de Vulnerabilidades Críticas - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        # Crear contenido HTML
        html_content = self._create_html_report(vulnerabilities)
        
        # Crear mensaje
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.from_email
        msg['To'] = ', '.join(self.to_emails)
        
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)
        
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            logger.info(f"Email enviado exitosamente a {len(self.to_emails)} destinatarios")
        except Exception as e:
            logger.error(f"Error enviando email: {e}")
    
    def _create_html_report(self, vulnerabilities: List[Dict]) -> str:
        """Crea reporte HTML de vulnerabilidades"""
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #d32f2f; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background-color: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                .vuln-item {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #d32f2f; }}
                .high {{ border-left: 5px solid #ff9800; }}
                .severity {{ padding: 3px 8px; border-radius: 3px; color: white; font-weight: bold; }}
                .severity.critical {{ background-color: #d32f2f; }}
                .severity.high {{ background-color: #ff9800; }}
                .cve-id {{ font-weight: bold; font-size: 18px; color: #1976d2; }}
                .score {{ font-weight: bold; font-size: 16px; }}
                .references {{ margin-top: 10px; }}
                .references a {{ color: #1976d2; text-decoration: none; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 Reporte de Vulnerabilidades Críticas</h1>
                <p>Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Resumen</h2>
                <p><strong>Total de vulnerabilidades:</strong> {len(vulnerabilities)}</p>
                <p><strong>Críticas:</strong> {len([v for v in vulnerabilities if v['severity'] == 'CRITICAL'])}</p>
                <p><strong>Altas:</strong> {len([v for v in vulnerabilities if v['severity'] == 'HIGH'])}</p>
                <p><strong>Con exploit:</strong> {len([v for v in vulnerabilities if v['exploit_code']])}</p>
            </div>
        """
        
        for vuln in vulnerabilities:
            severity_class = vuln['severity'].lower()
            html += f"""
            <div class="vuln-item {severity_class}">
                <div class="cve-id">{vuln['cve_id']}</div>
                <div style="margin: 10px 0;">
                    <span class="severity {severity_class}">{vuln['severity']}</span>
                    <span class="score">Score: {vuln['base_score']}</span>
                    {"🔓 EXPLOIT DISPONIBLE" if vuln['exploit_code'] else ""}
                </div>
                <p><strong>Descripción:</strong> {vuln['description'][:500]}...</p>
                <p><strong>Fecha de publicación:</strong> {vuln['published_date']}</p>
                {f"<p><strong>CWE:</strong> {vuln['cwe_id']}</p>" if vuln['cwe_id'] else ""}
                <div class="references">
                    <strong>Referencias:</strong><br>
                    {self._format_references(vuln['references'])}
                </div>
            </div>
            """
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def _format_references(self, references_json: str) -> str:
        """Formatea las referencias para HTML"""
        try:
            references = json.loads(references_json)
            return "<br>".join([f'<a href="{ref}">{ref}</a>' for ref in references[:5]])
        except:
            return "No disponible"

class VulnerabilityMonitor:
    """Clase principal del monitor"""
    
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.db_manager = DatabaseManager(self.config['database'])
        self.nvd_client = NVDClient(self.config['nvd'].get('api_key'))
        self.email_notifier = EmailNotifier(self.config['email'])
        self.check_interval = self.config['monitor'].get('check_interval', 6)
    
    def _load_config(self, config_file: str) -> Dict:
        """Carga la configuración desde archivo"""
        config = configparser.ConfigParser()
        config.read(config_file)
        
        return {
            'database': dict(config['database']),
            'nvd': dict(config['nvd']),
            'email': dict(config['email']),
            'monitor': dict(config['monitor'])
        }
    
    def initialize(self):
        """Inicializa el monitor"""
        logger.info("Inicializando NVD Monitor...")
        
        # Conectar a base de datos
        if not self.db_manager.connect():
            logger.error("No se pudo conectar a la base de datos")
            return False
        
        # Crear tablas
        self.db_manager.create_tables()
        
        logger.info("Monitor inicializado exitosamente")
        return True
    
    def check_vulnerabilities(self):
        """Verifica nuevas vulnerabilidades"""
        logger.info("Verificando nuevas vulnerabilidades...")
        
        # Obtener vulnerabilidades de NVD
        vulnerabilities = self.nvd_client.get_recent_vulnerabilities(self.check_interval)
        
        if not vulnerabilities:
            logger.info("No se encontraron nuevas vulnerabilidades críticas")
            return
        
        logger.info(f"Encontradas {len(vulnerabilities)} vulnerabilidades críticas")
        
        # Almacenar en base de datos
        new_count = 0
        for vuln in vulnerabilities:
            if self.db_manager.insert_vulnerability(vuln):
                new_count += 1
        
        logger.info(f"Almacenadas {new_count} vulnerabilidades en la base de datos")
        
        # Enviar notificación por email
        recent_vulns = self.db_manager.get_recent_vulnerabilities(self.check_interval)
        if recent_vulns:
            self.email_notifier.send_vulnerability_report(recent_vulns)
    
    def run_scheduler(self):
        """Ejecuta el scheduler"""
        logger.info(f"Iniciando scheduler con intervalo de {self.check_interval} horas")
        
        # Programar verificación
        schedule.every(self.check_interval).hours.do(self.check_vulnerabilities)
        
        # Ejecutar una vez al inicio
        self.check_vulnerabilities()
        
        # Loop principal
        while True:
            schedule.run_pending()
            time.sleep(60)  # Verificar cada minuto
    
    def run_once(self):
        """Ejecuta una sola verificación"""
        self.check_vulnerabilities()
    
    def cleanup(self):
        """Limpia recursos"""
        self.db_manager.close()

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='NVD Vulnerability Monitor')
    parser.add_argument('--config', default='/etc/nvd_monitor/config.ini', 
                       help='Archivo de configuración')
    parser.add_argument('--once', action='store_true', 
                       help='Ejecutar una sola vez')
    parser.add_argument('--daemon', action='store_true', 
                       help='Ejecutar como daemon')
    
    args = parser.parse_args()
    
    # Crear monitor
    monitor = VulnerabilityMonitor(args.config)
    
    # Inicializar
    if not monitor.initialize():
        sys.exit(1)
    
    try:
        if args.once:
            monitor.run_once()
        else:
            monitor.run_scheduler()
    except KeyboardInterrupt:
        logger.info("Monitor detenido por el usuario")
    except Exception as e:
        logger.error(f"Error en el monitor: {e}")
    finally:
        monitor.cleanup()

if __name__ == "__main__":
    main()
