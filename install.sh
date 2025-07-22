#!/bin/bash

# =============================================================================
# NVD Vulnerability Monitor - Script de Instalación Final v1.0.9
# Compatible con: Ubuntu 20.04+ LTS
# Incluye todas las correcciones y mejoras implementadas
# =============================================================================

set -euo pipefail

# Colores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Constantes del sistema
readonly SCRIPT_VERSION="1.0.9"
readonly SUPPORTED_UBUNTU="20.04"
readonly INSTALL_USER="nvd-monitor"
readonly INSTALL_DIR="/opt/nvd-monitor"
readonly CONFIG_DIR="/etc/nvd-monitor"
readonly LOG_DIR="/var/log/nvd-monitor"
readonly DATA_DIR="/var/lib/nvd-monitor"

# Variables globales
DB_PASSWORD=""
API_KEY=""
SMTP_SERVER="smtp.gmail.com"
SMTP_PORT="587"
SENDER_EMAIL=""
SENDER_PASSWORD=""
RECIPIENT_EMAIL=""
MONITOR_INTERVAL="4"
CURRENT_USER="${SUDO_USER:-$USER}"

# Funciones de logging
log_header() {
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}[CLEANUP]${NC} Limpiando archivos temporales..."
    rm -f /tmp/nvd-monitor-*.tmp /tmp/setup_database.sh /tmp/nvd_db_* /tmp/test_email.py /tmp/nvd_setup.sql 2>/dev/null || true
}
trap cleanup EXIT

# Banner de bienvenida
show_welcome_banner() {
    clear
    echo -e "${BLUE}"
    echo "================================================================"
    echo "       🛡️  NVD VULNERABILITY MONITOR INSTALLER v${SCRIPT_VERSION}"
    echo "================================================================"
    echo -e "${NC}"
    echo -e "${GREEN}Versión: ${SCRIPT_VERSION} - Final${NC}"
    echo
    echo "🎯 Este instalador configurará:"
    echo "   ✅ Sistema base con dependencias"
    echo "   ✅ Base de datos MariaDB/MySQL"
    echo "   ✅ Monitor de vulnerabilidades NVD completo"
    echo "   ✅ Sistema de notificaciones por email"
    echo "   ✅ API Key de NVD (opcional)"
    echo "   ✅ Servicio systemd con auto-inicio"
    echo "   ✅ Herramientas administrativas avanzadas"
    echo
    echo "📌 Mejoras incluidas en esta versión:"
    echo "   • Descarga real de vulnerabilidades desde NVD"
    echo "   • Notificaciones HTML corregidas"
    echo "   • Soporte para múltiples servidores SMTP"
    echo "   • Permisos optimizados"
    echo "   • Herramientas de diagnóstico mejoradas"
    echo
    read -p "🚀 ¿Continuar con la instalación? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Instalación cancelada."
        exit 0
    fi
    echo
}

# Generar contraseña segura
generate_password() {
    openssl rand -base64 16 | tr -d "=+/" | cut -c1-16
}

# Validar email
validate_email() {
    local email="$1"
    if [[ $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Verificar prerrequisitos
check_prerequisites() {
    log_step "Verificando prerrequisitos..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "Debe ejecutarse como root: sudo bash install.sh"
        exit 1
    fi
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 no está instalado"
        exit 1
    fi
    
    if ! timeout 5 ping -c 1 8.8.8.8 &> /dev/null; then
        log_error "Sin conectividad a internet"
        exit 1
    fi
    
    # Verificar versión de Ubuntu
    if command -v lsb_release &> /dev/null; then
        local ubuntu_version=$(lsb_release -rs)
        log_info "Ubuntu version: $ubuntu_version"
    fi
    
    log_success "Prerrequisitos OK"
}

# Instalar dependencias
install_dependencies() {
    log_step "Instalando dependencias..."
    
    # Detectar base de datos existente
    local db_exists=false
    local db_type=""
    
    if command -v mysql &>/dev/null; then
        if mysql --version | grep -qi mariadb; then
            db_exists=true
            db_type="MariaDB"
        else
            db_exists=true
            db_type="MySQL"
        fi
    fi
    
    if [ "$db_exists" = true ]; then
        log_info "$db_type ya está instalado"
    else
        log_info "Instalando MariaDB"
    fi
    
    local packages=(
        "python3-pip" "python3-venv" "python3-dev" "build-essential"
        "curl" "wget" "git" "logrotate" "systemd" "jq"
    )
    
    if [ "$db_exists" = false ]; then
        packages+=("mariadb-server")
    fi
    
    apt update -qq
    DEBIAN_FRONTEND=noninteractive apt install -y "${packages[@]}"
    
    if [ "$db_exists" = false ]; then
        systemctl enable mariadb
        systemctl start mariadb
    fi
    
    log_success "Dependencias configuradas"
}

# Crear usuario del sistema con grupo
create_system_user() {
    log_step "Creando usuario y grupo del sistema..."
    
    # Crear grupo primero
    if ! getent group "$INSTALL_USER" >/dev/null 2>&1; then
        groupadd "$INSTALL_USER"
        log_info "Grupo $INSTALL_USER creado"
    fi
    
    # Crear usuario
    if ! id "$INSTALL_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" -g "$INSTALL_USER" -c "NVD Monitor Service User" "$INSTALL_USER"
        log_info "Usuario $INSTALL_USER creado"
    fi
    
    # Agregar el usuario actual al grupo nvd-monitor para facilitar administración
    if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
        usermod -a -G "$INSTALL_USER" "$CURRENT_USER"
        log_info "Usuario $CURRENT_USER agregado al grupo $INSTALL_USER"
    fi
    
    log_success "Usuario y grupo $INSTALL_USER configurados"
}

# Crear directorios
create_directories() {
    log_step "Creando directorios..."
    
    local directories=(
        "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
        "$DATA_DIR/scripts" "$DATA_DIR/backups" "$DATA_DIR/cache"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        case "$dir" in
            "$CONFIG_DIR")
                chown root:"$INSTALL_USER" "$dir"
                chmod 750 "$dir"
                ;;
            *)
                chown "$INSTALL_USER:$INSTALL_USER" "$dir"
                chmod 755 "$dir"
                ;;
        esac
    done
    
    log_success "Directorios creados"
}

# Configurar Python
setup_python() {
    log_step "Configurando entorno Python..."
    
    cd "$INSTALL_DIR"
    
    sudo -u "$INSTALL_USER" python3 -m venv venv
    
    cat > requirements.txt << 'EOF'
requests>=2.31.0
mysql-connector-python>=8.0.33
schedule>=1.2.0
configparser>=5.3.0
tabulate>=0.9.0
python-dateutil>=2.8.2
colorama>=0.4.6
EOF
    
    sudo -u "$INSTALL_USER" bash -c "
        source venv/bin/activate
        pip install --upgrade pip -q
        pip install -r requirements.txt -q
    "
    
    chown -R "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR"
    log_success "Python configurado"
}

# Crear aplicación principal COMPLETA con todas las correcciones
create_application() {
    log_step "Creando aplicación principal completa..."
    
    # Copiar el contenido completo del nvd_monitor_complete.py que funciona
    cp /dev/stdin "$INSTALL_DIR/nvd_monitor.py" << 'APPEOF'
#!/usr/bin/env python3
"""NVD Vulnerability Monitor v1.0.9 - Versión Final Completa"""

import configparser
import logging
import sys
import os
import argparse
import time
import schedule
import json
import requests
import mysql.connector
import smtplib
from datetime import datetime, timedelta
from dateutil import parser as date_parser
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from tabulate import tabulate

class NVDMonitor:
    def __init__(self, config_file='/etc/nvd-monitor/config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.running = True
        self.load_config()
        self.setup_logging()
        self.db_connection = None
        
    def load_config(self):
        if not os.path.exists(self.config_file):
            print(f"Error: Archivo de configuración no encontrado: {self.config_file}")
            sys.exit(1)
        self.config.read(self.config_file)
        
    def setup_logging(self):
        log_file = self.config.get('logging', 'file', fallback='/var/log/nvd-monitor/nvd-monitor.log')
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('NVDMonitor')
        self.logger.info("="*60)
        self.logger.info("NVD Monitor iniciado - Versión 1.0.9 Final")
        self.logger.info("="*60)
    
    def get_db_connection(self):
        """Obtiene conexión a la base de datos"""
        try:
            if self.db_connection and self.db_connection.is_connected():
                return self.db_connection
            
            self.db_connection = mysql.connector.connect(
                host=self.config.get('database', 'host'),
                database=self.config.get('database', 'database'),
                user=self.config.get('database', 'user'),
                password=self.config.get('database', 'password'),
                port=self.config.getint('database', 'port', fallback=3306)
            )
            return self.db_connection
        except Exception as e:
            self.logger.error(f"Error conectando a base de datos: {e}")
            return None
    
    def test_nvd_api(self):
        """Prueba la conectividad con la API de NVD"""
        self.logger.info("Probando conexión con API de NVD...")
        
        api_key = self.config.get('nvd', 'api_key', fallback='')
        headers = {}
        if api_key:
            headers['apiKey'] = api_key
            self.logger.info(f"Usando API Key: {api_key[:8]}...{api_key[-4:]}")
        else:
            self.logger.warning("Sin API Key configurada - límite reducido")
        
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                total = data.get('totalResults', 0)
                self.logger.info(f"✅ Conexión exitosa - Total CVEs disponibles: {total}")
                return True
            else:
                self.logger.error(f"❌ Error API NVD: Status {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Error conectando con API NVD: {e}")
            return False
    
    def get_last_check_date(self):
        """Obtiene la fecha de la última verificación"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return None
            
            cursor = conn.cursor()
            cursor.execute("""
                SELECT config_value FROM system_config 
                WHERE config_key = 'last_check'
            """)
            result = cursor.fetchone()
            cursor.close()
            
            if result and result[0]:
                return datetime.fromisoformat(result[0])
            else:
                # Si no hay fecha, usar los últimos 7 días por defecto
                return datetime.now() - timedelta(days=7)
                
        except Exception as e:
            self.logger.error(f"Error obteniendo última fecha de verificación: {e}")
            return datetime.now() - timedelta(days=7)
    
    def update_last_check_date(self):
        """Actualiza la fecha de última verificación"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return
            
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO system_config (config_key, config_value, description)
                VALUES ('last_check', %s, 'Última verificación de vulnerabilidades')
                ON DUPLICATE KEY UPDATE config_value = %s, updated_at = NOW()
            """, (datetime.now().isoformat(), datetime.now().isoformat()))
            
            conn.commit()
            cursor.close()
            
        except Exception as e:
            self.logger.error(f"Error actualizando fecha de verificación: {e}")
    
    def fetch_vulnerabilities(self, start_date=None, end_date=None):
        """Descarga vulnerabilidades desde la API de NVD"""
        if not start_date:
            start_date = self.get_last_check_date()
        if not end_date:
            end_date = datetime.now()
        
        self.logger.info(f"Descargando vulnerabilidades desde {start_date} hasta {end_date}")
        
        api_key = self.config.get('nvd', 'api_key', fallback='')
        base_url = self.config.get('nvd', 'base_url', fallback='https://services.nvd.nist.gov/rest/json/cves/2.0')
        
        headers = {}
        if api_key:
            headers['apiKey'] = api_key
        
        vulnerabilities = []
        start_index = 0
        results_per_page = 200
        total_results = None
        
        # Formatear fechas para la API
        pub_start_date = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        pub_end_date = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        
        while True:
            try:
                # Construir URL con parámetros
                params = {
                    'pubStartDate': pub_start_date,
                    'pubEndDate': pub_end_date,
                    'startIndex': start_index,
                    'resultsPerPage': results_per_page
                }
                
                self.logger.info(f"Solicitando página con startIndex={start_index}")
                response = requests.get(base_url, params=params, headers=headers, timeout=60)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if total_results is None:
                        total_results = data.get('totalResults', 0)
                        self.logger.info(f"Total de vulnerabilidades a procesar: {total_results}")
                    
                    # Procesar vulnerabilidades
                    cves = data.get('vulnerabilities', [])
                    for cve_item in cves:
                        cve = cve_item.get('cve', {})
                        vulnerabilities.append(self.parse_cve(cve))
                    
                    self.logger.info(f"Procesadas {len(cves)} vulnerabilidades (total acumulado: {len(vulnerabilities)})")
                    
                    # Verificar si hay más páginas
                    if start_index + results_per_page >= total_results:
                        break
                    
                    start_index += results_per_page
                    
                    # Respetar límites de rate (más conservador sin API key)
                    if not api_key:
                        time.sleep(6)  # 5 requests por 30 segundos sin API key
                    else:
                        time.sleep(0.6)  # 50 requests por 30 segundos con API key
                    
                else:
                    self.logger.error(f"Error en API: Status {response.status_code}")
                    self.logger.error(f"Respuesta: {response.text}")
                    break
                    
            except Exception as e:
                self.logger.error(f"Error descargando vulnerabilidades: {e}")
                break
        
        self.logger.info(f"Descarga completada: {len(vulnerabilities)} vulnerabilidades obtenidas")
        return vulnerabilities
    
    def parse_cve(self, cve_data):
        """Parsea los datos de un CVE"""
        vuln = {
            'cve_id': cve_data.get('id', ''),
            'published_date': None,
            'last_modified': None,
            'description': '',
            'cvss_score': None,
            'cvss_severity': None,
            'reference_urls': [],
            'affected_products': []
        }
        
        # Fechas
        if 'published' in cve_data:
            vuln['published_date'] = datetime.fromisoformat(cve_data['published'].replace('Z', '+00:00'))
        if 'lastModified' in cve_data:
            vuln['last_modified'] = datetime.fromisoformat(cve_data['lastModified'].replace('Z', '+00:00'))
        
        # Descripción
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                vuln['description'] = desc.get('value', '')
                break
        
        # CVSS Score - buscar en metrics
        metrics = cve_data.get('metrics', {})
        
        # Intentar CVSS v3.1 primero
        cvss_v31 = metrics.get('cvssMetricV31', [])
        if cvss_v31:
            cvss_data = cvss_v31[0].get('cvssData', {})
            vuln['cvss_score'] = cvss_data.get('baseScore')
            vuln['cvss_severity'] = cvss_data.get('baseSeverity')
        else:
            # Intentar CVSS v3.0
            cvss_v30 = metrics.get('cvssMetricV30', [])
            if cvss_v30:
                cvss_data = cvss_v30[0].get('cvssData', {})
                vuln['cvss_score'] = cvss_data.get('baseScore')
                vuln['cvss_severity'] = cvss_data.get('baseSeverity')
            else:
                # Intentar CVSS v2.0
                cvss_v2 = metrics.get('cvssMetricV2', [])
                if cvss_v2:
                    cvss_data = cvss_v2[0].get('cvssData', {})
                    vuln['cvss_score'] = cvss_data.get('baseScore')
                    # Mapear severity para v2
                    if vuln['cvss_score']:
                        if vuln['cvss_score'] >= 7.0:
                            vuln['cvss_severity'] = 'HIGH'
                        elif vuln['cvss_score'] >= 4.0:
                            vuln['cvss_severity'] = 'MEDIUM'
                        else:
                            vuln['cvss_severity'] = 'LOW'
        
        # Referencias
        references = cve_data.get('references', [])
        for ref in references:
            url = ref.get('url', '')
            if url:
                vuln['reference_urls'].append(url)
        
        # Configuraciones afectadas (CPE)
        configurations = cve_data.get('configurations', [])
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    if cpe.get('vulnerable', False):
                        vuln['affected_products'].append(cpe.get('criteria', ''))
        
        return vuln
    
    def save_vulnerabilities(self, vulnerabilities):
        """Guarda las vulnerabilidades en la base de datos"""
        if not vulnerabilities:
            self.logger.info("No hay vulnerabilidades nuevas para guardar")
            return 0
        
        conn = self.get_db_connection()
        if not conn:
            self.logger.error("No se pudo conectar a la base de datos")
            return 0
        
        cursor = conn.cursor()
        saved_count = 0
        updated_count = 0
        
        for vuln in vulnerabilities:
            try:
                # Convertir listas a JSON
                reference_urls = json.dumps(vuln['reference_urls'][:10])  # Limitar a 10 URLs
                affected_products = json.dumps(vuln['affected_products'][:20])  # Limitar a 20 productos
                
                # Intentar insertar o actualizar
                cursor.execute("""
                    INSERT INTO vulnerabilities 
                    (cve_id, published_date, last_modified, description, 
                     cvss_score, cvss_severity, reference_urls, affected_products)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    last_modified = VALUES(last_modified),
                    description = VALUES(description),
                    cvss_score = VALUES(cvss_score),
                    cvss_severity = VALUES(cvss_severity),
                    reference_urls = VALUES(reference_urls),
                    affected_products = VALUES(affected_products)
                """, (
                    vuln['cve_id'],
                    vuln['published_date'],
                    vuln['last_modified'],
                    vuln['description'][:5000],  # Limitar descripción
                    vuln['cvss_score'],
                    vuln['cvss_severity'],
                    reference_urls,
                    affected_products
                ))
                
                if cursor.rowcount == 1:
                    saved_count += 1
                else:
                    updated_count += 1
                    
            except Exception as e:
                self.logger.error(f"Error guardando {vuln['cve_id']}: {e}")
        
        conn.commit()
        cursor.close()
        
        self.logger.info(f"Guardadas {saved_count} nuevas vulnerabilidades, actualizadas {updated_count}")
        return saved_count
    
    def get_new_critical_vulnerabilities(self, hours=None):
        """Obtiene vulnerabilidades críticas de las últimas horas"""
        if hours is None:
            hours = self.config.getint('monitoring', 'check_interval_hours', fallback=4) * 2
            
        try:
            conn = self.get_db_connection()
            if not conn:
                return []
            
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT cve_id, cvss_severity, cvss_score, description,
                       published_date, reference_urls
                FROM vulnerabilities
                WHERE cvss_severity IN ('CRITICAL', 'HIGH')
                AND published_date >= %s
                ORDER BY cvss_score DESC, published_date DESC
            """, (datetime.now() - timedelta(hours=hours),))
            
            vulnerabilities = cursor.fetchall()
            cursor.close()
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error obteniendo vulnerabilidades críticas: {e}")
            return []
    
    def send_email_notification(self, vulnerabilities):
        """Envía notificación por email de nuevas vulnerabilidades"""
        if not vulnerabilities:
            return
        
        smtp_server = self.config.get('email', 'smtp_server', fallback='')
        smtp_port = self.config.getint('email', 'smtp_port', fallback=587)
        sender_email = self.config.get('email', 'sender_email', fallback='')
        sender_password = self.config.get('email', 'sender_password', fallback='')
        recipient_emails = self.config.get('email', 'recipient_email', fallback='')
        
        if not all([smtp_server, sender_email, sender_password, recipient_emails]):
            self.logger.warning("Configuración de email incompleta, no se enviarán notificaciones")
            return
        
        try:
            # Crear mensaje
            msg = MIMEMultipart('alternative')
            msg['From'] = sender_email
            msg['To'] = recipient_emails
            msg['Subject'] = f"🚨 NVD Alert: {len(vulnerabilities)} Vulnerabilidades Críticas/Altas Detectadas"
            
            # Crear contenido HTML
            html_content = self.create_email_html(vulnerabilities)
            
            # Crear contenido de texto plano
            text_content = self.create_email_text(vulnerabilities)
            
            # Adjuntar ambas versiones
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Enviar email
            self.logger.info(f"Enviando notificación a: {recipient_emails}")
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            
            # Si hay múltiples destinatarios
            if ',' in recipient_emails:
                recipients = [email.strip() for email in recipient_emails.split(',')]
            else:
                recipients = [recipient_emails]
                
            server.send_message(msg)
            server.quit()
            
            self.logger.info("✅ Notificación enviada exitosamente")
            
            # Registrar en base de datos
            self.log_email_notification(recipient_emails, len(vulnerabilities))
            
        except Exception as e:
            self.logger.error(f"Error enviando email: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
    
    def create_email_html(self, vulnerabilities):
        """Crea el contenido HTML del email - VERSIÓN CORREGIDA"""
        html = '<html><body style="font-family: Arial; margin: 0; padding: 0;">'
        html += '<div style="background-color: #dc3545; color: white; padding: 20px; text-align: center;">'
        html += '<h1>🚨 Alerta de Vulnerabilidades NVD</h1>'
        html += f'<p>Se han detectado {len(vulnerabilities)} vulnerabilidades críticas/altas</p>'
        html += '</div>'
        html += '<div style="padding: 20px;">'
        html += f'<p><strong>Fecha del reporte:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>'
        html += '<p>Las siguientes vulnerabilidades requieren su atención inmediata:</p>'
        
        # Separar por severidad
        critical_vulns = [v for v in vulnerabilities if v.get('cvss_severity') == 'CRITICAL']
        high_vulns = [v for v in vulnerabilities if v.get('cvss_severity') == 'HIGH']
        
        if critical_vulns:
            html += f'<h2 style="color: #dc3545;">⚠️ VULNERABILIDADES CRÍTICAS ({len(critical_vulns)})</h2>'
            for vuln in critical_vulns[:5]:
                html += self.format_vulnerability_html(vuln, '#dc3545')
        
        if high_vulns:
            html += f'<h2 style="color: #fd7e14;">⚠️ VULNERABILIDADES ALTAS ({len(high_vulns)})</h2>'
            for vuln in high_vulns[:5]:
                html += self.format_vulnerability_html(vuln, '#fd7e14')
        
        total_shown = min(5, len(critical_vulns)) + min(5, len(high_vulns))
        if len(vulnerabilities) > total_shown:
            html += f'<p style="text-align: center; font-weight: bold; margin: 20px;">... y {len(vulnerabilities) - total_shown} vulnerabilidades más</p>'
        
        html += '</div>'
        html += '<div style="background-color: #f8f9fa; padding: 20px; text-align: center; color: #666;">'
        html += '<p>Este es un mensaje automático del sistema NVD Monitor</p>'
        html += '<p>Para más información, ejecute: <code>nvd-admin show-vulns --severity CRITICAL</code></p>'
        html += '</div>'
        html += '</body></html>'
        
        return html
    
    def format_vulnerability_html(self, vuln, color):
        """Formatea una vulnerabilidad individual para el HTML"""
        cve_id = vuln.get('cve_id', 'Unknown')
        cvss_score = vuln.get('cvss_score', 'N/A')
        cvss_severity = vuln.get('cvss_severity', 'N/A')
        description = vuln.get('description', 'Sin descripción')[:300]
        
        # Formatear fecha
        pub_date = vuln.get('published_date')
        if pub_date:
            if isinstance(pub_date, str):
                pub_date_str = pub_date
            else:
                pub_date_str = pub_date.strftime('%Y-%m-%d %H:%M')
        else:
            pub_date_str = 'Fecha desconocida'
        
        html = f'<div style="border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-left: 5px solid {color};">'
        html += f'<h3 style="color: #0066cc; margin: 0 0 10px 0;">{cve_id}</h3>'
        html += f'<p style="margin: 5px 0;"><strong>CVSS Score:</strong> {cvss_score} | '
        html += f'<strong>Severidad:</strong> {cvss_severity} | '
        html += f'<strong>Publicado:</strong> {pub_date_str}</p>'
        html += f'<p style="margin: 10px 0;">{description}...</p>'
        html += f'<p style="margin: 5px 0;"><a href="https://nvd.nist.gov/vuln/detail/{cve_id}">Ver detalles completos en NVD</a></p>'
        html += '</div>'
        
        return html
    
    def create_email_text(self, vulnerabilities):
        """Crea contenido de texto plano para el email"""
        text = "ALERTA DE VULNERABILIDADES NVD\n"
        text += "="*50 + "\n\n"
        text += f"Se han detectado {len(vulnerabilities)} vulnerabilidades críticas/altas\n"
        text += f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        critical_count = len([v for v in vulnerabilities if v.get('cvss_severity') == 'CRITICAL'])
        high_count = len([v for v in vulnerabilities if v.get('cvss_severity') == 'HIGH'])
        
        text += f"Resumen:\n"
        text += f"- Críticas: {critical_count}\n"
        text += f"- Altas: {high_count}\n\n"
        
        text += "VULNERABILIDADES DETECTADAS:\n"
        text += "-"*50 + "\n"
        
        for i, vuln in enumerate(vulnerabilities[:10], 1):
            text += f"\n{i}. {vuln.get('cve_id', 'Unknown')}\n"
            text += f"   Severidad: {vuln.get('cvss_severity', 'N/A')} (CVSS: {vuln.get('cvss_score', 'N/A')})\n"
            text += f"   Publicado: {vuln.get('published_date', 'Unknown')}\n"
            text += f"   Descripción: {vuln.get('description', 'Sin descripción')[:200]}...\n"
            text += f"   URL: https://nvd.nist.gov/vuln/detail/{vuln.get('cve_id', '')}\n"
        
        if len(vulnerabilities) > 10:
            text += f"\n... y {len(vulnerabilities) - 10} vulnerabilidades más\n"
        
        text += "\n" + "-"*50 + "\n"
        text += "Para ver todas las vulnerabilidades, ejecute:\n"
        text += "nvd-admin show-vulns --severity CRITICAL\n\n"
        text += "-- NVD Monitor System --\n"
        
        return text
    
    def log_email_notification(self, recipients, vuln_count):
        """Registra el envío de notificación en la base de datos"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return
            
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO email_notifications 
                (recipient_email, subject, vulnerabilities_count, status)
                VALUES (%s, %s, %s, %s)
            """, (
                recipients,
                f"Alerta: {vuln_count} vulnerabilidades críticas/altas",
                vuln_count,
                'sent'
            ))
            
            conn.commit()
            cursor.close()
            
        except Exception as e:
            self.logger.error(f"Error registrando notificación: {e}")
    
    def log_monitoring_cycle(self, vulns_found, new_vulns):
        """Registra el ciclo de monitoreo en la base de datos"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return
            
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO monitoring_logs 
                (vulnerabilities_found, new_vulnerabilities, status, message)
                VALUES (%s, %s, %s, %s)
            """, (
                vulns_found,
                new_vulns,
                'completed',
                f'Ciclo completado: {vulns_found} encontradas, {new_vulns} nuevas'
            ))
            
            # Actualizar contador total
            cursor.execute("""
                UPDATE system_config 
                SET config_value = (
                    SELECT COUNT(*) FROM vulnerabilities
                )
                WHERE config_key = 'total_vulnerabilities'
            """)
            
            conn.commit()
            cursor.close()
            
        except Exception as e:
            self.logger.error(f"Error registrando ciclo de monitoreo: {e}")
    
    def run_monitoring_cycle(self):
        """Ejecuta un ciclo completo de monitoreo"""
        self.logger.info("="*60)
        self.logger.info("INICIANDO CICLO DE MONITOREO")
        self.logger.info("="*60)
        
        start_time = datetime.now()
        
        try:
            # 1. Probar API
            if not self.test_nvd_api():
                self.logger.error("No se pudo conectar a la API de NVD")
                self.log_monitoring_cycle(0, 0)
                return
            
            # 2. Descargar vulnerabilidades
            vulnerabilities = self.fetch_vulnerabilities()
            
            # 3. Guardar en base de datos
            new_count = self.save_vulnerabilities(vulnerabilities)
            
            # 4. Actualizar fecha de última verificación
            self.update_last_check_date()
            
            # 5. Obtener vulnerabilidades críticas para notificar
            critical_vulns = self.get_new_critical_vulnerabilities()
            
            # 6. Enviar notificaciones si hay vulnerabilidades críticas
            if critical_vulns:
                self.logger.info(f"Encontradas {len(critical_vulns)} vulnerabilidades críticas/altas para notificar")
                self.send_email_notification(critical_vulns)
            
            # 7. Registrar ciclo
            self.log_monitoring_cycle(len(vulnerabilities), new_count)
            
            # 8. Mostrar resumen
            elapsed_time = (datetime.now() - start_time).total_seconds()
            self.logger.info("="*60)
            self.logger.info("CICLO DE MONITOREO COMPLETADO")
            self.logger.info(f"Tiempo total: {elapsed_time:.2f} segundos")
            self.logger.info(f"Vulnerabilidades procesadas: {len(vulnerabilities)}")
            self.logger.info(f"Nuevas vulnerabilidades: {new_count}")
            self.logger.info(f"Notificaciones enviadas: {'Sí' if critical_vulns else 'No'}")
            self.logger.info("="*60)
            
        except Exception as e:
            self.logger.error(f"Error en ciclo de monitoreo: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            self.log_monitoring_cycle(0, 0)
    
    def start_scheduler(self):
        """Inicia el scheduler para ejecución periódica"""
        interval = self.config.getint('monitoring', 'check_interval_hours', fallback=4)
        self.logger.info(f"Iniciando scheduler - Verificación cada {interval} horas")
        
        # Ejecutar inmediatamente
        self.run_monitoring_cycle()
        
        # Programar ejecuciones periódicas
        schedule.every(interval).hours.do(self.run_monitoring_cycle)
        
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Verificar cada minuto

def main():
    parser = argparse.ArgumentParser(description='NVD Monitor v1.0.9')
    parser.add_argument('--daemon', action='store_true', help='Ejecutar como daemon')
    parser.add_argument('--run-once', action='store_true', help='Ejecutar una vez')
    parser.add_argument('--test-api', action='store_true', help='Probar conexión con API')
    parser.add_argument('--check-recent', type=int, metavar='DAYS', 
                       help='Verificar vulnerabilidades de los últimos N días')
    args = parser.parse_args()
    
    monitor = NVDMonitor()
    
    if args.test_api:
        sys.exit(0 if monitor.test_nvd_api() else 1)
    elif args.check_recent:
        # Verificar vulnerabilidades de los últimos N días
        start_date = datetime.now() - timedelta(days=args.check_recent)
        vulnerabilities = monitor.fetch_vulnerabilities(start_date=start_date)
        new_count = monitor.save_vulnerabilities(vulnerabilities)
        print(f"Procesadas {len(vulnerabilities)} vulnerabilidades, {new_count} nuevas")
    elif args.run_once:
        monitor.run_monitoring_cycle()
    elif args.daemon:
        try:
            monitor.start_scheduler()
        except KeyboardInterrupt:
            monitor.logger.info("Cerrando...")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
APPEOF
    
    chmod +x "$INSTALL_DIR/nvd_monitor.py"
    chown "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR/nvd_monitor.py"
    log_success "Aplicación principal creada con todas las correcciones"
}

# Crear herramientas de administración mejoradas
create_admin_tools() {
    log_step "Creando herramientas admin avanzadas..."
    
    cat > "$INSTALL_DIR/nvd_admin.py" << 'ADMINEOF'
#!/usr/bin/env python3
"""NVD Admin Tools v1.0.9 - Versión Final"""

import configparser
import os
import sys
import argparse
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from tabulate import tabulate

class NVDAdmin:
    def __init__(self):
        self.config_file = '/etc/nvd-monitor/config.ini'
        self.config = configparser.ConfigParser()
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            print(f"❌ Error: No se encuentra el archivo de configuración: {self.config_file}")
            sys.exit(1)
    
    def test_database(self):
        print("🔍 Probando conexión a base de datos...")
        try:
            import mysql.connector
            
            # Leer configuración
            host = self.config.get('database', 'host', fallback='localhost')
            database = self.config.get('database', 'database', fallback='nvd_monitor')
            user = self.config.get('database', 'user', fallback='nvd_user')
            password = self.config.get('database', 'password', fallback='')
            port = self.config.getint('database', 'port', fallback=3306)
            
            print(f"🔗 Conectando a: {user}@{host}:{port}/{database}")
            
            if not password:
                print("❌ Error: No hay contraseña configurada")
                return False
            
            connection = mysql.connector.connect(
                host=host,
                database=database,
                user=user,
                password=password,
                port=port,
                connect_timeout=10
            )
            
            cursor = connection.cursor()
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            
            # Verificar tablas
            cursor.execute("SHOW TABLES")
            tables = [table[0] for table in cursor.fetchall()]
            
            print(f"✅ Conexión exitosa")
            print(f"📊 Versión: {version}")
            print(f"📋 Tablas: {len(tables)} encontradas")
            
            if tables:
                print("\nTablas en la base de datos:")
                for table in tables:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    print(f"  • {table}: {count} registros")
            
            cursor.close()
            connection.close()
            return True
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def show_status(self):
        print("📊 Estado de NVD Monitor")
        print("========================")
        try:
            import subprocess
            
            # Estado del servicio
            result = subprocess.run(['systemctl', 'is-active', 'nvd-monitor'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Servicio: Activo")
            else:
                print("❌ Servicio: Inactivo")
            
            # Información adicional
            result = subprocess.run(['systemctl', 'status', 'nvd-monitor', '--no-pager'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Active:' in line or 'Main PID:' in line or 'Memory:' in line:
                        print(f"  {line.strip()}")
            
            # Estadísticas de la base de datos
            print("\n📈 Estadísticas:")
            self.show_stats()
            
        except Exception as e:
            print(f"❓ Error obteniendo estado: {e}")
    
    def show_stats(self):
        """Muestra estadísticas de la base de datos"""
        try:
            import mysql.connector
            
            connection = mysql.connector.connect(
                host=self.config.get('database', 'host'),
                database=self.config.get('database', 'database'),
                user=self.config.get('database', 'user'),
                password=self.config.get('database', 'password')
            )
            
            cursor = connection.cursor()
            
            # Total de vulnerabilidades
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            total = cursor.fetchone()[0]
            print(f"  • Total vulnerabilidades: {total}")
            
            # Por severidad
            cursor.execute("""
                SELECT cvss_severity, COUNT(*) 
                FROM vulnerabilities 
                WHERE cvss_severity IS NOT NULL
                GROUP BY cvss_severity
            """)
            for severity, count in cursor.fetchall():
                print(f"  • {severity}: {count}")
            
            # Última verificación
            cursor.execute("""
                SELECT config_value 
                FROM system_config 
                WHERE config_key = 'last_check'
            """)
            result = cursor.fetchone()
            if result:
                print(f"  • Última verificación: {result[0]}")
            
            cursor.close()
            connection.close()
            
        except Exception as e:
            print(f"  Error obteniendo estadísticas: {e}")
    
    def test_email(self, test_recipient=None):
        """Envía un correo de prueba"""
        print("📧 Probando configuración de email...")
        
        try:
            smtp_server = self.config.get('email', 'smtp_server', fallback='')
            smtp_port = self.config.getint('email', 'smtp_port', fallback=587)
            sender_email = self.config.get('email', 'sender_email', fallback='')
            sender_password = self.config.get('email', 'sender_password', fallback='')
            recipient_email = test_recipient or self.config.get('email', 'recipient_email', fallback='')
            
            if not all([smtp_server, sender_email, sender_password, recipient_email]):
                print("❌ Error: Configuración de email incompleta")
                print("   Configuración actual:")
                print(f"   - Servidor SMTP: {smtp_server or 'NO CONFIGURADO'}")
                print(f"   - Puerto: {smtp_port}")
                print(f"   - Email remitente: {sender_email or 'NO CONFIGURADO'}")
                print(f"   - Contraseña: {'****' if sender_password else 'NO CONFIGURADA'}")
                print(f"   - Destinatarios: {recipient_email or 'NO CONFIGURADO'}")
                print("\n   Verifique la sección [email] en /etc/nvd-monitor/config.ini")
                return False
            
            # Crear mensaje
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Subject'] = "🧪 NVD Monitor - Correo de Prueba"
            
            body = f"""
¡Hola!

Este es un correo de prueba del sistema NVD Monitor.

✅ La configuración de email está funcionando correctamente.

Detalles del sistema:
- Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Servidor SMTP: {smtp_server}:{smtp_port}
- Remitente: {sender_email}
- Versión: 1.0.9 Final

Si recibiste este mensaje, las notificaciones por email están configuradas correctamente.

Saludos,
NVD Monitor System
"""
            msg.attach(MIMEText(body, 'plain'))
            
            # Enviar correo
            print(f"📤 Enviando correo de prueba a: {recipient_email}")
            print(f"   Usando servidor: {smtp_server}:{smtp_port}")
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            server.quit()
            
            print("✅ Correo de prueba enviado exitosamente")
            return True
            
        except Exception as e:
            print(f"❌ Error enviando correo: {e}")
            return False
    
    def test_nvd_api(self):
        """Prueba la conexión con la API de NVD"""
        print("🌐 Probando conexión con API de NVD...")
        
        try:
            api_key = self.config.get('nvd', 'api_key', fallback='')
            
            import requests
            
            headers = {}
            if api_key:
                headers['apiKey'] = api_key
                print(f"🔑 Usando API Key configurada: {api_key[:8]}...{api_key[-4:]}")
            else:
                print("⚠️  Sin API Key (límite: 5 requests/30 segundos)")
            
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                print("✅ Conexión exitosa con API de NVD")
                print(f"📊 Total de CVEs disponibles: {data.get('totalResults', 'N/A')}")
                
                # Verificar límites de rate
                rate_limit = response.headers.get('X-RateLimit-Limit', 'N/A')
                rate_remaining = response.headers.get('X-RateLimit-Remaining', 'N/A')
                print(f"📈 Límite de requests: {rate_limit}")
                print(f"📉 Requests restantes: {rate_remaining}")
                
                return True
            else:
                print(f"❌ Error: Status HTTP {response.status_code}")
                print(f"   Respuesta: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error conectando con API: {e}")
            return False
    
    def show_vulnerabilities(self, limit=10, severity=None):
        """Muestra las últimas vulnerabilidades detectadas"""
        print(f"🔍 Mostrando últimas {limit} vulnerabilidades")
        if severity:
            print(f"   Filtro de severidad: {severity}")
        
        try:
            import mysql.connector
            
            connection = mysql.connector.connect(
                host=self.config.get('database', 'host'),
                database=self.config.get('database', 'database'),
                user=self.config.get('database', 'user'),
                password=self.config.get('database', 'password'),
                port=self.config.getint('database', 'port', fallback=3306)
            )
            
            cursor = connection.cursor(dictionary=True)
            
            # Construir query
            query = """
            SELECT cve_id, cvss_severity, cvss_score, 
                   DATE_FORMAT(published_date, '%Y-%m-%d %H:%i') as published,
                   LEFT(description, 100) as description
            FROM vulnerabilities
            """
            
            params = []
            if severity:
                query += " WHERE cvss_severity = %s"
                params.append(severity)
            
            query += " ORDER BY published_date DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            vulns = cursor.fetchall()
            
            if vulns:
                # Preparar datos para tabla
                headers = ['CVE ID', 'Severidad', 'CVSS', 'Publicado', 'Descripción']
                rows = []
                
                for vuln in vulns:
                    # Colorear severidad
                    severity_color = {
                        'CRITICAL': '\033[91m',  # Rojo
                        'HIGH': '\033[93m',      # Amarillo
                        'MEDIUM': '\033[94m',    # Azul
                        'LOW': '\033[92m'        # Verde
                    }
                    
                    sev = vuln['cvss_severity'] or 'N/A'
                    if sev in severity_color:
                        sev = f"{severity_color[sev]}{sev}\033[0m"
                    
                    rows.append([
                        vuln['cve_id'],
                        sev,
                        vuln['cvss_score'] or 'N/A',
                        vuln['published'],
                        vuln['description'][:60] + '...' if vuln['description'] else 'N/A'
                    ])
                
                print("\n" + tabulate(rows, headers=headers, tablefmt='grid'))
                print(f"\n✅ Total: {len(vulns)} vulnerabilidades encontradas")
            else:
                print("⚠️  No se encontraron vulnerabilidades")
            
            cursor.close()
            connection.close()
            
        except Exception as e:
            print(f"❌ Error consultando vulnerabilidades: {e}")
    
    def update_config(self):
        """Actualiza la configuración interactivamente"""
        print("⚙️  Actualización de Configuración")
        print("=" * 50)
        
        if not os.access(self.config_file, os.W_OK):
            print("❌ Error: No tiene permisos para modificar la configuración")
            print("   Ejecute con sudo: sudo nvd-admin update-config")
            return
        
        sections = {
            '1': ('monitoring', 'check_interval_hours', 'Intervalo de verificación (horas)'),
            '2': ('nvd', 'api_key', 'API Key de NVD'),
            '3': ('email', 'smtp_server', 'Servidor SMTP'),
            '4': ('email', 'smtp_port', 'Puerto SMTP'),
            '5': ('email', 'sender_email', 'Email remitente'),
            '6': ('email', 'sender_password', 'Contraseña remitente'),
            '7': ('email', 'recipient_email', 'Email(s) destinatario(s)')
        }
        
        while True:
            print("\n¿Qué desea configurar?")
            for key, (section, option, desc) in sections.items():
                current = self.config.get(section, option, fallback='No configurado')
                if option == 'sender_password' and current:
                    current = '***' + current[-4:] if len(current) > 4 else '****'
                elif option == 'api_key' and current:
                    current = current[:8] + '...' + current[-4:]
                print(f"  {key}. {desc}: {current}")
            print("  0. Salir")
            
            choice = input("\nSeleccione una opción: ").strip()
            
            if choice == '0':
                break
            
            if choice in sections:
                section, option, desc = sections[choice]
                current = self.config.get(section, option, fallback='')
                
                if option == 'sender_password':
                    import getpass
                    new_value = getpass.getpass(f"Nuevo valor para {desc}: ")
                else:
                    new_value = input(f"Nuevo valor para {desc} (actual: {current}): ").strip()
                
                if new_value:
                    if section not in self.config:
                        self.config.add_section(section)
                    self.config.set(section, option, new_value)
                    
                    # Guardar configuración
                    with open(self.config_file, 'w') as f:
                        self.config.write(f)
                    
                    print(f"✅ {desc} actualizado")
                    
                    # Reiniciar servicio si está activo
                    import subprocess
                    if subprocess.run(['systemctl', 'is-active', 'nvd-monitor'], 
                                    capture_output=True).returncode == 0:
                        print("🔄 Reiniciando servicio...")
                        subprocess.run(['systemctl', 'restart', 'nvd-monitor'])

def main():
    parser = argparse.ArgumentParser(description='NVD Admin Tools v1.0.9')
    
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')
    
    # Comandos básicos
    subparsers.add_parser('test-db', help='Probar conexión a base de datos')
    subparsers.add_parser('status', help='Mostrar estado del servicio')
    subparsers.add_parser('test-nvd-api', help='Probar conexión con API de NVD')
    subparsers.add_parser('update-config', help='Actualizar configuración')
    
    # Comando test-email
    email_parser = subparsers.add_parser('test-email', help='Enviar correo de prueba')
    email_parser.add_argument('recipient', nargs='?', help='Email destinatario (opcional)')
    
    # Comando show-vulns
    vulns_parser = subparsers.add_parser('show-vulns', help='Mostrar vulnerabilidades')
    vulns_parser.add_argument('--limit', type=int, default=10, help='Número de vulnerabilidades a mostrar')
    vulns_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], 
                            help='Filtrar por severidad')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    admin = NVDAdmin()
    
    if args.command == 'test-db':
        sys.exit(0 if admin.test_database() else 1)
    elif args.command == 'status':
        admin.show_status()
    elif args.command == 'test-email':
        sys.exit(0 if admin.test_email(args.recipient) else 1)
    elif args.command == 'test-nvd-api':
        sys.exit(0 if admin.test_nvd_api() else 1)
    elif args.command == 'show-vulns':
        admin.show_vulnerabilities(args.limit, args.severity)
    elif args.command == 'update-config':
        admin.update_config()

if __name__ == "__main__":
    main()
ADMINEOF
    
    chmod +x "$INSTALL_DIR/nvd_admin.py"
    chown "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR/nvd_admin.py"
    log_success "Herramientas admin avanzadas creadas"
}

# Crear comandos globales
create_commands() {
    log_step "Creando comandos globales..."
    
    cat > /usr/local/bin/nvd-monitor << CMDEOF
#!/bin/bash
cd "$INSTALL_DIR"
exec ./venv/bin/python nvd_monitor.py "\$@"
CMDEOF
    chmod +x /usr/local/bin/nvd-monitor
    
    cat > /usr/local/bin/nvd-admin << ADMINCMDEOF
#!/bin/bash
cd "$INSTALL_DIR"
exec ./venv/bin/python nvd_admin.py "\$@"
ADMINCMDEOF
    chmod +x /usr/local/bin/nvd-admin
    
    cat > /usr/local/bin/nvd-status << 'STATUSEOF'
#!/bin/bash
echo "📊 Estado de NVD Monitor"
echo "========================"
systemctl is-active nvd-monitor >/dev/null 2>&1 && echo "✅ Servicio: Activo" || echo "❌ Servicio: Inactivo"
echo
echo "Para más detalles use: nvd-admin status"
STATUSEOF
    chmod +x /usr/local/bin/nvd-status
    
    log_success "Comandos globales creados"
}

# Crear servicio systemd
create_service() {
    log_step "Creando servicio systemd..."
    
    cat > /etc/systemd/system/nvd-monitor.service << SERVICEEOF
[Unit]
Description=NVD Vulnerability Monitor
After=network.target mariadb.service mysql.service
Wants=network.target

[Service]
Type=simple
User=$INSTALL_USER
Group=$INSTALL_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/nvd_monitor.py --daemon
Restart=always
RestartSec=30

# Configuración de seguridad
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$LOG_DIR $DATA_DIR $CONFIG_DIR

# Variables de entorno
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SERVICEEOF
    
    systemctl daemon-reload
    log_success "Servicio systemd creado"
}

# Configurar base de datos
setup_database() {
    log_step "Configurando base de datos..."
    
    DB_PASSWORD=$(generate_password)
    
    log_info "Configurando usuario y base de datos nvd_monitor..."
    
    # Probar autenticación
    local mysql_cmd=""
    if mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
        mysql_cmd="mysql -u root"
    elif sudo mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
        mysql_cmd="sudo mysql -u root"
    else
        log_error "No se pudo autenticar con MySQL/MariaDB"
        exit 1
    fi
    
    # Crear script SQL temporal
    cat > /tmp/nvd_setup.sql << SQLEOF
-- Eliminar usuario existente si existe
DROP USER IF EXISTS 'nvd_user'@'localhost';

-- Crear base de datos
CREATE DATABASE IF NOT EXISTS nvd_monitor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Crear usuario nuevo
CREATE USER 'nvd_user'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';

-- Otorgar permisos
GRANT ALL PRIVILEGES ON nvd_monitor.* TO 'nvd_user'@'localhost';

-- Aplicar cambios
FLUSH PRIVILEGES;

-- Usar la base de datos
USE nvd_monitor;

-- Crear tablas
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    published_date DATETIME,
    last_modified DATETIME,
    cvss_score DECIMAL(3,1),
    cvss_severity VARCHAR(20),
    description TEXT,
    reference_urls TEXT,
    affected_products TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_cve_id (cve_id),
    INDEX idx_severity (cvss_severity),
    INDEX idx_published (published_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS monitoring_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    vulnerabilities_found INT DEFAULT 0,
    new_vulnerabilities INT DEFAULT 0,
    status VARCHAR(50),
    message TEXT,
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS email_notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    recipient_email VARCHAR(255),
    subject VARCHAR(255),
    vulnerabilities_count INT,
    status VARCHAR(50),
    INDEX idx_sent_date (sent_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insertar configuración inicial
INSERT IGNORE INTO system_config (config_key, config_value, description) VALUES
('installation_date', NOW(), 'Fecha de instalación del sistema'),
('database_version', '1.0.9', 'Versión del esquema de base de datos'),
('last_check', NULL, 'Última verificación de vulnerabilidades'),
('total_vulnerabilities', '0', 'Total de vulnerabilidades en la base de datos');
SQLEOF
    
    # Ejecutar script
    $mysql_cmd < /tmp/nvd_setup.sql || {
        log_error "Error ejecutando comandos SQL"
        rm -f /tmp/nvd_setup.sql
        exit 1
    }
    
    rm -f /tmp/nvd_setup.sql
    
    log_success "Base de datos configurada correctamente"
    
    # Verificar conexión
    if mysql -u nvd_user -p"${DB_PASSWORD}" nvd_monitor -e "SELECT COUNT(*) FROM system_config;" &>/dev/null; then
        log_success "Usuario nvd_user verificado"
    else
        log_error "Error verificando usuario nvd_user"
        exit 1
    fi
}

# Configuración de API Key
configure_api_key() {
    log_header "CONFIGURACIÓN DE API KEY NVD"
    
    echo "🔑 API Key de NVD (opcional pero recomendado):"
    echo "   • Sin API key: 5 requests/30 segundos"
    echo "   • Con API key: 50 requests/30 segundos"
    echo "   • Obtener en: https://nvd.nist.gov/developers/request-an-api-key"
    echo
    
    read -p "¿Configurar API key ahora? (y/N): " configure_api
    if [[ $configure_api =~ ^[Yy]$ ]]; then
        read -p "Ingrese su API key: " API_KEY
        if [[ -n "$API_KEY" ]]; then
            log_success "API key configurada"
        else
            API_KEY=""
        fi
    else
        API_KEY=""
        log_info "API key omitida (puede configurarla después con: sudo nvd-admin update-config)"
    fi
}

# Configuración de email mejorada
configure_email() {
    log_header "CONFIGURACIÓN DE EMAIL"
    
    echo "📧 Notificaciones por email para alertas de vulnerabilidades"
    echo
    
    read -p "¿Configurar email ahora? (y/N): " configure_mail
    if [[ $configure_mail =~ ^[Yy]$ ]]; then
        
        # Servidor SMTP
        echo
        echo "📮 SERVIDOR SMTP:"
        echo "Ejemplos comunes:"
        echo "  • Gmail: smtp.gmail.com (puerto 587)"
        echo "  • Outlook: smtp-mail.outlook.com (puerto 587)"
        echo "  • Yahoo: smtp.mail.yahoo.com (puerto 587)"
        echo "  • Office 365: smtp.office365.com (puerto 587)"
        echo "  • Personalizado: su.servidor.smtp.com"
        echo
        read -p "Servidor SMTP [smtp.gmail.com]: " smtp_input
        SMTP_SERVER=${smtp_input:-smtp.gmail.com}
        
        read -p "Puerto SMTP [587]: " port_input
        SMTP_PORT=${port_input:-587}
        
        # Email remitente
        echo
        while true; do
            read -p "Email remitente: " SENDER_EMAIL
            if validate_email "$SENDER_EMAIL"; then
                break
            else
                echo "❌ Email inválido"
            fi
        done
        
        # Contraseña del remitente
        echo
        echo "⚠️  IMPORTANTE SOBRE LA CONTRASEÑA:"
        echo "   • Gmail: Use una 'Contraseña de Aplicación' (no su contraseña regular)"
        echo "     Generar en: https://myaccount.google.com/apppasswords"
        echo "   • Outlook/Office365: Use contraseña de aplicación si tiene 2FA activo"
        echo "   • Otros: Use su contraseña regular del email"
        echo
        read -s -p "Contraseña del remitente: " SENDER_PASSWORD
        echo
        
        # Emails destinatarios
        echo
        echo "📧 DESTINATARIOS DE ALERTAS:"
        echo "Puede ingresar múltiples emails separados por comas"
        echo "Ejemplo: admin@empresa.com, security@empresa.com"
        
        while true; do
            read -p "Email(s) destinatario(s): " recipient_input
            
            if [[ -z "$recipient_input" ]]; then
                echo "❌ Debe ingresar al menos un email"
                continue
            fi
            
            # Procesar múltiples emails
            IFS=',' read -ra emails <<< "$recipient_input"
            valid_emails=()
            
            for email in "${emails[@]}"; do
                email=$(echo "$email" | xargs)
                if validate_email "$email"; then
                    valid_emails+=("$email")
                else
                    echo "❌ Email inválido: $email"
                fi
            done
            
            if [ ${#valid_emails[@]} -gt 0 ]; then
                RECIPIENT_EMAIL=$(IFS=','; echo "${valid_emails[*]}")
                echo "✅ Emails configurados: $RECIPIENT_EMAIL"
                break
            else
                echo "❌ No se ingresaron emails válidos"
            fi
        done
        
        log_success "Email configurado"
    else
        SENDER_EMAIL=""
        SENDER_PASSWORD=""
        RECIPIENT_EMAIL=""
        log_info "Email omitido (puede configurarlo después con: sudo nvd-admin update-config)"
    fi
}

# Crear archivo de configuración con permisos correctos
create_config_file() {
    log_step "Creando archivo de configuración..."
    
    cat > "$CONFIG_DIR/config.ini" << CONFEOF
[database]
host = localhost
port = 3306
database = nvd_monitor
user = nvd_user
password = ${DB_PASSWORD}

[nvd]
api_key = ${API_KEY}
base_url = https://services.nvd.nist.gov/rest/json/cves/2.0

[email]
smtp_server = ${SMTP_SERVER}
smtp_port = ${SMTP_PORT}
sender_email = ${SENDER_EMAIL}
sender_password = ${SENDER_PASSWORD}
recipient_email = ${RECIPIENT_EMAIL}

[monitoring]
check_interval_hours = ${MONITOR_INTERVAL}
results_per_page = 200
days_back = 7

[logging]
level = INFO
file = /var/log/nvd-monitor/nvd-monitor.log
max_size_mb = 100
backup_count = 5
CONFEOF
    
    # Configurar permisos correctos
    chown root:"$INSTALL_USER" "$CONFIG_DIR/config.ini"
    chmod 640 "$CONFIG_DIR/config.ini"
    
    log_success "Configuración creada con permisos correctos"
}

# Finalizar instalación con validaciones
finalize_installation() {
    log_step "Finalizando instalación y validando permisos..."
    
    # Asegurar que el grupo existe
    if ! getent group "$INSTALL_USER" >/dev/null 2>&1; then
        groupadd "$INSTALL_USER"
    fi
    
    # Validar permisos del archivo de configuración
    log_info "Validando permisos de configuración..."
    
    # Si el usuario actual no es root, agregarlo al grupo
    if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
        if ! groups "$CURRENT_USER" 2>/dev/null | grep -q "$INSTALL_USER"; then
            usermod -a -G "$INSTALL_USER" "$CURRENT_USER"
            log_warn "Usuario $CURRENT_USER agregado al grupo $INSTALL_USER"
            log_warn "⚠️  IMPORTANTE: Debe cerrar sesión y volver a entrar para que los cambios surtan efecto"
            log_warn "   O ejecute: newgrp $INSTALL_USER"
        fi
    fi
    
    # Verificar que nvd-monitor puede leer la configuración
    if ! sudo -u "$INSTALL_USER" test -r "$CONFIG_DIR/config.ini"; then
        log_error "Error: Usuario $INSTALL_USER no puede leer la configuración"
        log_error "Intentando corregir..."
        chmod 640 "$CONFIG_DIR/config.ini"
        chown root:"$INSTALL_USER" "$CONFIG_DIR/config.ini"
    fi
    
    log_success "Permisos verificados y corregidos"
    
    # Probar herramientas básicas
    log_info "Probando instalación..."
    
    # Test de sintaxis Python
    if sudo -u "$INSTALL_USER" "$INSTALL_DIR/venv/bin/python" -m py_compile "$INSTALL_DIR/nvd_monitor.py"; then
        log_success "Sintaxis de aplicación principal: OK"
    else
        log_error "Error en sintaxis de aplicación principal"
        exit 1
    fi
    
    # Iniciar servicio
    log_info "Iniciando servicio NVD Monitor..."
    systemctl enable nvd-monitor
    systemctl start nvd-monitor
    
    sleep 5
    if systemctl is-active --quiet nvd-monitor; then
        log_success "Servicio iniciado correctamente"
    else
        log_error "Error iniciando servicio"
        echo "🔍 Ver logs del servicio:"
        echo "sudo journalctl -u nvd-monitor -n 20 --no-pager"
    fi
}

# Crear script de prueba post-instalación
create_test_script() {
    log_step "Creando script de prueba post-instalación..."
    
    cat > "$DATA_DIR/scripts/test_installation.sh" << 'TESTSCRIPT'
#!/bin/bash

echo "🧪 PRUEBA DE INSTALACIÓN NVD MONITOR"
echo "===================================="
echo

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Función de prueba
test_feature() {
    local name="$1"
    local command="$2"
    echo -n "Probando $name... "
    if eval "$command" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ OK${NC}"
        return 0
    else
        echo -e "${RED}❌ FALLO${NC}"
        return 1
    fi
}

# Pruebas
echo "1️⃣ PRUEBAS DE SISTEMA:"
test_feature "Servicio activo" "systemctl is-active nvd-monitor"
test_feature "Base de datos" "nvd-admin test-db"
test_feature "API de NVD" "nvd-admin test-nvd-api"

echo
echo "2️⃣ PRUEBAS DE FUNCIONALIDAD:"
test_feature "Ejecución manual" "nvd-monitor --run-once"
test_feature "Email configurado" "grep -q sender_email /etc/nvd-monitor/config.ini && grep -q sender_password /etc/nvd-monitor/config.ini"

echo
echo "3️⃣ ESTADÍSTICAS:"
nvd-admin status

echo
echo "✅ Prueba completada"
TESTSCRIPT
    
    chmod +x "$DATA_DIR/scripts/test_installation.sh"
    chown "$INSTALL_USER:$INSTALL_USER" "$DATA_DIR/scripts/test_installation.sh"
}

# Mostrar resumen mejorado
show_summary() {
    log_header "INSTALACIÓN COMPLETADA"
    
    echo -e "${GREEN}🎉 NVD Monitor v${SCRIPT_VERSION} instalado exitosamente${NC}"
    echo
    echo "📊 ESTADO ACTUAL:"
    nvd-status
    
    # Verificar configuración
    echo
    echo "⚙️ CONFIGURACIÓN:"
    if [[ -n "$API_KEY" ]]; then
        echo "✅ API Key de NVD configurada"
    else
        echo "⚠️  API Key de NVD no configurada (funcionalidad limitada)"
    fi
    
    if [[ -n "$SENDER_EMAIL" ]]; then
        echo "✅ Notificaciones por email configuradas"
        echo "   📧 Servidor: $SMTP_SERVER:$SMTP_PORT"
        echo "   📧 Remitente: $SENDER_EMAIL"
        echo "   📧 Destinatarios: $RECIPIENT_EMAIL"
    else
        echo "⚠️  Notificaciones por email no configuradas"
    fi
    
    echo
    echo "🔧 COMANDOS DISPONIBLES:"
    echo
    echo "COMANDOS BÁSICOS:"
    echo "  • nvd-status                    - Ver estado del servicio"
    echo "  • nvd-monitor --run-once        - Ejecutar verificación manual"
    echo "  • nvd-monitor --test-api        - Probar conexión con API de NVD"
    echo "  • nvd-monitor --check-recent 7  - Verificar vulnerabilidades de los últimos 7 días"
    echo
    echo "COMANDOS ADMINISTRATIVOS:"
    echo "  • nvd-admin status              - Estado detallado con estadísticas"
    echo "  • nvd-admin test-db             - Probar conexión a base de datos"
    echo "  • nvd-admin test-nvd-api        - Validar conexión a API de NVD"
    echo "  • nvd-admin test-email [email]  - Enviar correo de prueba"
    echo "  • nvd-admin update-config       - Actualizar configuración"
    echo
    echo "CONSULTA DE VULNERABILIDADES:"
    echo "  • nvd-admin show-vulns --limit 10              - Últimas 10 vulnerabilidades"
    echo "  • nvd-admin show-vulns --limit 20              - Últimas 20 vulnerabilidades"
    echo "  • nvd-admin show-vulns --severity CRITICAL     - Solo vulnerabilidades críticas"
    echo "  • nvd-admin show-vulns --severity HIGH         - Solo vulnerabilidades altas"
    echo
    echo "📁 ARCHIVOS Y DIRECTORIOS:"
    echo "  • Configuración: /etc/nvd-monitor/config.ini"
    echo "  • Logs: /var/log/nvd-monitor/nvd-monitor.log"
    echo "  • Aplicación: /opt/nvd-monitor/"
    echo "  • Scripts: /var/lib/nvd-monitor/scripts/"
    echo
    
    # Mostrar advertencia sobre permisos si es necesario
    if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
        echo -e "${YELLOW}⚠️  IMPORTANTE SOBRE PERMISOS:${NC}"
        echo "   Para usar comandos administrativos sin sudo:"
        echo "   1. Cierre sesión y vuelva a entrar"
        echo "   2. O ejecute: newgrp $INSTALL_USER"
        echo "   3. O use sudo con los comandos"
        echo
    fi
    
    echo "🚀 PRÓXIMOS PASOS RECOMENDADOS:"
    echo
    
    local step_num=1
    
    # Probar instalación
    echo "${step_num}. 🧪 Ejecutar prueba de instalación:"
    echo "   sudo bash /var/lib/nvd-monitor/scripts/test_installation.sh"
    echo
    ((step_num++))
    
    if [[ -z "$API_KEY" ]]; then
        echo "${step_num}. 🔑 Configurar API Key de NVD para mejor rendimiento:"
        echo "   • Obtener en: https://nvd.nist.gov/developers/request-an-api-key"
        echo "   • Configurar: sudo nvd-admin update-config"
        echo
        ((step_num++))
    fi
    
    if [[ -n "$SENDER_EMAIL" ]]; then
        echo "${step_num}. 📧 Probar notificaciones por email:"
        echo "   • sudo nvd-admin test-email"
        echo
        ((step_num++))
    else
        echo "${step_num}. 📧 Configurar notificaciones por email:"
        echo "   • Ejecutar: sudo nvd-admin update-config"
        echo "   • Probar: sudo nvd-admin test-email"
        echo
        ((step_num++))
    fi
    
    echo "${step_num}. 🔍 Verificar funcionamiento completo:"
    echo "   • sudo nvd-monitor --check-recent 7  # Cargar vulnerabilidades de los últimos 7 días"
    echo "   • sudo nvd-admin show-vulns --severity HIGH"
    echo "   • sudo journalctl -u nvd-monitor -f  # Ver logs en tiempo real"
    echo
    ((step_num++))
    
    echo "${step_num}. 📊 El sistema monitoreará vulnerabilidades cada ${MONITOR_INTERVAL} horas automáticamente"
    echo
    
    # Información adicional
    echo "📚 INFORMACIÓN ADICIONAL:"
    echo "• Las vulnerabilidades se descargan desde la fecha de la última verificación"
    echo "• Solo se notifican vulnerabilidades CRITICAL y HIGH"
    echo "• Los emails incluyen formato HTML con las vulnerabilidades más importantes"
    echo "• El servicio se reinicia automáticamente en caso de fallo"
    echo
    
    log_success "¡Sistema listo para proteger su infraestructura!"
}

# Función principal
main() {
    case "${1:-}" in
        -h|--help)
            echo "NVD Vulnerability Monitor Installer v${SCRIPT_VERSION} Final"
            echo "Uso: sudo bash install.sh"
            echo
            echo "Este instalador incluye:"
            echo "• Monitor completo de vulnerabilidades NVD"
            echo "• Sistema de notificaciones por email funcional"
            echo "• Descarga real de vulnerabilidades desde NVD API"
            echo "• Soporte para múltiples servidores SMTP"
            echo "• Herramientas administrativas completas"
            echo "• Permisos optimizados y validados"
            echo
            echo "Compatible con Ubuntu 20.04+ LTS"
            exit 0
            ;;
        -v|--version)
            echo "v${SCRIPT_VERSION}"
            exit 0
            ;;
    esac
    
    show_welcome_banner
    check_prerequisites
    install_dependencies
    create_system_user
    create_directories
    setup_python
    create_application
    create_admin_tools
    create_commands
    create_service
    setup_database
    configure_api_key
    configure_email
    create_config_file
    create_test_script
    finalize_installation
    show_summary
}

# Manejo de errores mejorado
error_handler() {
    local exit_code=$?
    local line_number=$1
    
    echo -e "\n${RED}================================================================${NC}"
    echo -e "${RED}  ERROR EN LA INSTALACIÓN${NC}"
    echo -e "${RED}================================================================${NC}"
    echo
    log_error "Error en línea $line_number (código: $exit_code)"
    
    echo
    echo "🔍 INFORMACIÓN DE DIAGNÓSTICO:"
    echo "• Línea del error: $line_number"
    echo "• Código de salida: $exit_code"
    echo "• Versión del script: $SCRIPT_VERSION"
    echo "• Usuario ejecutando: $USER"
    echo "• Usuario sudo: ${SUDO_USER:-N/A}"
    
    cleanup
    exit $exit_code
}

trap 'error_handler $LINENO' ERR

# Ejecutar función principal
main "$@"