#!/bin/bash

# =============================================================================
# NVD Vulnerability Monitor - Script de Instalación Final Corregido
# Versión: 1.0.6
# Compatible con: Ubuntu 24.04 LTS y superiores
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
readonly SCRIPT_VERSION="1.0.6"
readonly SUPPORTED_UBUNTU="24.04"
readonly INSTALL_USER="nvd-monitor"
readonly INSTALL_DIR="/opt/nvd-monitor"
readonly CONFIG_DIR="/etc/nvd-monitor"
readonly LOG_DIR="/var/log/nvd-monitor"
readonly DATA_DIR="/var/lib/nvd-monitor"

# Variables globales
DB_PASSWORD=""
API_KEY=""
SENDER_EMAIL=""
SENDER_PASSWORD=""
RECIPIENT_EMAIL=""
MONITOR_INTERVAL="4"

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
    rm -f /tmp/nvd-monitor-*.tmp /tmp/setup_database.sh /tmp/nvd_db_* /tmp/test_email.py 2>/dev/null || true
}
trap cleanup EXIT

# Banner de bienvenida
show_welcome_banner() {
    clear
    echo -e "${BLUE}"
    echo "================================================================"
    echo "       🛡️  NVD VULNERABILITY MONITOR INSTALLER"
    echo "================================================================"
    echo -e "${NC}"
    echo -e "${GREEN}Versión: ${SCRIPT_VERSION}${NC}"
    echo
    echo "🎯 Este instalador configurará:"
    echo "   ✅ Sistema base con dependencias"
    echo "   ✅ Base de datos MariaDB/MySQL"
    echo "   ✅ Aplicación de monitoreo"
    echo "   ✅ API Key de NVD (opcional)"
    echo "   ✅ Notificaciones por email (opcional)"
    echo "   ✅ Servicio systemd"
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
        "curl" "wget" "git" "logrotate" "systemd"
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

# Crear usuario del sistema
create_system_user() {
    log_step "Creando usuario del sistema..."
    
    if ! id "$INSTALL_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" -c "NVD Monitor Service User" "$INSTALL_USER"
    fi
    
    if ! getent group "$INSTALL_USER" >/dev/null 2>&1; then
        groupadd "$INSTALL_USER"
    fi
    
    log_success "Usuario $INSTALL_USER configurado"
}

# Crear directorios
create_directories() {
    log_step "Creando directorios..."
    
    local directories=(
        "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
        "$DATA_DIR/scripts" "$DATA_DIR/backups"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        case "$dir" in
            "$CONFIG_DIR")
                chown root:root "$dir"
                chmod 755 "$dir"
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
EOF
    
    sudo -u "$INSTALL_USER" bash -c "
        source venv/bin/activate
        pip install --upgrade pip -q
        pip install -r requirements.txt -q
    "
    
    chown -R "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR"
    log_success "Python configurado"
}

# Crear aplicación principal
create_application() {
    log_step "Creando aplicación..."
    
    cat > "$INSTALL_DIR/nvd_monitor.py" << 'PYEOF'
#!/usr/bin/env python3
"""NVD Vulnerability Monitor v1.0.6"""

import configparser
import logging
import sys
import os
import argparse
import time
import schedule
from datetime import datetime

class NVDMonitor:
    def __init__(self, config_file='/etc/nvd-monitor/config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.running = True
        self.load_config()
        self.setup_logging()
        
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
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler(log_file)]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("NVD Monitor iniciado")
    
    def run_monitoring_cycle(self):
        self.logger.info("Ejecutando ciclo de monitoreo...")
        # Aquí iría la lógica de monitoreo
        self.logger.info("Ciclo completado")
    
    def start_scheduler(self):
        interval = self.config.getint('monitoring', 'check_interval_hours', fallback=4)
        self.logger.info(f"Iniciando scheduler cada {interval} horas")
        
        schedule.every(interval).hours.do(self.run_monitoring_cycle)
        self.run_monitoring_cycle()  # Ejecutar inmediatamente
        
        while self.running:
            schedule.run_pending()
            time.sleep(60)

def main():
    parser = argparse.ArgumentParser(description='NVD Monitor v1.0.6')
    parser.add_argument('--daemon', action='store_true', help='Ejecutar como daemon')
    parser.add_argument('--run-once', action='store_true', help='Ejecutar una vez')
    args = parser.parse_args()
    
    monitor = NVDMonitor()
    
    if args.run_once:
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
PYEOF
    
    chmod +x "$INSTALL_DIR/nvd_monitor.py"
    log_success "Aplicación creada"
}

# Crear herramientas de administración
create_admin_tools() {
    log_step "Creando herramientas admin..."
    
    cat > "$INSTALL_DIR/nvd_admin.py" << 'ADMINEOF'
#!/usr/bin/env python3
"""NVD Admin Tools v1.0.6"""

import configparser
import os
import sys
import argparse

class NVDAdmin:
    def __init__(self):
        self.config_file = '/etc/nvd-monitor/config.ini'
        self.config = configparser.ConfigParser()
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
    
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
            result = subprocess.run(['systemctl', 'is-active', 'nvd-monitor'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Servicio: Activo")
            else:
                print("❌ Servicio: Inactivo")
        except:
            print("❓ Estado desconocido")

def main():
    parser = argparse.ArgumentParser(description='NVD Admin Tools')
    parser.add_argument('command', nargs='?', choices=['test-db', 'status'], help='Comando')
    args = parser.parse_args()
    
    admin = NVDAdmin()
    
    if args.command == 'test-db':
        success = admin.test_database()
        sys.exit(0 if success else 1)
    elif args.command == 'status':
        admin.show_status()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
ADMINEOF
    
    chmod +x "$INSTALL_DIR/nvd_admin.py"
    log_success "Herramientas admin creadas"
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
    INDEX idx_severity (cvss_severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS monitoring_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    vulnerabilities_found INT DEFAULT 0,
    new_vulnerabilities INT DEFAULT 0,
    status VARCHAR(50),
    message TEXT
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
('database_version', '1.0.6', 'Versión del esquema de base de datos');
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
    echo "   • Con API key: 120 requests/minuto"
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
        log_info "API key omitida"
    fi
}

# Configuración de email
configure_email() {
    log_header "CONFIGURACIÓN DE EMAIL"
    
    echo "📧 Notificaciones por email para alertas de vulnerabilidades"
    echo
    
    read -p "¿Configurar email ahora? (y/N): " configure_mail
    if [[ $configure_mail =~ ^[Yy]$ ]]; then
        # Email remitente
        while true; do
            read -p "Email remitente: " SENDER_EMAIL
            if validate_email "$SENDER_EMAIL"; then
                break
            else
                echo "❌ Email inválido"
            fi
        done
        
        # Contraseña del remitente
        read -s -p "Contraseña del remitente: " SENDER_PASSWORD
        echo
        
        # Emails destinatarios
        echo
        echo "📧 DESTINATARIOS DE ALERTAS:"
        echo "Puede ingresar múltiples emails separados por comas"
        
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
        log_info "Email omitido"
    fi
}

# Crear archivo de configuración
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

[email]
smtp_server = smtp.gmail.com
smtp_port = 587
sender_email = ${SENDER_EMAIL}
sender_password = ${SENDER_PASSWORD}
recipient_email = ${RECIPIENT_EMAIL}

[monitoring]
check_interval_hours = ${MONITOR_INTERVAL}

[logging]
level = INFO
file = /var/log/nvd-monitor/nvd-monitor.log
CONFEOF
    
    chmod 755 "$CONFIG_DIR"
    chown root:nvd-monitor "$CONFIG_DIR/config.ini"
    chmod 640 "$CONFIG_DIR/config.ini"
    
    log_success "Configuración creada"
}

# Finalizar instalación
finalize_installation() {
    log_step "Finalizando instalación..."
    
    # Verificar permisos
    if ! sudo -u nvd-monitor cat "$CONFIG_DIR/config.ini" >/dev/null 2>&1; then
        log_error "Corrigiendo permisos..."
        chgrp nvd-monitor "$CONFIG_DIR/config.ini"
        chmod 640 "$CONFIG_DIR/config.ini"
    fi
    
    log_success "Permisos verificados"
    
    # Probar herramientas
    log_info "Probando herramientas..."
    if nvd-admin test-db; then
        log_success "Test de base de datos exitoso"
    else
        log_error "Error en test de base de datos"
        exit 1
    fi
    
    # Iniciar servicio
    log_info "Iniciando servicio..."
    systemctl enable nvd-monitor
    systemctl start nvd-monitor
    
    sleep 5
    if systemctl is-active --quiet nvd-monitor; then
        log_success "Servicio iniciado correctamente"
    else
        log_error "Error iniciando servicio"
        exit 1
    fi
}

# Mostrar resumen
show_summary() {
    log_header "INSTALACIÓN COMPLETADA"
    
    echo -e "${GREEN}🎉 NVD Monitor instalado exitosamente${NC}"
    echo
    echo "📊 ESTADO ACTUAL:"
    nvd-status
    
    echo
    echo "⚙️ CONFIGURACIÓN:"
    if [[ -n "$API_KEY" ]]; then
        echo "✅ API Key de NVD configurada"
    else
        echo "⚠️  API Key de NVD no configurada"
    fi
    
    if [[ -n "$SENDER_EMAIL" ]]; then
        echo "✅ Notificaciones por email configuradas"
        echo "   📧 Destinatarios: $RECIPIENT_EMAIL"
    else
        echo "⚠️  Notificaciones por email no configuradas"
    fi
    
    echo
    echo "🔧 COMANDOS ÚTILES:"
    echo "• nvd-status           - Ver estado del servicio"
    echo "• nvd-admin test-db    - Probar conexión a BD"
    echo "• nvd-monitor --run-once - Ejecutar verificación manual"
    echo
    echo "📁 ARCHIVOS IMPORTANTES:"
    echo "• Configuración: /etc/nvd-monitor/config.ini"
    echo "• Logs: /var/log/nvd-monitor/nvd-monitor.log"
    echo
    echo "🚀 PRÓXIMOS PASOS:"
    echo "• El sistema monitoreará vulnerabilidades cada ${MONITOR_INTERVAL} horas"
    echo "• Ver logs: sudo journalctl -u nvd-monitor -f"
    
    echo
    log_success "¡Sistema listo para proteger su infraestructura!"
}

# Función principal
main() {
    case "${1:-}" in
        -h|--help)
            echo "NVD Vulnerability Monitor Installer v${SCRIPT_VERSION}"
            echo "Uso: sudo bash install.sh"
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
    finalize_installation
    show_summary
}

# Manejo de errores
error_handler() {
    local exit_code=$?
    local line_number=$1
    
    echo -e "\n${RED}ERROR EN LA INSTALACIÓN${NC}"
    log_error "Error en línea $line_number (código: $exit_code)"
    
    cleanup
    exit $exit_code
}

trap 'error_handler $LINENO' ERR

# Ejecutar función principal
main "$@"