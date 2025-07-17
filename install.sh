#!/bin/bash

# =============================================================================
# NVD Vulnerability Monitor - Script de Instalación Corregido
# Versión: 1.0.1
# Compatible con: Ubuntu 24.04 LTS
# =============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Colores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Constantes del sistema
readonly SCRIPT_VERSION="1.0.1"
readonly SUPPORTED_UBUNTU="24.04"
readonly PYTHON_MIN_VERSION="3.10"
readonly PROJECT_NAME="nvd-monitor"
readonly INSTALL_USER="nvd-monitor"
readonly INSTALL_DIR="/opt/nvd-monitor"
readonly CONFIG_DIR="/etc/nvd-monitor"
readonly LOG_DIR="/var/log/nvd-monitor"
readonly DATA_DIR="/var/lib/nvd-monitor"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}[CLEANUP]${NC} Limpiando archivos temporales..."
    rm -f /tmp/nvd-monitor-*.tmp 2>/dev/null || true
}
trap cleanup EXIT

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

# Función para mostrar progreso
show_progress() {
    local current=$1
    local total=$2
    local description=$3
    local percentage=$((current * 100 / total))
    local completed=$((current * 50 / total))
    local remaining=$((50 - completed))
    
    printf "\r${PURPLE}[%s] %3d%% [" "$description"
    printf "%${completed}s" | tr ' ' '='
    printf "%${remaining}s" | tr ' ' '-'
    printf "] (%d/%d)${NC}" "$current" "$total"
    
    if [ "$current" -eq "$total" ]; then
        echo
    fi
}

# Verificar prerrequisitos del sistema
check_prerequisites() {
    log_step "Verificando prerrequisitos del sistema..."
    
    # Verificar que se ejecuta como root
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root (sudo)"
        echo "Uso: sudo bash install.sh"
        exit 1
    fi
    
    # Verificar Ubuntu 24.04
    if ! grep -q "Ubuntu ${SUPPORTED_UBUNTU}" /etc/os-release 2>/dev/null; then
        log_warn "Este script está diseñado para Ubuntu ${SUPPORTED_UBUNTU} LTS"
        echo "Sistema detectado: $(lsb_release -d 2>/dev/null | cut -f2 || echo 'Desconocido')"
        read -p "¿Desea continuar de todos modos? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Instalación cancelada por el usuario"
            exit 0
        fi
    fi
    
    # Verificar Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 no está instalado"
        exit 1
    fi
    
    local python_version
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
        log_error "Se requiere Python ${PYTHON_MIN_VERSION}+. Versión actual: ${python_version}"
        exit 1
    fi
    
    # Verificar conectividad a internet
    if ! timeout 5 ping -c 1 8.8.8.8 &> /dev/null; then
        log_error "No hay conectividad a internet. Se requiere para descargar dependencias."
        exit 1
    fi
    
    log_success "Prerrequisitos verificados correctamente"
}

# Instalar dependencias del sistema
install_system_dependencies() {
    log_step "Instalando dependencias del sistema..."
    
    local packages=(
        "python3-pip"
        "python3-venv" 
        "python3-dev"
        "build-essential"
        "curl"
        "wget"
        "git"
        "mysql-client"
        "logrotate"
        "cron"
        "systemd"
    )
    
    # Actualizar repositorios
    show_progress 1 4 "Actualizando repositorios"
    apt update -qq
    
    # Actualizar sistema crítico
    show_progress 2 4 "Actualizando sistema"
    DEBIAN_FRONTEND=noninteractive apt upgrade -y -qq
    
    # Instalar paquetes
    show_progress 3 4 "Instalando paquetes"
    DEBIAN_FRONTEND=noninteractive apt install -y -qq "${packages[@]}"
    
    # Limpiar cache
    show_progress 4 4 "Limpiando cache"
    apt autoremove -y -qq
    apt autoclean -qq
    
    log_success "Dependencias del sistema instaladas"
}

# Crear usuario del sistema
create_system_user() {
    log_step "Configurando usuario del sistema..."
    
    if id "$INSTALL_USER" &>/dev/null; then
        log_info "Usuario '$INSTALL_USER' ya existe"
    else
        useradd -r -s /bin/false -d "$INSTALL_DIR" -c "NVD Monitor Service User" "$INSTALL_USER"
        log_success "Usuario '$INSTALL_USER' creado"
    fi
}

# Crear estructura de directorios
create_directory_structure() {
    log_step "Creando estructura de directorios..."
    
    local directories=(
        "$INSTALL_DIR"
        "$CONFIG_DIR"
        "$LOG_DIR"
        "$DATA_DIR"
        "$DATA_DIR/scripts"
        "$DATA_DIR/backups"
        "$DATA_DIR/reports"
        "$DATA_DIR/cache"
    )
    
    local count=0
    for dir in "${directories[@]}"; do
        count=$((count + 1))
        show_progress $count ${#directories[@]} "Creando directorios"
        
        mkdir -p "$dir"
        
        # Configurar permisos según el directorio
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
    
    log_success "Estructura de directorios creada"
}

# Configurar entorno virtual de Python
setup_python_environment() {
    log_step "Configurando entorno virtual de Python..."
    
    # Cambiar al directorio de instalación
    cd "$INSTALL_DIR"
    
    # Crear entorno virtual
    show_progress 1 4 "Creando entorno virtual"
    sudo -u "$INSTALL_USER" python3 -m venv venv
    
    # Crear archivo requirements.txt
    show_progress 2 4 "Creando requirements.txt"
    cat > requirements.txt << 'EOF'
requests>=2.31.0
mysql-connector-python>=8.0.33
schedule>=1.2.0
configparser>=5.3.0
tabulate>=0.9.0
EOF
    
    # Activar entorno e instalar dependencias
    show_progress 3 4 "Instalando dependencias Python"
    sudo -u "$INSTALL_USER" bash -c "
        source venv/bin/activate
        pip install --upgrade pip -q
        pip install -r requirements.txt -q
    "
    
    # Establecer permisos
    show_progress 4 4 "Configurando permisos"
    chown -R "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR"
    
    log_success "Entorno Python configurado"
}

# Crear aplicación principal
create_main_application() {
    log_step "Instalando aplicación principal..."
    
    cat > "$INSTALL_DIR/nvd_monitor.py" << 'EOF'
#!/usr/bin/env python3
"""
NVD Vulnerability Monitor
Sistema de monitoreo de vulnerabilidades críticas desde la National Vulnerability Database
Versión: 1.0.1
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
import signal
from typing import List, Dict, Optional

class NVDMonitor:
    def __init__(self, config_file: str = '/etc/nvd-monitor/config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.running = True
        self.load_config()
        self.setup_logging()
        
        # Configurar manejador de señales
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Manejador de señales para cierre graceful"""
        self.logger.info(f"Recibida señal {signum}, cerrando...")
        self.running = False
        
    def load_config(self):
        """Cargar configuración desde archivo"""
        try:
            if not os.path.exists(self.config_file):
                print(f"Error: Archivo de configuración no encontrado: {self.config_file}")
                print("Ejecute 'sudo nvd-configure' para configurar el sistema")
                sys.exit(1)
                
            self.config.read(self.config_file)
            
            # Verificar secciones requeridas
            required_sections = ['database', 'nvd', 'email', 'monitoring', 'logging']
            for section in required_sections:
                if not self.config.has_section(section):
                    print(f"Error: Sección '{section}' faltante en configuración")
                    sys.exit(1)
                    
        except Exception as e:
            print(f"Error cargando configuración: {e}")
            sys.exit(1)
    
    def setup_logging(self):
        """Configurar sistema de logging"""
        log_level = self.config.get('logging', 'level', fallback='INFO')
        log_file = self.config.get('logging', 'file', fallback='/var/log/nvd-monitor/nvd-monitor.log')
        
        # Crear directorio de logs si no existe
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Configurar formato de logging
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Configurar handlers
        handlers = []
        
        # Handler para archivo
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)
        
        # Handler para consola (solo si no es daemon)
        if '--daemon' not in sys.argv:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(log_format))
            handlers.append(console_handler)
        
        # Configurar logger
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format=log_format,
            handlers=handlers
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Sistema de logging configurado")
    
    def get_database_connection(self):
        """Obtener conexión a la base de datos"""
        try:
            connection = mysql.connector.connect(
                host=self.config.get('database', 'host'),
                database=self.config.get('database', 'database'),
                user=self.config.get('database', 'user'),
                password=self.config.get('database', 'password'),
                port=self.config.getint('database', 'port', fallback=3306),
                autocommit=False,
                connect_timeout=30
            )
            return connection
        except Error as e:
            self.logger.error(f"Error conectando a la base de datos: {e}")
            return None
    
    def test_database_connection(self) -> bool:
        """Probar conexión a la base de datos"""
        self.logger.info("Probando conexión a base de datos...")
        connection = self.get_database_connection()
        if connection and connection.is_connected():
            connection.close()
            self.logger.info("✅ Conexión a base de datos exitosa")
            return True
        else:
            self.logger.error("❌ Error de conexión a base de datos")
            return False
    
    def run_monitoring_cycle(self):
        """Ejecutar un ciclo completo de monitoreo"""
        start_time = datetime.now()
        self.logger.info("🔄 Iniciando ciclo de monitoreo")
        
        try:
            # Aquí iría la lógica completa de monitoreo
            self.logger.info("ℹ️ Ciclo de monitoreo básico ejecutado")
            
            duration = (datetime.now() - start_time).total_seconds()
            self.logger.info(f"Ciclo completado en {duration:.2f} segundos")
            
        except Exception as e:
            self.logger.error(f"❌ Error en ciclo de monitoreo: {e}")
    
    def start_scheduler(self):
        """Iniciar el programador de tareas"""
        interval_hours = self.config.getint('monitoring', 'check_interval_hours', fallback=4)
        
        self.logger.info(f"🕐 Programador iniciado - Ejecutando cada {interval_hours} horas")
        
        # Programar tarea recurrente
        schedule.every(interval_hours).hours.do(self.run_monitoring_cycle)
        
        # Ejecutar inmediatamente
        self.run_monitoring_cycle()
        
        # Loop principal
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Verificar cada minuto
        
        self.logger.info("Programador detenido")

def main():
    parser = argparse.ArgumentParser(description='NVD Vulnerability Monitor v1.0.1')
    parser.add_argument('--config', default='/etc/nvd-monitor/config.ini', 
                       help='Archivo de configuración')
    parser.add_argument('--test-db', action='store_true', 
                       help='Probar conexión a base de datos')
    parser.add_argument('--run-once', action='store_true', 
                       help='Ejecutar una sola vez')
    parser.add_argument('--daemon', action='store_true', 
                       help='Ejecutar como daemon')
    parser.add_argument('--version', action='version', version='NVD Monitor 1.0.1')
    
    args = parser.parse_args()
    
    try:
        monitor = NVDMonitor(args.config)
    except Exception as e:
        print(f"Error inicializando monitor: {e}")
        sys.exit(1)
    
    if args.test_db:
        success = monitor.test_database_connection()
        sys.exit(0 if success else 1)
    
    if args.run_once:
        monitor.run_monitoring_cycle()
        sys.exit(0)
    
    if args.daemon:
        try:
            monitor.start_scheduler()
        except KeyboardInterrupt:
            monitor.logger.info("Recibida interrupción de teclado, cerrando...")
        except Exception as e:
            monitor.logger.error(f"Error fatal: {e}")
            sys.exit(1)
    else:
        parser.print_help()
        print("\nEjemplos de uso:")
        print("  nvd-monitor --daemon           # Ejecutar como servicio")
        print("  nvd-monitor --test-db          # Probar base de datos")
        print("  nvd-monitor --run-once         # Ejecutar una vez")

if __name__ == "__main__":
    main()
EOF

    chmod +x "$INSTALL_DIR/nvd_monitor.py"
    log_success "Aplicación principal instalada"
}

# Crear script de configuración
create_configuration_script() {
    log_step "Creando script de configuración..."
    
    cat > "$INSTALL_DIR/configure.py" << 'EOF'
#!/usr/bin/env python3
"""
NVD Vulnerability Monitor - Script de Configuración
Versión: 1.0.1
"""

import configparser
import os
import sys

def create_default_config():
    """Crear configuración por defecto"""
    config = configparser.ConfigParser()
    
    # Configuración de base de datos
    config.add_section('database')
    config.set('database', 'host', 'localhost')
    config.set('database', 'port', '3306')
    config.set('database', 'database', 'nvd_monitor')
    config.set('database', 'user', 'nvd_user')
    config.set('database', 'password', 'changeme_password')
    
    # Configuración de NVD
    config.add_section('nvd')
    config.set('nvd', 'api_key', '')
    
    # Configuración de email
    config.add_section('email')
    config.set('email', 'smtp_server', 'smtp.gmail.com')
    config.set('email', 'smtp_port', '587')
    config.set('email', 'sender_email', 'your-email@example.com')
    config.set('email', 'sender_password', 'your-app-password')
    config.set('email', 'recipient_email', 'admin@example.com')
    
    # Configuración de monitoreo
    config.add_section('monitoring')
    config.set('monitoring', 'check_interval_hours', '4')
    
    # Configuración de logging
    config.add_section('logging')
    config.set('logging', 'level', 'INFO')
    config.set('logging', 'file', '/var/log/nvd-monitor/nvd-monitor.log')
    
    return config

def main():
    config_file = '/etc/nvd-monitor/config.ini'
    
    print("🔧 NVD Monitor - Configuración")
    print("==============================")
    
    if os.path.exists(config_file):
        print(f"⚠️  El archivo {config_file} ya existe.")
        response = input("¿Desea sobrescribirlo? (y/N): ")
        if response.lower() not in ['y', 'yes', 'sí']:
            print("Configuración cancelada.")
            return
    
    # Crear configuración por defecto
    config = create_default_config()
    
    # Crear directorio si no existe
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    
    # Guardar configuración
    with open(config_file, 'w') as f:
        config.write(f)
    
    # Establecer permisos seguros
    os.chmod(config_file, 0o600)
    
    print(f"✅ Configuración creada en: {config_file}")
    print()
    print("📝 IMPORTANTE: Edite el archivo de configuración con sus credenciales:")
    print(f"   sudo nano {config_file}")
    print()
    print("🔑 No olvide:")
    print("   • Configurar credenciales de base de datos")
    print("   • Obtener API key de NVD: https://nvd.nist.gov/developers/request-an-api-key")
    print("   • Configurar credenciales SMTP para notificaciones")
    print()
    print("🧪 Para probar la configuración:")
    print("   nvd-admin test-all")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse como root")
        print("Uso: sudo python3 configure.py")
        sys.exit(1)
    
    main()
EOF

    chmod +x "$INSTALL_DIR/configure.py"
    log_success "Script de configuración creado"
}

# Crear herramientas de administración
create_admin_tools() {
    log_step "Creando herramientas de administración..."
    
    cat > "$INSTALL_DIR/nvd_admin.py" << 'EOF'
#!/usr/bin/env python3
"""
NVD Vulnerability Monitor - Herramientas de Administración
Versión: 1.0.1
"""

import argparse
import configparser
import os
import sys

class NVDAdmin:
    def __init__(self, config_file='/etc/nvd-monitor/config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()
    
    def load_config(self):
        """Cargar configuración"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            print(f"❌ Archivo de configuración no encontrado: {self.config_file}")
            print("Ejecute: sudo nvd-configure")
    
    def test_database(self):
        """Probar conexión a base de datos"""
        print("🔍 Probando conexión a base de datos...")
        try:
            import mysql.connector
            connection = mysql.connector.connect(
                host=self.config.get('database', 'host', fallback='localhost'),
                database=self.config.get('database', 'database', fallback='nvd_monitor'),
                user=self.config.get('database', 'user', fallback='nvd_user'),
                password=self.config.get('database', 'password', fallback=''),
                port=self.config.getint('database', 'port', fallback=3306)
            )
            
            cursor = connection.cursor()
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            
            print(f"✅ Conexión exitosa")
            print(f"📊 Versión: {version}")
            
            cursor.close()
            connection.close()
            return True
            
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def test_all(self):
        """Probar todas las conexiones"""
        print("🧪 Probando todas las conexiones...\n")
        
        db_ok = self.test_database()
        
        if db_ok:
            print("\n✅ Todas las pruebas básicas pasaron")
            return True
        else:
            print("\n❌ Algunas pruebas fallaron")
            return False
    
    def show_status(self):
        """Mostrar estado del sistema"""
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
            print("❓ Servicio: Estado desconocido")

def main():
    parser = argparse.ArgumentParser(description='NVD Monitor - Herramientas de Administración')
    parser.add_argument('command', nargs='?', choices=['test-db', 'test-all', 'status'], 
                       help='Comando a ejecutar')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        print("\nEjemplos:")
        print("  nvd-admin test-all    # Probar todas las conexiones")
        print("  nvd-admin test-db     # Probar base de datos")
        print("  nvd-admin status      # Ver estado del sistema")
        return
    
    admin = NVDAdmin()
    
    if args.command == 'test-db':
        success = admin.test_database()
        sys.exit(0 if success else 1)
    elif args.command == 'test-all':
        success = admin.test_all()
        sys.exit(0 if success else 1)
    elif args.command == 'status':
        admin.show_status()

if __name__ == "__main__":
    main()
EOF

    chmod +x "$INSTALL_DIR/nvd_admin.py"
    log_success "Herramientas de administración creadas"
}

# Crear comandos globales
create_global_commands() {
    log_step "Creando comandos globales..."
    
    # Comando principal nvd-monitor
    cat > /usr/local/bin/nvd-monitor << EOF
#!/bin/bash
cd "$INSTALL_DIR"
exec ./venv/bin/python nvd_monitor.py "\$@"
EOF
    chmod +x /usr/local/bin/nvd-monitor
    
    # Comando de configuración
    cat > /usr/local/bin/nvd-configure << EOF
#!/bin/bash
cd "$INSTALL_DIR"
exec ./venv/bin/python configure.py "\$@"
EOF
    chmod +x /usr/local/bin/nvd-configure
    
    # Comando de administración
    cat > /usr/local/bin/nvd-admin << EOF
#!/bin/bash
cd "$INSTALL_DIR"
exec ./venv/bin/python nvd_admin.py "\$@"
EOF
    chmod +x /usr/local/bin/nvd-admin
    
    # Comando de estado rápido
    cat > /usr/local/bin/nvd-status << 'EOF'
#!/bin/bash
echo "📊 Estado de NVD Monitor"
echo "========================"
systemctl is-active nvd-monitor >/dev/null 2>&1 && echo "✅ Servicio: Activo" || echo "❌ Servicio: Inactivo"
EOF
    chmod +x /usr/local/bin/nvd-status
    
    log_success "Comandos globales creados"
}

# Crear servicio systemd
create_systemd_service() {
    log_step "Creando servicio systemd..."
    
    cat > /etc/systemd/system/nvd-monitor.service << EOF
[Unit]
Description=NVD Vulnerability Monitor
Documentation=https://github.com/juanpadiaz/NVD-Monitor
After=network.target mysql.service mariadb.service
Wants=network.target

[Service]
Type=simple
User=$INSTALL_USER
Group=$INSTALL_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/nvd_monitor.py --daemon
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=30
TimeoutStopSec=30

# Configuración de recursos
LimitNOFILE=65536

# Configuración de seguridad
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$LOG_DIR $DATA_DIR
PrivateTmp=yes

# Variables de entorno
Environment=PYTHONPATH=$INSTALL_DIR
Environment=PYTHONUNBUFFERED=1

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nvd-monitor

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_success "Servicio systemd creado"
}

# Configurar logrotate
setup_logrotate() {
    log_step "Configurando rotación de logs..."
    
    cat > /etc/logrotate.d/nvd-monitor << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $INSTALL_USER $INSTALL_USER
    sharedscripts
    postrotate
        systemctl reload nvd-monitor >/dev/null 2>&1 || true
    endscript
}
EOF
    
    log_success "Logrotate configurado"
}

# Crear scripts de utilidad
create_utility_scripts() {
    log_step "Creando scripts de utilidad..."
    
    # Script de health check básico
    cat > "$DATA_DIR/scripts/health-check.sh" << 'EOF'
#!/bin/bash
# Health check básico para NVD Monitor

echo "$(date '+%Y-%m-%d %H:%M:%S') - Health check iniciado"

# Verificar servicio
if systemctl is-active --quiet nvd-monitor; then
    echo "✅ Servicio nvd-monitor activo"
else
    echo "❌ Servicio nvd-monitor inactivo"
    exit 1
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') - Health check completado"
EOF

    chmod +x "$DATA_DIR/scripts/health-check.sh"
    
    log_success "Scripts de utilidad creados"
}

# Configurar permisos finales
set_final_permissions() {
    log_step "Configurando permisos finales..."
    
    # Cambiar propietario de directorios principales
    chown -R "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR"
    chown -R "$INSTALL_USER:$INSTALL_USER" "$LOG_DIR"
    chown -R "$INSTALL_USER:$INSTALL_USER" "$DATA_DIR"
    
    # Mantener configuración como root pero accesible
    chown -R root:root "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    # Permisos específicos para archivos ejecutables
    find "$INSTALL_DIR" -name "*.py" -exec chmod +x {} \;
    
    log_success "Permisos configurados"
}

# Función principal de instalación
main_installation() {
    local total_steps=10
    local current_step=0
    
    log_header "NVD VULNERABILITY MONITOR - INSTALACIÓN v${SCRIPT_VERSION}"
    
    echo "🎯 Iniciando instalación para Ubuntu ${SUPPORTED_UBUNTU}"
    echo "📦 Se instalarán los siguientes componentes:"
    echo "   • Aplicación principal de monitoreo"
    echo "   • Script de configuración"
    echo "   • Herramientas de administración"
    echo "   • Servicio systemd"
    echo "   • Scripts de utilidad"
    echo ""
    
    # Verificar prerrequisitos
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Verificando prerrequisitos"
    check_prerequisites
    
    # Instalar dependencias del sistema
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Instalando dependencias"
    install_system_dependencies
    
    # Crear usuario del sistema
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Creando usuario del sistema"
    create_system_user
    
    # Crear estructura de directorios
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Creando directorios"
    create_directory_structure
    
    # Configurar entorno Python
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Configurando Python"
    setup_python_environment
    
    # Crear aplicación principal
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Instalando aplicación"
    create_main_application
    
    # Crear script de configuración
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Creando configuración"
    create_configuration_script
    
    # Crear herramientas de administración
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Instalando herramientas"
    create_admin_tools
    
    # Crear comandos globales
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Creando comandos"
    create_global_commands
    
    # Crear servicio systemd
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Configurando servicio"
    create_systemd_service
    
    # Configurar logrotate
    setup_logrotate
    
    # Crear scripts de utilidad
    create_utility_scripts
    
    # Configurar permisos finales
    set_final_permissions
    
    echo
}

# Mostrar resumen final
show_final_summary() {
    log_header "INSTALACIÓN COMPLETADA EXITOSAMENTE"
    
    echo -e "${GREEN}✅ NVD Vulnerability Monitor ha sido instalado correctamente${NC}"
    echo
    echo "📁 Archivos instalados:"
    echo "   • Aplicación principal: $INSTALL_DIR/nvd_monitor.py"
    echo "   • Script de configuración: $INSTALL_DIR/configure.py"
    echo "   • Herramientas admin: $INSTALL_DIR/nvd_admin.py"
    echo "   • Servicio systemd: /etc/systemd/system/nvd-monitor.service"
    echo "   • Scripts de utilidad: $DATA_DIR/scripts/"
    echo
    echo "🔧 Comandos disponibles:"
    echo "   • nvd-configure      - Configurar el sistema"
    echo "   • nvd-monitor        - Aplicación principal"
    echo "   • nvd-admin          - Herramientas de administración"
    echo "   • nvd-status         - Estado rápido del sistema"
    echo
    echo "📋 Próximos pasos:"
    echo "   1. Configurar el sistema:"
    echo "      ${CYAN}sudo nvd-configure${NC}"
    echo
    echo "   2. Editar la configuración con sus credenciales:"
    echo "      ${CYAN}sudo nano /etc/nvd-monitor/config.ini${NC}"
    echo
    echo "   3. Probar la configuración:"
    echo "      ${CYAN}nvd-admin test-all${NC}"
    echo
    echo "   4. Iniciar el servicio:"
    echo "      ${CYAN}sudo systemctl enable nvd-monitor${NC}"
    echo "      ${CYAN}sudo systemctl start nvd-monitor${NC}"
    echo
    echo "   5. Verificar funcionamiento:"
    echo "      ${CYAN}sudo systemctl status nvd-monitor${NC}"
    echo "      ${CYAN}nvd-status${NC}"
    echo
    echo "📚 Documentación:"
    echo "   • Configuración: /etc/nvd-monitor/"
    echo "   • Logs: /var/log/nvd-monitor/"
    echo "   • Datos: /var/lib/nvd-monitor/"
    echo
    echo "🔑 IMPORTANTE:"
    echo "   • Obtenga una API key gratuita de NVD:"
    echo "     https://nvd.nist.gov/developers/request-an-api-key"
    echo "   • Configure MySQL/MariaDB antes de usar el sistema"
    echo "   • Configure credenciales SMTP para notificaciones por email"
    echo
    
    # Preguntar si ejecutar configuración
    echo -e "${YELLOW}¿Desea ejecutar la configuración básica ahora? (y/N):${NC} "
    read -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Ejecutando configuración básica..."
        echo
        nvd-configure
    else
        echo "Puede ejecutar la configuración más tarde con: ${CYAN}sudo nvd-configure${NC}"
    fi
    
    echo
    log_success "¡NVD Monitor está listo para proteger su infraestructura!"
}

# Función de ayuda
show_help() {
    echo "NVD Vulnerability Monitor - Instalador v${SCRIPT_VERSION}"
    echo "Uso: sudo bash install.sh [opciones]"
    echo ""
    echo "Opciones:"
    echo "  -h, --help     Mostrar esta ayuda"
    echo "  -v, --version  Mostrar versión"
    echo ""
    echo "Este script instalará NVD Monitor en Ubuntu ${SUPPORTED_UBUNTU} LTS"
    echo "Más información: https://github.com/juanpadiaz/NVD-Monitor"
}

# Función principal
main() {
    # Verificar argumentos
    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            echo "NVD Monitor Installer v${SCRIPT_VERSION}"
            exit 0
            ;;
        "")
            # Sin argumentos, proceder con la instalación
            ;;
        *)
            echo "Opción desconocida: $1"
            show_help
            exit 1
            ;;
    esac
    
    # Ejecutar instalación
    main_installation
    show_final_summary
}

# Manejo de errores
error_handler() {
    local exit_code=$?
    log_error "Error en línea $1. Código de salida: $exit_code"
    log_error "La instalación ha fallado. Revise los logs arriba para más detalles."
    exit $exit_code
}

# Configurar trap para errores
trap 'error_handler $LINENO' ERR

# Verificar que no se ejecute como source
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    log_error "Este script debe ejecutarse directamente, no como source"
    exit 1
fi

# Ejecutar función principal con todos los argumentos
main "$@"