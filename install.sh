#!/bin/bash

# Script de instalación para NVD Monitor
# Compatible con Ubuntu 22.04

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Función para logging
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar si es root
if [[ $EUID -ne 0 ]]; then
   error "Este script debe ejecutarse como root"
   exit 1
fi

# Verificar Ubuntu 22.04
if ! grep -q "22.04" /etc/os-release; then
    warn "Este script está diseñado para Ubuntu 22.04"
    read -p "¿Continuar de todos modos? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

log "Iniciando instalación de NVD Monitor..."

# Actualizar sistema
log "Actualizando sistema..."
apt update && apt upgrade -y

# Instalar dependencias del sistema
log "Instalando dependencias del sistema..."
apt install -y python3 python3-pip python3-venv mysql-server git curl wget

# Crear usuario del sistema
log "Creando usuario nvd_monitor..."
if ! id "nvd_monitor" &>/dev/null; then
    useradd -r -s /bin/false -d /opt/nvd_monitor nvd_monitor
fi

# Crear directorios
log "Creando estructura de directorios..."
mkdir -p /opt/nvd_monitor/{bin,conf,logs,venv}
mkdir -p /etc/nvd_monitor
mkdir -p /var/log/nvd_monitor

# Crear entorno virtual
log "Creando entorno virtual Python..."
python3 -m venv /opt/nvd_monitor/venv
source /opt/nvd_monitor/venv/bin/activate

# Instalar paquetes Python
log "Instalando paquetes Python..."
pip install --upgrade pip
pip install \
    requests \
    mysql-connector-python \
    schedule \
    configparser \
    python-daemon

# Copiar archivos de la aplicación
log "Copiando archivos de la aplicación..."

# Crear el archivo principal de la aplicación
cat > /opt/nvd_monitor/bin/nvd_monitor.py << 'EOF'
# Aquí iría el código de la aplicación principal
# (En un caso real, copiarías el archivo nvd_monitor.py)
EOF

# Hacer ejecutable
chmod +x /opt/nvd_monitor/bin/nvd_monitor.py

# Crear archivo de configuración
log "Creando archivo de configuración..."
cat > /etc/nvd_monitor/config.ini << 'EOF'
[database]
host = localhost
port = 3306
database = nvd_monitor
user = nvd_user
password = CHANGE_THIS_PASSWORD

[nvd]
# API Key opcional para mayor rate limit
api_key = 

[email]
smtp_server = smtp.gmail.com
smtp_port = 587
username = your_email@gmail.com
password = your_app_password
from_email = your_email@gmail.com
to_emails = admin@company.com,security@company.com

[monitor]
check_interval = 6

[logging]
level = INFO
file = /var/log/nvd_monitor/nvd_monitor.log
EOF

# Configurar MySQL
log "Configurando MySQL..."
mysql -e "CREATE DATABASE IF NOT EXISTS nvd_monitor;"
mysql -e "CREATE USER IF NOT EXISTS 'nvd_user'@'localhost' IDENTIFIED BY 'CHANGE_THIS_PASSWORD';"
mysql -e "GRANT ALL PRIVILEGES ON nvd_monitor.* TO 'nvd_user'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

# Crear servicio systemd
log "Creando servicio systemd..."
cat > /etc/systemd/system/nvd-monitor.service << 'EOF'
[Unit]
Description=NVD Vulnerability Monitor
After=network.target mysql.service
Requires=mysql.service

[Service]
Type=simple
User=nvd_monitor
Group=nvd_monitor
WorkingDirectory=/opt/nvd_monitor
Environment=PATH=/opt/nvd_monitor/venv/bin
ExecStart=/opt/nvd_monitor/venv/bin/python /opt/nvd_monitor/bin/nvd_monitor.py --config /etc/nvd_monitor/config.ini
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Crear script de utilidad
log "Creando scripts de utilidad..."
cat > /usr/local/bin/nvd-monitor << 'EOF'
#!/bin/bash
# Script de utilidad para NVD Monitor

case "$1" in
    start)
        systemctl start nvd-monitor
        ;;
    stop)
        systemctl stop nvd-monitor
        ;;
    restart)
        systemctl restart nvd-monitor
        ;;
    status)
        systemctl status nvd-monitor
        ;;
    logs)
        journalctl -u nvd-monitor -f
        ;;
    check)
        sudo -u nvd_monitor /opt/nvd_monitor/venv/bin/python /opt/nvd_monitor/bin/nvd_monitor.py --config /etc/nvd_monitor/config.ini --once
        ;;
    config)
        nano /etc/nvd_monitor/config.ini
        ;;
    *)
        echo "Uso: $0 {start|stop|restart|status|logs|check|config}"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/nvd-monitor

# Configurar logrotate
log "Configurando logrotate..."
cat > /etc/logrotate.d/nvd-monitor << 'EOF'
/var/log/nvd_monitor/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 nvd_monitor nvd_monitor
    postrotate
        systemctl reload nvd-monitor
    endscript
}
EOF

# Configurar permisos
log "Configurando permisos..."
chown -R nvd_monitor:nvd_monitor /opt/nvd_monitor
chown -R nvd_monitor:nvd_monitor /var/log/nvd_monitor
chmod 600 /etc/nvd_monitor/config.ini

# Habilitar servicio
log "Habilitando servicio..."
systemctl daemon-reload
systemctl enable nvd-monitor

# Crear script de configuración inicial
log "Creando script de configuración inicial..."
cat > /opt/nvd_monitor/setup_config.sh << 'EOF'
#!/bin/bash
# Script de configuración inicial

echo "=== Configuración inicial de NVD Monitor ==="
echo

# Configurar base de datos
echo "Configuración de base de datos:"
read -p "Host de MySQL [localhost]: " DB_HOST
DB_HOST=${DB_HOST:-localhost}

read -p "Puerto de MySQL [3306]: " DB_PORT
DB_PORT=${DB_PORT:-3306}

read -p "Usuario de MySQL [nvd_user]: " DB_USER
DB_USER=${DB_USER:-nvd_user}

read -s -p "Contraseña de MySQL: " DB_PASS
echo

# Configurar email
echo -e "\nConfiguración de email:"
read -p "Servidor SMTP [smtp.gmail.com]: " SMTP_SERVER
SMTP_SERVER=${SMTP_SERVER:-smtp.gmail.com}

read -p "Puerto SMTP [587]: " SMTP_PORT
SMTP_PORT=${SMTP_PORT:-587}

read -p "Usuario SMTP: " SMTP_USER
read -s -p "Contraseña SMTP: " SMTP_PASS
echo

read -p "Email origen: " FROM_EMAIL
read -p "Emails destino (separados por coma): " TO_EMAILS

# Configurar monitoreo
echo -e "\nConfiguración de monitoreo:"
read -p "Intervalo de verificación en horas [6]: " CHECK_INTERVAL
CHECK_INTERVAL=${CHECK_INTERVAL:-6}

read -p "API Key de NVD (opcional): " NVD_API_KEY

# Actualizar configuración
CONFIG_FILE="/etc/nvd_monitor/config.ini"
cp "$CONFIG_FILE" "$CONFIG_FILE.backup"

# Actualizar base de datos
sed -i "s/host = localhost/host = $DB_HOST/" "$CONFIG_FILE"
sed -i "s/port = 3306/port = $DB_PORT/" "$CONFIG_FILE"
sed -i "s/user = nvd_user/user = $DB_USER/" "$CONFIG_FILE"
sed -i "s/password = CHANGE_THIS_PASSWORD/password = $DB_PASS/" "$CONFIG_FILE"

# Actualizar email
sed -i "s/smtp_server = smtp.gmail.com/smtp_server = $SMTP_SERVER/" "$CONFIG_FILE"
sed -i "s/smtp_port = 587/smtp_port = $SMTP_PORT/" "$CONFIG_FILE"
sed -i "s/username = your_email@gmail.com/username = $SMTP_USER/" "$CONFIG_FILE"
sed -i "s/password = your_app_password/password = $SMTP_PASS/" "$CONFIG_FILE"
sed -i "s/from_email = your_email@gmail.com/from_email = $FROM_EMAIL/" "$CONFIG_FILE"
sed -i "s/to_emails = admin@company.com,security@company.com/to_emails = $TO_EMAILS/" "$CONFIG_FILE"

# Actualizar monitoreo
sed -i "s/check_interval = 6/check_interval = $CHECK_INTERVAL/" "$CONFIG_FILE"
if [ ! -z "$NVD_API_KEY" ]; then
    sed -i "s/api_key = /api_key = $NVD_API_KEY/" "$CONFIG_FILE"
fi

echo -e "\nConfiguración actualizada exitosamente!"
echo "Archivo de configuración: $CONFIG_FILE"
echo "Backup creado en: $CONFIG_FILE.backup"

# Actualizar contraseña de MySQL
mysql -e "ALTER USER 'nvd_user'@'localhost' IDENTIFIED BY '$DB_PASS';"
mysql -e "FLUSH PRIVILEGES;"

echo -e "\nPara iniciar el servicio ejecute:"
echo "  systemctl start nvd-monitor"
echo -e "\nPara verificar el estado:"
echo "  nvd-monitor status"
echo -e "\nPara ejecutar una verificación manual:"
echo "  nvd-monitor check"
EOF

chmod +x /opt/nvd_monitor/setup_config.sh

# Instalar firewall rules si ufw está activo
if systemctl is-active --quiet ufw; then
    log "Configurando firewall..."
    ufw allow 3306/tcp comment "MySQL para NVD Monitor"
fi

# Mostrar resumen de instalación
log "Instalación completada exitosamente!"
echo
echo "=== Resumen de instalación ==="
echo "• Usuario del sistema: nvd_monitor"
echo "• Directorio de instalación: /opt/nvd_monitor"
echo "• Archivo de configuración: /etc/nvd_monitor/config.ini"
echo "• Logs: /var/log/nvd_monitor/"
echo "• Servicio: nvd-monitor"
echo "• Comando de utilidad: nvd-monitor"
echo
echo "=== Próximos pasos ==="
echo "1. Configurar la aplicación:"
echo "   sudo /opt/nvd_monitor/setup_config.sh"
echo
echo "2. Copiar el código de la aplicación:"
echo "   sudo cp nvd_monitor.py /opt/nvd_monitor/bin/"
echo
echo "3. Iniciar el servicio:"
echo "   sudo systemctl start nvd-monitor"
echo
echo "4. Verificar el estado:"
echo "   nvd-monitor status"
echo
echo "5. Ver logs en tiempo real:"
echo "   nvd-monitor logs"
echo

warn "IMPORTANTE: Recuerda cambiar las contraseñas por defecto en el archivo de configuración"
warn "IMPORTANTE: Para Gmail, usa contraseñas de aplicación en lugar de tu contraseña regular"

log "Instalación finalizada. ¡Disfruta de NVD Monitor!"