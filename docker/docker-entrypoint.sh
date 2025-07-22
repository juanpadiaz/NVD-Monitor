#!/bin/bash
set -e

echo "=========================================="
echo "   NVD Monitor Docker Container v1.0.9"
echo "=========================================="

# Función para esperar que MySQL esté listo
wait_for_mysql() {
    echo "Esperando que MySQL esté listo..."
    for i in {1..30}; do
        if mysqladmin ping -h localhost --silent; then
            echo "MySQL está listo!"
            return 0
        fi
        echo -n "."
        sleep 2
    done
    echo "ERROR: MySQL no se inició correctamente"
    return 1
}

# Iniciar MySQL si no está ejecutándose
if ! pgrep -x mysqld > /dev/null; then
    echo "Iniciando MySQL..."
    chown -R mysql:mysql /var/lib/mysql /run/mysqld
    mysqld_safe --skip-grant-tables &
    wait_for_mysql
    
    # Configurar contraseña root si se proporciona
    if [ -n "$DB_ROOT_PASSWORD" ]; then
        echo "Configurando contraseña root de MySQL..."
        mysql -u root <<EOF
FLUSH PRIVILEGES;
ALTER USER 'root'@'localhost' IDENTIFIED BY '$DB_ROOT_PASSWORD';
FLUSH PRIVILEGES;
EOF
    fi
    
    # Detener MySQL para que supervisor lo maneje
    mysqladmin -u root ${DB_ROOT_PASSWORD:+-p$DB_ROOT_PASSWORD} shutdown
fi

# Crear directorios si no existen
mkdir -p /var/log/nvd-monitor /var/lib/nvd-monitor/backups /etc/nvd-monitor

# Generar configuración si no existe
if [ ! -f /etc/nvd-monitor/config.ini ]; then
    echo "Generando configuración inicial..."
    
    # Generar contraseña para usuario de BD si no existe
    DB_USER_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    
    cat > /etc/nvd-monitor/config.ini << EOF
[database]
host = localhost
port = 3306
database = nvd_monitor
user = nvd_user
password = ${DB_USER_PASSWORD}

[nvd]
api_key = ${NVD_API_KEY}
base_url = https://services.nvd.nist.gov/rest/json/cves/2.0

[email]
smtp_server = ${SMTP_SERVER}
smtp_port = ${SMTP_PORT}
sender_email = ${SENDER_EMAIL}
sender_password = ${SENDER_PASSWORD}
recipient_email = ${RECIPIENT_EMAIL}

[monitoring]
check_interval_hours = ${CHECK_INTERVAL:-4}
results_per_page = 200
days_back = 7

[logging]
level = INFO
file = /var/log/nvd-monitor/nvd-monitor.log
max_size_mb = 100
backup_count = 5
EOF
    
    # Configurar permisos
    chmod 640 /etc/nvd-monitor/config.ini
    chown root:nvd-monitor /etc/nvd-monitor/config.ini
fi

# Configurar base de datos si no existe
echo "Verificando base de datos..."
service mysql start
wait_for_mysql

mysql -u root ${DB_ROOT_PASSWORD:+-p$DB_ROOT_PASSWORD} <<EOF || true
-- Crear base de datos si no existe
CREATE DATABASE IF NOT EXISTS nvd_monitor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Crear usuario si no existe
CREATE USER IF NOT EXISTS 'nvd_user'@'localhost' IDENTIFIED BY '$(grep "^password" /etc/nvd-monitor/config.ini | cut -d'=' -f2 | xargs)';

-- Otorgar permisos
GRANT ALL PRIVILEGES ON nvd_monitor.* TO 'nvd_user'@'localhost';
FLUSH PRIVILEGES;

-- Usar la base de datos
USE nvd_monitor;

-- Crear tablas si no existen
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
EOF

# Detener MySQL para que supervisor lo maneje
service mysql stop

echo "Configuración completada!"

# Validar configuración requerida
if [ -z "$SENDER_EMAIL" ] || [ -z "$SENDER_PASSWORD" ] || [ -z "$RECIPIENT_EMAIL" ]; then
    echo "⚠️  ADVERTENCIA: Configuración de email incompleta"
    echo "   Las notificaciones por email no funcionarán sin:"
    echo "   - SENDER_EMAIL"
    echo "   - SENDER_PASSWORD"
    echo "   - RECIPIENT_EMAIL"
fi

if [ -z "$NVD_API_KEY" ]; then
    echo "⚠️  ADVERTENCIA: Sin API Key de NVD"
    echo "   El sistema funcionará con límites reducidos (5 requests/30 segundos)"
    echo "   Obtener API Key en: https://nvd.nist.gov/developers/request-an-api-key"
fi

echo ""
echo "Iniciando servicios con supervisor..."

# Ejecutar el comando pasado al contenedor
exec "$@"
    