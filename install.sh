#!/bin/bash

# =============================================================================
# NVD Monitor - Script de Configuración de Base de Datos
# Versión: 1.0.0
# =============================================================================

set -euo pipefail

# Colores
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Constantes
readonly SCRIPT_NAME="setup_database.sh"
readonly DB_NAME="nvd_monitor"
readonly DB_USER="nvd_user"
readonly CONFIG_FILE="/etc/nvd-monitor/config.ini"

# Funciones de logging
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Generar contraseña segura
generate_password() {
    local length=${1:-16}
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-${length}
}

# Verificar si MySQL/MariaDB está instalado y ejecutándose
check_mysql_service() {
    log_info "Verificando servidor de base de datos..."
    
    local db_type=""
    local db_service=""
    
    # Detectar tipo de base de datos instalada
    if systemctl list-unit-files | grep -q "mariadb.service"; then
        db_type="MariaDB"
        db_service="mariadb"
    elif systemctl list-unit-files | grep -q "mysql.service"; then
        db_type="MySQL" 
        db_service="mysql"
    elif command -v mysql &> /dev/null; then
        # Intentar detectar por comando
        if mysql --version | grep -qi "mariadb"; then
            db_type="MariaDB"
            db_service="mariadb"
        else
            db_type="MySQL"
            db_service="mysql"
        fi
    fi
    
    if [ -n "$db_type" ]; then
        log_success "$db_type detectado"
        
        # Verificar si está ejecutándose
        if systemctl is-active --quiet "$db_service"; then
            log_success "$db_type está ejecutándose"
        else
            log_info "Iniciando $db_type..."
            systemctl start "$db_service"
            if systemctl is-active --quiet "$db_service"; then
                log_success "$db_type iniciado correctamente"
            else
                log_error "No se pudo iniciar $db_type"
                exit 1
            fi
        fi
    else
        # No hay base de datos, ofrecer instalación
        log_warn "No se encontró servidor de base de datos instalado"
        echo
        echo "🔧 Opciones disponibles:"
        echo "   1. Instalar MariaDB (recomendado para Ubuntu 24.04+)"
        echo "   2. Instalar MySQL" 
        echo "   3. Cancelar (instalar manualmente)"
        echo
        
        while true; do
            read -p "Seleccione una opción [1]: " choice
            choice=${choice:-1}
            
            case $choice in
                1)
                    log_info "Instalando MariaDB Server..."
                    export DEBIAN_FRONTEND=noninteractive
                    apt update -qq
                    apt install -y mariadb-server
                    systemctl enable mariadb
                    systemctl start mariadb
                    db_type="MariaDB"
                    db_service="mariadb"
                    log_success "MariaDB instalado y configurado"
                    break
                    ;;
                2)
                    log_info "Instalando MySQL Server..."
                    export DEBIAN_FRONTEND=noninteractive
                    apt update -qq
                    apt install -y mysql-server
                    systemctl enable mysql
                    systemctl start mysql
                    db_type="MySQL"
                    db_service="mysql"
                    log_success "MySQL instalado y configurado"
                    break
                    ;;
                3)
                    log_info "Instalación cancelada"
                    log_info "Instale MySQL o MariaDB manualmente y vuelva a ejecutar este script"
                    exit 0
                    ;;
                *)
                    echo "❌ Opción inválida. Seleccione 1, 2 o 3"
                    ;;
            esac
        done
    fi
    
    # Guardar información del tipo de base de datos
    echo "DB_TYPE=$db_type" > /tmp/nvd_db_info
    echo "DB_SERVICE=$db_service" >> /tmp/nvd_db_info
}

# Configurar MySQL de forma segura
secure_mysql_installation() {
    log_info "Configurando MySQL de forma segura..."
    
    # Verificar si ya tiene contraseña root
    if mysql -u root -e "SELECT 1;" &>/dev/null; then
        log_info "MySQL sin contraseña root detectado, configurando seguridad..."
        
        # Generar contraseña root
        local root_password
        root_password=$(generate_password 20)
        
        # Configurar contraseña root y securizar
        mysql -u root <<EOF
-- Establecer contraseña root
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${root_password}';

-- Eliminar usuarios anónimos
DELETE FROM mysql.user WHERE User='';

-- Eliminar base de datos test
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Recargar privilegios
FLUSH PRIVILEGES;
EOF
        
        # Guardar contraseña root en archivo seguro
        echo "[client]" > /root/.my.cnf
        echo "user=root" >> /root/.my.cnf
        echo "password=${root_password}" >> /root/.my.cnf
        chmod 600 /root/.my.cnf
        
        log_success "MySQL configurado de forma segura"
        log_warn "Contraseña root guardada en /root/.my.cnf"
    else
        log_info "MySQL ya tiene configuración de seguridad"
    fi
}

# Crear base de datos y usuario para NVD Monitor
create_database_and_user() {
    log_info "Creando base de datos y usuario para NVD Monitor..."
    
    # Generar contraseña para usuario nvd_user
    local nvd_password
    nvd_password=$(generate_password 16)
    
    # Crear base de datos y usuario
    mysql -u root <<EOF
-- Crear base de datos
CREATE DATABASE IF NOT EXISTS ${DB_NAME} 
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Crear usuario
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' 
IDENTIFIED BY '${nvd_password}';

-- Otorgar permisos
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';

-- Aplicar cambios
FLUSH PRIVILEGES;
EOF
    
    # Verificar creación
    if mysql -u root -e "USE ${DB_NAME}; SELECT 1;" &>/dev/null; then
        log_success "Base de datos '${DB_NAME}' creada correctamente"
    else
        log_error "Error creando la base de datos"
        exit 1
    fi
    
    # Verificar usuario
    if mysql -u "${DB_USER}" -p"${nvd_password}" -e "SELECT 1;" &>/dev/null; then
        log_success "Usuario '${DB_USER}' creado correctamente"
    else
        log_error "Error creando el usuario"
        exit 1
    fi
    
    # Guardar credenciales
    echo "${nvd_password}" > /tmp/nvd_db_password
    chmod 600 /tmp/nvd_db_password
    
    log_info "Contraseña del usuario guardada temporalmente en /tmp/nvd_db_password"
}

# Crear tablas de la aplicación
create_application_tables() {
    log_info "Creando tablas de la aplicación..."
    
    local nvd_password
    nvd_password=$(cat /tmp/nvd_db_password)
    
    # Script SQL para crear tablas
    mysql -u "${DB_USER}" -p"${nvd_password}" "${DB_NAME}" <<'EOF'
-- Tabla de vulnerabilidades
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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_cve_id (cve_id),
    INDEX idx_severity (cvss_severity),
    INDEX idx_published (published_date),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de logs de monitoreo
CREATE TABLE IF NOT EXISTS monitoring_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    vulnerabilities_found INT DEFAULT 0,
    new_vulnerabilities INT DEFAULT 0,
    status VARCHAR(50),
    message TEXT,
    execution_time DECIMAL(10,3),
    
    INDEX idx_timestamp (timestamp),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de configuración del sistema
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_key (config_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insertar configuración inicial
INSERT IGNORE INTO system_config (config_key, config_value, description) VALUES
('last_nvd_check', '1970-01-01 00:00:00', 'Última verificación de NVD API'),
('total_vulnerabilities', '0', 'Total de vulnerabilidades almacenadas'),
('installation_date', NOW(), 'Fecha de instalación del sistema');
EOF
    
    # Verificar tablas creadas
    local table_count
    table_count=$(mysql -u "${DB_USER}" -p"${nvd_password}" "${DB_NAME}" -e "SHOW TABLES;" | wc -l)
    
    if [ "$table_count" -ge 4 ]; then  # 3 tablas + header
        log_success "Tablas creadas correctamente"
        
        # Mostrar información de tablas
        echo
        log_info "Tablas creadas en la base de datos:"
        mysql -u "${DB_USER}" -p"${nvd_password}" "${DB_NAME}" -e "
        SELECT 
            TABLE_NAME as 'Tabla',
            TABLE_ROWS as 'Filas',
            ROUND(((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024), 2) as 'Tamaño (MB)'
        FROM information_schema.TABLES 
        WHERE TABLE_SCHEMA = '${DB_NAME}' 
        ORDER BY TABLE_NAME;
        "
    else
        log_error "Error creando las tablas"
        exit 1
    fi
}

# Actualizar archivo de configuración
update_config_file() {
    log_info "Actualizando archivo de configuración..."
    
    local nvd_password
    nvd_password=$(cat /tmp/nvd_db_password)
    
    # Crear configuración si no existe
    if [ ! -f "$CONFIG_FILE" ]; then
        log_info "Creando archivo de configuración..."
        mkdir -p "$(dirname "$CONFIG_FILE")"
        
        cat > "$CONFIG_FILE" <<EOF
[database]
host = localhost
port = 3306
database = ${DB_NAME}
user = ${DB_USER}
password = ${nvd_password}

[nvd]
api_key = 

[email]
smtp_server = smtp.gmail.com
smtp_port = 587
sender_email = 
sender_password = 
recipient_email = 

[monitoring]
check_interval_hours = 4

[logging]
level = INFO
file = /var/log/nvd-monitor/nvd-monitor.log
EOF
    else
        # Actualizar solo la sección de base de datos
        log_info "Actualizando configuración de base de datos..."
        
        # Usar Python para actualizar el archivo INI
        python3 <<EOF
import configparser
import os

config = configparser.ConfigParser()
config.read('${CONFIG_FILE}')

# Asegurar que existe la sección database
if not config.has_section('database'):
    config.add_section('database')

# Actualizar valores
config.set('database', 'host', 'localhost')
config.set('database', 'port', '3306')
config.set('database', 'database', '${DB_NAME}')
config.set('database', 'user', '${DB_USER}')
config.set('database', 'password', '${nvd_password}')

# Guardar archivo
with open('${CONFIG_FILE}', 'w') as f:
    config.write(f)
EOF
    fi
    
    # Establecer permisos seguros
    chown root:root "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    
    log_success "Archivo de configuración actualizado"
}

# Probar conexión
test_database_connection() {
    log_info "Probando conexión a la base de datos..."
    
    if nvd-admin test-db &>/dev/null; then
        log_success "¡Conexión a la base de datos exitosa!"
        
        # Mostrar estadísticas
        echo
        log_info "Estadísticas de la base de datos:"
        local nvd_password
        nvd_password=$(cat /tmp/nvd_db_password)
        
        mysql -u "${DB_USER}" -p"${nvd_password}" "${DB_NAME}" -e "
        SELECT 'Vulnerabilidades' as Tabla, COUNT(*) as Registros FROM vulnerabilities
        UNION ALL
        SELECT 'Logs de monitoreo' as Tabla, COUNT(*) as Registros FROM monitoring_logs
        UNION ALL
        SELECT 'Configuración' as Tabla, COUNT(*) as Registros FROM system_config;
        "
    else
        log_error "Error en la conexión a la base de datos"
        log_error "Verifique la configuración en $CONFIG_FILE"
        exit 1
    fi
}

# Limpieza final
cleanup() {
    # Eliminar archivo temporal con contraseña
    rm -f /tmp/nvd_db_password
}

# Función principal
main() {
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}  NVD MONITOR - CONFIGURACIÓN DE BASE DE DATOS${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo
    
    # Verificar permisos root
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root"
        echo "Uso: sudo bash $SCRIPT_NAME"
        exit 1
    fi
    
    # Verificar que NVD Monitor esté instalado
    if [ ! -f "/usr/local/bin/nvd-admin" ]; then
        log_error "NVD Monitor no está instalado"
        log_error "Ejecute primero: sudo bash install.sh"
        exit 1
    fi
    
    echo "🔧 Este script configurará automáticamente:"
    echo "   • Instalación y configuración segura de MySQL"
    echo "   • Creación de base de datos 'nvd_monitor'"
    echo "   • Creación de usuario 'nvd_user' con contraseña segura"
    echo "   • Creación de todas las tablas necesarias"
    echo "   • Actualización del archivo de configuración"
    echo
    
    read -p "¿Desea continuar? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Configuración cancelada"
        exit 0
    fi
    
    # Ejecutar configuración
    check_mysql_service
    secure_mysql_installation
    create_database_and_user
    create_application_tables
    update_config_file
    test_database_connection
    
    echo
    log_success "🎉 Configuración de base de datos completada exitosamente"
    echo
    echo "📋 Información de la base de datos:"
    echo "   • Base de datos: $DB_NAME"
    echo "   • Usuario: $DB_USER"
    echo "   • Host: localhost"
    echo "   • Puerto: 3306"
    echo
    echo "🔧 Próximos pasos:"
    echo "   1. Configurar API key de NVD en: $CONFIG_FILE"
    echo "   2. Configurar credenciales SMTP para notificaciones"
    echo "   3. Probar configuración: nvd-admin test-all"
    echo "   4. Iniciar servicio: sudo systemctl start nvd-monitor"
    echo
}

# Configurar trap para limpieza
trap cleanup EXIT

# Ejecutar función principal
main "$@"