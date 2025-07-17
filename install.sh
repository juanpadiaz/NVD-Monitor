    def show_config(self):
        """Mostrar configuración actual (sin contraseñas)"""
        print("\n⚙️  CONFIGURACIÓN ACTUAL")
        print("=" * 50)
        
        try:
            print("📊 Base de datos:")
            print(f"  Host: {self.config.get('database', 'host')}")
            print(f"  Puerto: {self.config.get('database', 'port')}")
            print(f"  Base de datos: {self.config.get('database', 'database')}")
            print(f"  Usuario: {self.config.get('database', 'user')}")
            print("  Contraseña: ****")
            
            print("\n🔑 NVD API:")
            api_key = self.config.get('nvd', 'api_key', fallback='')
            if api_key:
                masked_key = api_key[:8] + "*" * 20 + api_key[-4:] if len(api_key) > 12 else "****"
                print(f"  API Key: {masked_key}")
            else:
                print("  API Key: (no configurada)")
            
            print("\n📧 Email:")
            print(f"  Servidor SMTP: {self.config.get('email', 'smtp_server')}")
            print(f"  Puerto: {self.config.get('email', 'smtp_port')}")
            print(f"  Remitente: {self.config.get('email', 'sender_email')}")
            print("  Contraseña: ****")
            print(f"  Destinatario: {self.config.get('email', 'recipient_email')}")
            
            print("\n⏰ Monitoreo:")
            print(f"  Intervalo: {self.config.get('monitoring', 'check_interval_hours')} horas")
            
            print("\n📝 Logging:")
            print(f"  Nivel: {self.config.get('logging', 'level')}")
            print(f"  Archivo: {self.config.get('logging', 'file')}")
            
        except Exception as e:
            print(f"❌ Error mostrando configuración: {e}")
    
    def show_status(self):
        """Mostrar estado rápido del sistema"""
        print("🛡️  NVD MONITOR - ESTADO DEL SISTEMA")
        print("=" * 50)
        
        # Estado del servicio
        try:
            result = subprocess.run(['systemctl', 'is-active', 'nvd-monitor'], 
                                  capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == 'active':
                print("✅ Servicio: Activo")
            else:
                print("❌ Servicio: Inactivo")
        except:
            print("❓ Servicio: Estado desconocido")
        
        # Última actividad
        try:
            with open('/var/log/nvd-monitor/nvd-monitor.log', 'r') as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1]
                    if 'INFO' in last_line:
                        timestamp = last_line.split(' - ')[0]
                        print(f"🕐 Última actividad: {timestamp}")
                    else:
                        print("⚠️  Última actividad: Sin información")
                else:
                    print("❓ Última actividad: Sin logs")
        except:
            print("❓ Última actividad: No disponible")
        
        # Estadísticas básicas
        connection = self.get_database_connection()
        if connection:
            try:
                cursor = connection.cursor()
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)")
                last_24h = cursor.fetchone()[0]
                print(f"🆕 Últimas 24h: {last_24h} vulnerabilidades")
                cursor.close()
                connection.close()
            except:
                print("❓ Estadísticas: No disponibles")
    
    def backup_database(self):
        """Crear backup de la base de datos"""
        print("💾 Creando backup de la base de datos...")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = "/var/lib/nvd-monitor/backups"
        backup_file = f"{backup_dir}/nvd_monitor_backup_{timestamp}.sql"
        
        try:
            # Crear directorio si no existe
            os.makedirs(backup_dir, exist_ok=True)
            
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
                '--events',
                self.config.get('database', 'database')
            ]
            
            with open(backup_file, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                # Comprimir backup
                subprocess.run(['gzip', backup_file])
                compressed_file = f"{backup_file}.gz"
                
                # Mostrar información del backup
                size = os.path.getsize(compressed_file)
                size_mb = size / (1024 * 1024)
                
                print(f"✅ Backup creado exitosamente")
                print(f"📁 Archivo: {compressed_file}")
                print(f"📊 Tamaño: {size_mb:.2f} MB")
                
                return True
            else:
                print(f"❌ Error creando backup: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error en backup: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='NVD Monitor - Herramientas de Administración v1.0.0')
    parser.add_argument('--config', default='/etc/nvd-monitor/config.ini', 
                       help='Archivo de configuración')
    
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')
    
    # Comandos de test
    subparsers.add_parser('test-db', help='Probar conexión a base de datos')
    subparsers.add_parser('test-nvd', help='Probar conexión NVD API')
    subparsers.add_parser('test-email', help='Probar envío de email')
    subparsers.add_parser('test-all', help='Probar todas las conexiones')
    
    # Comandos de información
    vuln_parser = subparsers.add_parser('show-vulns', help='Mostrar vulnerabilidades')
    vuln_parser.add_argument('--limit', type=int, default=10, help='Número de vulnerabilidades')
    vuln_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH'], help='Filtrar por severidad')
    
    subparsers.add_parser('stats', help='Mostrar estadísticas del sistema')
    subparsers.add_parser('config', help='Mostrar configuración actual')
    subparsers.add_parser('status', help='Mostrar estado rápido del sistema')
    
    # Comandos de acción
    subparsers.add_parser('backup', help='Crear backup de base de datos')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        print("\nEjemplos de uso:")
        print("  nvd-admin test-all              # Probar todas las conexiones")
        print("  nvd-admin show-vulns --limit 20 # Mostrar últimas 20 vulnerabilidades")
        print("  nvd-admin stats                 # Mostrar estadísticas")
        print("  nvd-admin status                # Estado rápido del sistema")
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
    
    elif args.command == 'config':
        admin.show_config()
    
    elif args.command == 'status':
        admin.show_status()
    
    elif args.command == 'backup':
        success = admin.backup_database()
        sys.exit(0 if success else 1)

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
    cat > /usr/local/bin/nvd-monitor << 'EOF'
#!/bin/bash
cd /opt/nvd-monitor
exec ./venv/bin/python nvd_monitor.py "$@"
EOF
    chmod +x /usr/local/bin/nvd-monitor
    
    # Comando de configuración
    cat > /usr/local/bin/nvd-configure << 'EOF'
#!/bin/bash
cd /opt/nvd-monitor
exec ./venv/bin/python configure.py "$@"
EOF
    chmod +x /usr/local/bin/nvd-configure
    
    # Comando de administración
    cat > /usr/local/bin/nvd-admin << 'EOF'
#!/bin/bash
cd /opt/nvd-monitor
exec ./venv/bin/python nvd_admin.py "$@"
EOF
    chmod +x /usr/local/bin/nvd-admin
    
    # Comando de estado rápido
    cat > /usr/local/bin/nvd-status << 'EOF'
#!/bin/bash
nvd-admin status
EOF
    chmod +x /usr/local/bin/nvd-status
    
    log_success "Comandos globales creados"
}

# Crear servicio systemd
create_systemd_service() {
    log_step "Creando servicio systemd..."
    
    cat > /etc/systemd/system/nvd-monitor.service << 'EOF'
[Unit]
Description=NVD Vulnerability Monitor
Documentation=https://github.com/tu-usuario/nvd-monitor
After=network.target mysql.service mariadb.service
Wants=network.target

[Service]
Type=simple
User=nvd-monitor
Group=nvd-monitor
WorkingDirectory=/opt/nvd-monitor
ExecStart=/opt/nvd-monitor/venv/bin/python /opt/nvd-monitor/nvd_monitor.py --daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=30
TimeoutStopSec=30

# Configuración de recursos
LimitNOFILE=65536
MemoryLimit=512M

# Configuración de seguridad
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/nvd-monitor /var/lib/nvd-monitor /tmp
PrivateTmp=yes

# Variables de entorno
Environment=PYTHONPATH=/opt/nvd-monitor
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
    
    cat > /etc/logrotate.d/nvd-monitor << 'EOF'
/var/log/nvd-monitor/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 nvd-monitor nvd-monitor
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
    
    # Script de backup
    cat > "$DATA_DIR/scripts/backup.sh" << 'EOF'
#!/bin/bash

# NVD Monitor - Script de Backup Automatizado

set -e

BACKUP_DIR="/var/lib/nvd-monitor/backups"
CONFIG_FILE="/etc/nvd-monitor/config.ini"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Crear directorio de backups
mkdir -p "$BACKUP_DIR"

# Función para leer configuración
get_config_value() {
    local section=$1
    local key=$2
    python3 -c "
import configparser
config = configparser.ConfigParser()
config.read('$CONFIG_FILE')
try:
    print(config.get('$section', '$key'))
except:
    print('')
"
}

# Leer configuración de base de datos
DB_HOST=$(get_config_value "database" "host")
DB_PORT=$(get_config_value "database" "port")
DB_NAME=$(get_config_value "database" "database")
DB_USER=$(get_config_value "database" "user")
DB_PASS=$(get_config_value "database" "password")

if [ -z "$DB_HOST" ] || [ -z "$DB_NAME" ] || [ -z "$DB_USER" ] || [ -z "$DB_PASS" ]; then
    echo "Error: No se pudo leer la configuración de la base de datos"
    exit 1
fi

# Crear backup
BACKUP_FILE="$BACKUP_DIR/nvd_monitor_backup_$DATE.sql"

echo "$(date '+%Y-%m-%d %H:%M:%S') - Iniciando backup..."

mysqldump \
    --host="$DB_HOST" \
    --port="${DB_PORT:-3306}" \
    --user="$DB_USER" \
    --password="$DB_PASS" \
    --single-transaction \
    --routines \
    --triggers \
    --events \
    --add-drop-table \
    "$DB_NAME" > "$BACKUP_FILE"

# Comprimir backup
gzip "$BACKUP_FILE"
BACKUP_FILE="$BACKUP_FILE.gz"

# Backup de configuración
cp "$CONFIG_FILE" "$BACKUP_DIR/config_backup_$DATE.ini"

# Limpiar backups antiguos
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "config_backup_*.ini" -mtime +$RETENTION_DAYS -delete

# Log del resultado
echo "$(date '+%Y-%m-%d %H:%M:%S') - Backup completado: $BACKUP_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - Backup completado: $BACKUP_FILE" >> /var/log/nvd-monitor/backup.log

# Verificar tamaño del backup
SIZE=$(stat -f%z "$BACKUP_FILE" 2>/dev/null || stat -c%s "$BACKUP_FILE" 2>/dev/null || echo "0")
SIZE_MB=$((SIZE / 1024 / 1024))

echo "Tamaño del backup: ${SIZE_MB} MB"
EOF

    # Script de health check
    cat > "$DATA_DIR/scripts/health-check.sh" << 'EOF'
#!/bin/bash

# NVD Monitor - Health Check Script

CONFIG_FILE="/etc/nvd-monitor/config.ini"
LOG_FILE="/var/log/nvd-monitor/health-check.log"
EMAIL_ALERT=false

# Función para logging
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Función para enviar alerta
send_alert() {
    local message="$1"
    log_message "ALERT: $message"
    
    if [ "$EMAIL_ALERT" = true ]; then
        echo "$message" | mail -s "NVD Monitor - Alerta de Salud" admin@localhost 2>/dev/null || true
    fi
}

# Verificar si el servicio está ejecutándose
check_service() {
    if systemctl is-active --quiet nvd-monitor; then
        log_message "✅ Servicio nvd-monitor activo"
        return 0
    else
        send_alert "❌ Servicio nvd-monitor no está ejecutándose"
        return 1
    fi
}

# Verificar conectividad de base de datos
check_database() {
    if timeout 10 nvd-monitor --test-db &>/dev/null; then
        log_message "✅ Conexión a base de datos OK"
        return 0
    else
        send_alert "❌ Error de conexión a base de datos"
        return 1
    fi
}

# Verificar API de NVD
check_nvd_api() {
    if timeout 15 nvd-monitor --test-nvd &>/dev/null; then
        log_message "✅ Conexión a NVD API OK"
        return 0
    else
        send_alert "❌ Error de conexión a NVD API"
        return 1
    fi
}

# Verificar configuración de email
check_email() {
    if timeout 15 nvd-monitor --test-email &>/dev/null; then
        log_message "✅ Configuración de email OK"
        return 0
    else
        send_alert "❌ Error en configuración de email"
        return 1
    fi
}

# Verificar espacio en disco
check_disk_space() {
    local usage=$(df /var/log/nvd-monitor 2>/dev/null | awk 'NR==2 {print $5}' | sed 's/%//' || echo "0")
    
    if [ "$usage" -lt 80 ]; then
        log_message "✅ Espacio en disco OK (${usage}%)"
        return 0
    elif [ "$usage" -lt 90 ]; then
        send_alert "⚠️  Espacio en disco alto (${usage}%)"
        return 1
    else
        send_alert "❌ Espacio en disco crítico (${usage}%)"
        return 1
    fi
}

# Verificar logs recientes
check_recent_activity() {
    local last_log=$(find /var/log/nvd-monitor -name "*.log" -mmin -240 2>/dev/null | head -1)
    
    if [ -n "$last_log" ]; then
        log_message "✅ Actividad reciente detectada"
        return 0
    else
        send_alert "⚠️  No hay actividad reciente en logs (últimas 4 horas)"
        return 1
    fi
}

# Función principal
main() {
    # Crear directorio de logs si no existe
    mkdir -p /var/log/nvd-monitor
    
    log_message "=== Iniciando health check ==="
    
    local exit_code=0
    
    check_service || exit_code=1
    check_database || exit_code=1
    check_nvd_api || exit_code=1
    check_email || exit_code=1
    check_disk_space || exit_code=1
    check_recent_activity || exit_code=1
    
    if [ $exit_code -eq 0 ]; then
        log_message "✅ Health check completado - Todo OK"
    else
        log_message "❌ Health check completado - Se encontraron problemas"
    fi
    
    log_message "=== Health check finalizado ==="
    exit $exit_code
}

# Verificar argumentos
if [ "$1" = "--email-alerts" ]; then
    EMAIL_ALERT=true
fi

main
EOF

    # Script de mantenimiento
    cat > "$DATA_DIR/scripts/maintenance.sh" << 'EOF'
#!/bin/bash

# NVD Monitor - Script de Mantenimiento

echo "$(date '+%Y-%m-%d %H:%M:%S') - Iniciando mantenimiento..."

# Limpiar archivos temporales
find /tmp -name "*nvd-monitor*" -mtime +1 -delete 2>/dev/null || true

# Limpiar cache antiguo
find /var/lib/nvd-monitor/cache -type f -mtime +7 -delete 2>/dev/null || true

# Optimizar base de datos (ejecutar semanalmente)
if [ "$(date +%u)" = "1" ]; then  # Lunes
    echo "Optimizando base de datos..."
    nvd-admin optimize-db 2>/dev/null || true
fi

# Generar reporte semanal
if [ "$(date +%u)" = "1" ]; then  # Lunes
    REPORT_FILE="/var/lib/nvd-monitor/reports/weekly-$(date +%Y%m%d).txt"
    mkdir -p /var/lib/nvd-monitor/reports
    
    {
        echo "REPORTE SEMANAL NVD MONITOR"
        echo "=========================="
        echo "Fecha: $(date)"
        echo ""
        nvd-admin stats
    } > "$REPORT_FILE"
    
    echo "Reporte semanal generado: $REPORT_FILE"
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') - Mantenimiento completado"
EOF

    # Hacer ejecutables
    chmod +x "$DATA_DIR/scripts/"*.sh
    
    log_success "Scripts de utilidad creados"
}

# Configurar permisos finales
set_final_permissions() {
    log_step "Configurando permisos finales..."
    
    # Cambiar propietario de directorios principales
    chown -R "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR"
    chown -R "$INSTALL_USER:$INSTALL_USER" "$LOG_DIR"
    chown -R "$INSTALL_USER:$INSTALL_USER" "$DATA_DIR"
    
    # Mantener configuración como root
    chown -R root:root "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    # Permisos específicos
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR/venv"
    chmod +x "$INSTALL_DIR"/*.py
    
    log_success "Permisos configurados"
}

# Función principal de instalación
main_installation() {
    local total_steps=12
    local current_step=0
    
    log_header "NVD VULNERABILITY MONITOR - INSTALACIÓN v${SCRIPT_VERSION}"
    
    echo "🎯 Iniciando instalación para Ubuntu ${SUPPORTED_UBUNTU}"
    echo "📦 Se instalarán los siguientes componentes:"
    echo "   • Aplicación principal de monitoreo"
    echo "   • Script de configuración post-instalación"
    echo "   • Herramientas de administración"
    echo "   • Servicio systemd"
    echo "   • Scripts de utilidad y mantenimiento"
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
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Configurando logs"
    setup_logrotate
    
    # Crear scripts de utilidad
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Creando utilidades"
    create_utility_scripts
    
    # Configurar permisos finales
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Configurando permisos"
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
    echo "   2. Probar la configuración:"
    echo "      ${CYAN}nvd-admin test-all${NC}"
    echo
    echo "   3. Iniciar el servicio:"
    echo "      ${CYAN}sudo systemctl enable nvd-monitor${NC}"
    echo "      ${CYAN}sudo systemctl start nvd-monitor${NC}"
    echo
    echo "   4. Verificar funcionamiento:"
    echo "      ${CYAN}sudo systemctl status nvd-monitor${NC}"
    echo "      ${CYAN}nvd-admin show-vulns${NC}"
    echo
    echo "📚 Documentación:"
    echo "   • Configuración: /etc/nvd-monitor/"
    echo "   • Logs: /var/log/nvd-monitor/"
    echo "   • Datos: /var/lib/nvd-monitor/"
    echo
    
    # Preguntar si ejecutar configuración
    echo -e "${YELLOW}¿Desea ejecutar la configuración ahora? (y/N):${NC} "
    read -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Ejecutando configuración..."
        echo
        nvd-configure
    else
        echo "Puede ejecutar la configuración más tarde con: ${CYAN}sudo nvd-configure${NC}"
    fi
    
    echo
    log_success "¡NVD Monitor está listo para proteger su infraestructura!"
}

# Función principal
main() {
    # Verificar argumentos
    case "${1:-}" in
        -h|--help)
            echo "NVD Vulnerability Monitor - Instalador v${SCRIPT_VERSION}"
            echo "Uso: sudo bash install.sh [opciones]"
            echo ""
            echo "Opciones:"
            echo "  -h, --help     Mostrar esta ayuda"
            echo "  -v, --version  Mostrar versión"
            echo ""
            echo "Este script instalará NVD Monitor en Ubuntu 24.04 LTS"
            exit 0
            ;;
        -v|--version)
            echo "NVD Monitor Installer v${SCRIPT_VERSION}"
            exit 0
            ;;
    esac
    
    # Ejecutar instalación
    main_installation
    show_final_summary
}

# Ejecutar función principal
main "$@"            create_vulnerabilities_table = """
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
            """
            
            cursor.execute(create_vulnerabilities_table)
            print("✅ Tabla 'vulnerabilities' creada")
            
            # Tabla de logs de monitoreo
            create_monitoring_logs_table = """
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
            """
            
            cursor.execute(create_monitoring_logs_table)
            print("✅ Tabla 'monitoring_logs' creada")
            
            # Tabla de configuración del sistema
            create_system_config_table = """
            CREATE TABLE IF NOT EXISTS system_config (
                id INT AUTO_INCREMENT PRIMARY KEY,
                config_key VARCHAR(100) UNIQUE NOT NULL,
                config_value TEXT,
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                
                INDEX idx_key (config_key)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
            
            cursor.execute(create_system_config_table)
            print("✅ Tabla 'system_config' creada")
            
            connection.commit()
            print("✅ Todas las tablas creadas correctamente")
            
            cursor.close()
            connection.close()
            return True
            
        except Error as e:
            print(f"❌ Error creando tablas: {e}")
            return False
    
    def get_nvd_api_key(self):
        """Solicitar API key de NVD"""
        print("\n🔑 CONFIGURACIÓN DE NVD API")
        print("-" * 50)
        print("📖 Para obtener una API key de NVD:")
        print("   1. Visita: https://nvd.nist.gov/developers/request-an-api-key")
        print("   2. Completa el formulario de registro")
        print("   3. Recibirás la API key por email (puede tardar unas horas)")
        print()
        print("💡 Beneficios de usar API key:")
        print("   • Sin API key: 5 requests cada 30 segundos")
        print("   • Con API key: 120 requests por minuto")
        print()
        
        while True:
            api_key = input("Ingresa tu API key de NVD (o 'test' para usar sin API key): ").strip()
            
            if not api_key:
                print("❌ La API key no puede estar vacía")
                continue
            
            if api_key.lower() == 'test':
                api_key = ''
                print("⚠️  Usando modo sin API key (limitado a 5 requests/30s)")
                break
            
            # Validar formato básico de API key (UUID)
            if len(api_key) == 36 and api_key.count('-') == 4:
                # Probar API key
                if self.test_nvd_api_key(api_key):
                    break
                else:
                    print("❌ API key inválida o no funciona")
                    retry = input("¿Desea intentar con otra API key? (y/N): ").strip().lower()
                    if retry not in ['y', 'yes', 'sí', 's']:
                        api_key = ''
                        print("⚠️  Usando modo sin API key")
                        break
            else:
                print("❌ Formato de API key inválido (debe ser un UUID)")
        
        return api_key
    
    def test_nvd_api_key(self, api_key):
        """Probar API key de NVD"""
        print("🔍 Probando API key...")
        
        try:
            headers = {
                'apiKey': api_key,
                'User-Agent': 'NVD-Monitor-Setup/1.0'
            }
            
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=headers,
                params={'resultsPerPage': 1},
                timeout=10
            )
            
            if response.status_code == 200:
                print("✅ API key válida")
                return True
            else:
                print(f"❌ Error HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error probando API key: {e}")
            return False
    
    def get_email_config(self):
        """Solicitar configuración de email"""
        print("\n📧 CONFIGURACIÓN DE EMAIL")
        print("-" * 50)
        
        email_config = {}
        
        # Servidor SMTP
        print("🌐 Servidores SMTP comunes:")
        print("   • Gmail: smtp.gmail.com (puerto 587)")
        print("   • Outlook: smtp-mail.outlook.com (puerto 587)")
        print("   • Yahoo: smtp.mail.yahoo.com (puerto 587)")
        print()
        
        email_config['smtp_server'] = input("Servidor SMTP [smtp.gmail.com]: ").strip()
        if not email_config['smtp_server']:
            email_config['smtp_server'] = "smtp.gmail.com"
        
        # Puerto SMTP
        while True:
            port_input = input("Puerto SMTP [587]: ").strip()
            if not port_input:
                email_config['smtp_port'] = 587
                break
            try:
                email_config['smtp_port'] = int(port_input)
                break
            except ValueError:
                print("❌ Por favor ingrese un número válido")
        
        # Email del remitente
        while True:
            sender = input("Email del remitente: ").strip()
            if self.validate_email(sender):
                email_config['sender_email'] = sender
                break
            else:
                print("❌ Formato de email inválido")
        
        # Contraseña del remitente
        print("\n🔐 Para Gmail, use una 'Contraseña de Aplicación':")
        print("   https://myaccount.google.com/apppasswords")
        print()
        
        email_config['sender_password'] = getpass.getpass("Contraseña del remitente: ")
        
        # Email del destinatario
        while True:
            recipient = input("Email del destinatario: ").strip()
            if self.validate_email(recipient):
                email_config['recipient_email'] = recipient
                break
            else:
                print("❌ Formato de email inválido")
        
        return email_config
    
    def test_email_config(self, email_config):
        """Probar configuración de email"""
        print("\n🔍 Probando configuración de email...")
        
        try:
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['sender_email'], email_config['sender_password'])
            server.quit()
            
            print("✅ Configuración de email exitosa")
            
            # Preguntar si enviar email de prueba
            send_test = input("¿Enviar email de prueba? (y/N): ").strip().lower()
            if send_test in ['y', 'yes', 'sí', 's']:
                self.send_test_email(email_config)
            
            return True
            
        except Exception as e:
            print(f"❌ Error en configuración de email: {e}")
            print("\n💡 Posibles soluciones:")
            print("   • Verificar credenciales SMTP")
            print("   • Para Gmail: usar contraseña de aplicación")
            print("   • Verificar configuración de firewall")
            return False
    
    def send_test_email(self, email_config):
        """Enviar email de prueba"""
        try:
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            message = MIMEMultipart()
            message["From"] = email_config['sender_email']
            message["To"] = email_config['recipient_email']
            message["Subject"] = "🛡️ NVD Monitor - Configuración Exitosa"
            
            body = f"""
🛡️ NVD VULNERABILITY MONITOR
============================

¡Configuración completada exitosamente!

📅 Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
📧 Remitente: {email_config['sender_email']}
📨 Destinatario: {email_config['recipient_email']}
🌐 Servidor SMTP: {email_config['smtp_server']}:{email_config['smtp_port']}

El sistema está listo para enviar alertas de vulnerabilidades críticas.

Para probar el sistema:
  nvd-monitor --test-all
  nvd-monitor --run-once

Para ver el estado:
  sudo systemctl status nvd-monitor
  nvd-admin show-vulns

¡Su infraestructura está ahora protegida con monitoreo proactivo!

---
Este email fue generado automáticamente por NVD Monitor
            """
            
            message.attach(MIMEText(body, "plain"))
            
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['sender_email'], email_config['sender_password'])
            server.send_message(message)
            server.quit()
            
            print(f"✅ Email de prueba enviado a {email_config['recipient_email']}")
            
        except Exception as e:
            print(f"❌ Error enviando email de prueba: {e}")
    
    def get_monitoring_config(self):
        """Solicitar configuración de monitoreo"""
        print("\n⏰ CONFIGURACIÓN DE MONITOREO")
        print("-" * 50)
        
        while True:
            interval_input = input("Intervalo de revisión en horas [4]: ").strip()
            if not interval_input:
                interval = 4
                break
            try:
                interval = int(interval_input)
                if 1 <= interval <= 168:  # Máximo una semana
                    break
                else:
                    print("❌ El intervalo debe estar entre 1 y 168 horas")
            except ValueError:
                print("❌ Por favor ingrese un número válido")
        
        print(f"✅ Configurado para revisar cada {interval} horas")
        
        return {'check_interval_hours': interval}
    
    def save_config(self, db_config, nvd_config, email_config, monitoring_config):
        """Guardar configuración en archivo"""
        print("\n💾 Guardando configuración...")
        
        # Configuración de base de datos
        self.config.add_section('database')
        self.config.set('database', 'host', db_config['host'])
        self.config.set('database', 'port', str(db_config['port']))
        self.config.set('database', 'database', db_config['database'])
        self.config.set('database', 'user', db_config['user'])
        self.config.set('database', 'password', db_config['password'])
        
        # Configuración de NVD
        self.config.add_section('nvd')
        self.config.set('nvd', 'api_key', nvd_config.get('api_key', ''))
        
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
        os.chown(self.config_file, 0, 0)  # root:root
        
        print(f"✅ Configuración guardada en {self.config_file}")
    
    def run(self):
        """Ejecutar configuración completa"""
        self.print_banner()
        
        # Configurar base de datos
        while True:
            db_config = self.get_database_info()
            self.create_mysql_user_script(db_config)
            
            if self.test_db_connection(db_config):
                if self.create_database_tables(db_config):
                    break
                else:
                    print("\n❌ Error creando tablas")
            
            print("\n⚠️  Reintenta la configuración de base de datos")
            retry = input("¿Continuar? (y/N): ").strip().lower()
            if retry not in ['y', 'yes', 'sí', 's']:
                print("❌ Configuración cancelada")
                return False
        
        # Configurar NVD API
        nvd_config = {'api_key': self.get_nvd_api_key()}
        
        # Configurar email
        while True:
            email_config = self.get_email_config()
            if self.test_email_config(email_config):
                break
            
            print("\n⚠️  Reintenta la configuración de email")
            retry = input("¿Continuar? (y/N): ").strip().lower()
            if retry not in ['y', 'yes', 'sí', 's']:
                print("❌ Configuración cancelada")
                return False
        
        # Configurar monitoreo
        monitoring_config = self.get_monitoring_config()
        
        # Guardar configuración
        self.save_config(db_config, nvd_config, email_config, monitoring_config)
        
        # Mostrar resumen final
        self.show_final_summary(db_config, nvd_config, email_config, monitoring_config)
        
        return True
    
    def show_final_summary(self, db_config, nvd_config, email_config, monitoring_config):
        """Mostrar resumen final de configuración"""
        print("\n" + "=" * 70)
        print("✅ CONFIGURACIÓN COMPLETADA EXITOSAMENTE")
        print("=" * 70)
        
        print(f"\n📊 Base de datos:")
        print(f"   • Servidor: {db_config['host']}:{db_config['port']}")
        print(f"   • Base de datos: {db_config['database']}")
        print(f"   • Usuario: {db_config['user']}")
        
        print(f"\n🔑 NVD API:")
        if nvd_config['api_key']:
            masked_key = nvd_config['api_key'][:8] + "*" * 20 + nvd_config['api_key'][-4:]
            print(f"   • API Key: {masked_key}")
            print(f"   • Límite: 120 requests/minuto")
        else:
            print(f"   • Sin API Key (5 requests/30 segundos)")
        
        print(f"\n📧 Email:")
        print(f"   • Servidor: {email_config['smtp_server']}:{email_config['smtp_port']}")
        print(f"   • Remitente: {email_config['sender_email']}")
        print(f"   • Destinatario: {email_config['recipient_email']}")
        
        print(f"\n⏰ Monitoreo:")
        print(f"   • Intervalo: {monitoring_config['check_interval_hours']} horas")
        print(f"   • Próxima ejecución: En {monitoring_config['check_interval_hours']} horas")
        
        print(f"\n📁 Archivos:")
        print(f"   • Configuración: {self.config_file}")
        print(f"   • Logs: /var/log/nvd-monitor/nvd-monitor.log")
        print(f"   • Aplicación: /opt/nvd-monitor/nvd_monitor.py")
        
        print(f"\n🔧 Comandos útiles:")
        print(f"   • Probar configuración: nvd-admin test-all")
        print(f"   • Ejecutar una vez: nvd-monitor --run-once")
        print(f"   • Ver vulnerabilidades: nvd-admin show-vulns")
        print(f"   • Estado del servicio: sudo systemctl status nvd-monitor")
        print(f"   • Iniciar servicio: sudo systemctl start nvd-monitor")
        print(f"   • Ver logs: sudo journalctl -u nvd-monitor -f")
        
        print(f"\n🎉 ¡Su sistema está listo para proteger su infraestructura!")
        print()

if __name__ == "__main__":
    import datetime
    
    if os.geteuid() != 0:
        print("❌ Este script debe ejecutarse como root")
        print("Uso: sudo python3 configure.py")
        sys.exit(1)
    
    configurator = NVDConfigurator()
    
    try:
        success = configurator.run()
        if success:
            print("✅ Configuración completada exitosamente")
            sys.exit(0)
        else:
            print("❌ Configuración fallida")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n❌ Configuración cancelada por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        sys.exit(1)
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
Versión: 1.0.0
"""

import argparse
import configparser
import mysql.connector
import requests
import smtplib
from email.mime.text import MIMEText
import sys
import os
from datetime import datetime
from tabulate import tabulate
import subprocess

class NVDAdmin:
    def __init__(self, config_file='/etc/nvd-monitor/config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()
    
    def load_config(self):
        """Cargar configuración"""
        try:
            if not os.path.exists(self.config_file):
                print(f"❌ Archivo de configuración no encontrado: {self.config_file}")
                print("Ejecute: sudo nvd-configure")
                sys.exit(1)
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
            print(f"🔍 Vulnerabilidades almacenadas: {vuln_count:,}")
            print(f"📝 Logs de monitoreo: {log_count:,}")
            
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
            api_key = self.config.get('nvd', 'api_key', fallback='')
            headers = {
                'User-Agent': 'NVD-Monitor-Admin/1.0'
            }
            
            if api_key:
                headers['apiKey'] = api_key
            
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=headers,
                params={'resultsPerPage': 1},
                timeout=15
            )
            response.raise_for_status()
            
            data = response.json()
            total_results = data.get('totalResults', 0)
            
            print(f"✅ Conexión con NVD API exitosa")
            print(f"📊 Total de CVEs en NVD: {total_results:,}")
            
            # Verificar límites de rate
            if 'X-RateLimit-Remaining' in response.headers:
                remaining = response.headers['X-RateLimit-Remaining']
                print(f"🚦 Requests restantes: {remaining}")
            
            if api_key:
                print(f"🔑 Usando API key (120 req/min)")
            else:
                print(f"⚠️  Sin API key (5 req/30s)")
            
            return True
            
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def test_email(self):
        """Probar configuración de email"""
        print("🔍 Probando configuración de email...")
        
        try:
            smtp_server = self.config.get('email', 'smtp_server')
            smtp_port = self.config.getint('email', 'smtp_port')
            sender_email = self.config.get('email', 'sender_email')
            sender_password = self.config.get('email', 'sender_password')
            recipient_email = self.config.get('email', 'recipient_email')
            
            # Probar conexión
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.quit()
            
            print(f"✅ Conexión SMTP exitosa")
            print(f"📧 Servidor: {smtp_server}:{smtp_port}")
            print(f"📤 Remitente: {sender_email}")
            print(f"📥 Destinatario: {recipient_email}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error: {e}")
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
            
            if results:
                headers = ['CVE ID', 'Publicado', 'CVSS', 'Severidad', 'Descripción', 'Detectado']
                
                formatted_results = []
                for row in results:
                    formatted_results.append([
                        row[0] or 'N/A',
                        row[1].strftime('%Y-%m-%d') if row[1] else 'N/A',
                        f"{row[2]:.1f}" if row[2] else 'N/A',
                        row[3] or 'N/A',
                        (row[4] or 'N/A')[:50] + '...' if len(row[4] or '') > 50 else (row[4] or 'N/A'),
                        row[5].strftime('%Y-%m-%d %H:%M') if row[5] else 'N/A'
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
            stats_queries = {
                'total_vulns': "SELECT COUNT(*) FROM vulnerabilities",
                'critical_vulns': "SELECT COUNT(*) FROM vulnerabilities WHERE cvss_severity = 'CRITICAL'",
                'high_vulns': "SELECT COUNT(*) FROM vulnerabilities WHERE cvss_severity = 'HIGH'",
                'avg_score': "SELECT AVG(cvss_score) FROM vulnerabilities WHERE cvss_score IS NOT NULL",
                'latest_detection': "SELECT MAX(created_at) FROM vulnerabilities"
            }
            
            stats = {}
            for key, query in stats_queries.items():
                cursor.execute(query)
                result = cursor.fetchone()
                stats[key] = result[0] if result[0] is not None else 0
            
            print(f"\n📊 ESTADÍSTICAS DEL SISTEMA")
            print("=" * 50)
            print(f"🔍 Total vulnerabilidades: {stats['total_vulns']:,}")
            print(f"🔴 Críticas: {stats['critical_vulns']:,} ({stats['critical_vulns']/max(stats['total_vulns'], 1)*100:.1f}%)")
            print(f"🟠 Altas: {stats['high_vulns']:,} ({stats['high_vulns']/max(stats['total_vulns'], 1)*100:.1f}%)")
            print(f"📈 Puntuación CVSS promedio: {stats['avg_score']:.2f}" if stats['avg_score'] else "📈 Puntuación CVSS promedio: N/A")
            
            if stats['latest_detection']:
                latest = stats['latest_detection']
                if isinstance(latest, str):
                    latest = datetime.fromisoformat(latest.replace('Z', ''))
                print(f"🕐 Última detección: {latest.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Vulnerabilidades por mes (últimos 6 meses)
            cursor.execute("""
                SELECT DATE_FORMAT(created_at, '%Y-%m') as month, COUNT(*) as count
                FROM vulnerabilities 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
                GROUP BY month 
                ORDER BY month DESC
                LIMIT 6
            """)
            monthly_stats = cursor.fetchall()
            
            if monthly_stats:
                print(f"\n📅 Vulnerabilidades por mes (últimos 6 meses):")
                for month, count in monthly_stats:
                    print(f"  {month}: {count:,}")
            
            cursor.close()
            connection.close()
            
        except Exception as e:
            print(f"❌ Error obteniendo estadísticas: {e}")
    
    def show_config(self):
        """Mostrar configuración actual (sin contraseñas)"""
        print    def get_references(self, cve_data: Dict) -> str:
        """Extraer referencias del CVE"""
        references = cve_data.get('references', [])
        ref_urls = [ref.get('url', '') for ref in references[:5] if ref.get('url')]
        return ', '.join(ref_urls)
    
    def get_affected_products(self, cve_data: Dict) -> str:
        """Extraer productos afectados"""
        configurations = cve_data.get('configurations', [])
        products = set()
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    if cpe.get('vulnerable', False):
                        cpe_name = cpe.get('criteria', '').split(':')
                        if len(cpe_name) >= 5:
                            vendor = cpe_name[3] if cpe_name[3] != '*' else 'unknown'
                            product = cpe_name[4] if cpe_name[4] != '*' else 'unknown'
                            products.add(f"{vendor}:{product}")
        
        return ', '.join(list(products)[:10])  # Limitar a 10 productos únicos
    
    def save_to_database(self, vulnerabilities: List[Dict]) -> bool:
        """Guardar vulnerabilidades en la base de datos"""
        if not vulnerabilities:
            return True
            
        connection = self.get_database_connection()
        if not connection:
            return False
        
        cursor = connection.cursor()
        saved_count = 0
        
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
                    
                    # Convertir fechas
                    pub_date = self.parse_date(vuln['published_date'])
                    mod_date = self.parse_date(vuln['last_modified'])
                    
                    cursor.execute(insert_query, (
                        vuln['cve_id'],
                        pub_date,
                        mod_date,
                        vuln['cvss_score'],
                        vuln['cvss_severity'],
                        vuln['description'][:4000] if vuln['description'] else None,
                        vuln['references'][:2000] if vuln['references'] else None,
                        vuln['affected_products'][:2000] if vuln['affected_products'] else None,
                        datetime.now()
                    ))
                    
                    saved_count += 1
                    self.logger.debug(f"Guardada vulnerabilidad: {vuln['cve_id']}")
            
            connection.commit()
            self.logger.info(f"Guardadas {saved_count} nuevas vulnerabilidades en la base de datos")
            
            # Registrar estadísticas de monitoreo
            self.log_monitoring_stats(len(vulnerabilities), saved_count)
            
            return True
            
        except Error as e:
            self.logger.error(f"Error guardando en base de datos: {e}")
            connection.rollback()
            return False
        finally:
            cursor.close()
            connection.close()
    
    def parse_date(self, date_str: str) -> Optional[datetime]:
        """Parsear fecha ISO format"""
        if not date_str:
            return None
        try:
            # Remover timezone info si existe para simplificar
            date_str = date_str.replace('Z', '').split('.')[0]
            return datetime.fromisoformat(date_str)
        except:
            return None
    
    def log_monitoring_stats(self, total_found: int, new_saved: int):
        """Registrar estadísticas de monitoreo"""
        connection = self.get_database_connection()
        if not connection:
            return
            
        cursor = connection.cursor()
        try:
            insert_query = """
            INSERT INTO monitoring_logs (vulnerabilities_found, new_vulnerabilities, status, message)
            VALUES (%s, %s, %s, %s)
            """
            
            status = "SUCCESS" if new_saved >= 0 else "ERROR"
            message = f"Procesadas {total_found} vulnerabilidades, {new_saved} nuevas guardadas"
            
            cursor.execute(insert_query, (total_found, new_saved, status, message))
            connection.commit()
            
        except Error as e:
            self.logger.error(f"Error guardando estadísticas: {e}")
        finally:
            cursor.close()
            connection.close()
    
    def send_email_notification(self, vulnerabilities: List[Dict]) -> bool:
        """Enviar notificación por email"""
        if not vulnerabilities:
            return True
            
        self.logger.info(f"Enviando notificación por email para {len(vulnerabilities)} vulnerabilidades")
        
        try:
            smtp_server = self.config.get('email', 'smtp_server')
            smtp_port = self.config.getint('email', 'smtp_port')
            sender_email = self.config.get('email', 'sender_email')
            sender_password = self.config.get('email', 'sender_password')
            recipient_email = self.config.get('email', 'recipient_email')
            
            # Crear mensaje
            message = MIMEMultipart('alternative')
            message["From"] = sender_email
            message["To"] = recipient_email
            message["Subject"] = f"🚨 NVD Alert: {len(vulnerabilities)} Vulnerabilidades Críticas Detectadas"
            
            # Crear cuerpo del mensaje
            html_body = self.create_email_body(vulnerabilities)
            text_body = self.create_text_email_body(vulnerabilities)
            
            # Adjuntar partes del mensaje
            message.attach(MIMEText(text_body, "plain"))
            message.attach(MIMEText(html_body, "html"))
            
            # Enviar email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(message)
            
            self.logger.info(f"✅ Email enviado exitosamente a {recipient_email}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error enviando email: {e}")
            return False
    
    def create_email_body(self, vulnerabilities: List[Dict]) -> str:
        """Crear cuerpo del email en HTML"""
        critical_count = sum(1 for v in vulnerabilities if v['cvss_severity'] == 'CRITICAL')
        high_count = len(vulnerabilities) - critical_count
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 800px; margin: 0 auto; background-color: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #dc3545, #c82333); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .header h1 {{ margin: 0; font-size: 24px; }}
                .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
                .summary {{ padding: 20px; background-color: #f8f9fa; border-bottom: 1px solid #dee2e6; }}
                .summary-item {{ display: inline-block; margin: 0 20px; text-align: center; }}
                .summary-number {{ font-size: 24px; font-weight: bold; }}
                .critical {{ color: #dc3545; }}
                .high {{ color: #fd7e14; }}
                .vulnerability {{ border: 1px solid #dee2e6; margin: 15px 20px; border-radius: 8px; overflow: hidden; }}
                .vuln-header {{ padding: 15px; }}
                .vuln-header.critical {{ border-left: 5px solid #dc3545; background-color: #f8d7da; }}
                .vuln-header.high {{ border-left: 5px solid #fd7e14; background-color: #fff3cd; }}
                .cve-id {{ font-weight: bold; font-size: 18px; margin-bottom: 5px; }}
                .score {{ font-weight: bold; margin-bottom: 10px; }}
                .description {{ margin-bottom: 10px; line-height: 1.4; }}
                .meta {{ font-size: 12px; color: #666; }}
                .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #666; background-color: #f8f9fa; border-radius: 0 0 10px 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ NVD Vulnerability Monitor</h1>
                    <p>Alerta de Vulnerabilidades Críticas</p>
                    <p>Generado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                </div>
                
                <div class="summary">
                    <div class="summary-item">
                        <div class="summary-number critical">{critical_count}</div>
                        <div>Críticas</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number high">{high_count}</div>
                        <div>Altas</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{len(vulnerabilities)}</div>
                        <div>Total</div>
                    </div>
                </div>
        """
        
        for vuln in vulnerabilities:
            severity_class = "critical" if vuln['cvss_severity'] == 'CRITICAL' else "high"
            severity_icon = "🔴" if vuln['cvss_severity'] == 'CRITICAL' else "🟠"
            
            # Formatear fecha de publicación
            pub_date = vuln['published_date'][:10] if vuln['published_date'] else 'N/A'
            
            html += f"""
                <div class="vulnerability">
                    <div class="vuln-header {severity_class}">
                        <div class="cve-id">{severity_icon} {vuln['cve_id']}</div>
                        <div class="score">CVSS: {vuln['cvss_score']:.1f} ({vuln['cvss_severity']})</div>
                        <div class="description">{vuln['description'][:300]}{'...' if len(vuln['description']) > 300 else ''}</div>
                        <div class="meta">
                            <strong>📅 Publicado:</strong> {pub_date}<br>
                            <strong>🎯 Productos afectados:</strong> {vuln['affected_products'][:100]}{'...' if len(vuln['affected_products']) > 100 else ''}<br>
                            <strong>🔗 Referencias:</strong> <a href="{vuln['references'].split(',')[0].strip() if vuln['references'] else '#'}">Ver detalles</a>
                        </div>
                    </div>
                </div>
            """
        
        html += f"""
                <div class="footer">
                    <p>Este reporte fue generado automáticamente por NVD Vulnerability Monitor</p>
                    <p>Para más información, consulte los logs del sistema o ejecute: <code>nvd-admin show-vulns</code></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def create_text_email_body(self, vulnerabilities: List[Dict]) -> str:
        """Crear cuerpo del email en texto plano"""
        body = f"""
🛡️ NVD VULNERABILITY MONITOR - ALERTA
========================================

Se han detectado {len(vulnerabilities)} nuevas vulnerabilidades críticas/altas.
Reporte generado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

RESUMEN:
"""
        
        critical_count = sum(1 for v in vulnerabilities if v['cvss_severity'] == 'CRITICAL')
        high_count = len(vulnerabilities) - critical_count
        
        body += f"  🔴 Críticas: {critical_count}\n"
        body += f"  🟠 Altas: {high_count}\n"
        body += f"  📊 Total: {len(vulnerabilities)}\n\n"
        
        body += "DETALLES:\n"
        body += "=" * 50 + "\n\n"
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_icon = "🔴" if vuln['cvss_severity'] == 'CRITICAL' else "🟠"
            pub_date = vuln['published_date'][:10] if vuln['published_date'] else 'N/A'
            
            body += f"{i}. {severity_icon} {vuln['cve_id']}\n"
            body += f"   CVSS: {vuln['cvss_score']:.1f} ({vuln['cvss_severity']})\n"
            body += f"   Publicado: {pub_date}\n"
            body += f"   Descripción: {vuln['description'][:200]}{'...' if len(vuln['description']) > 200 else ''}\n"
            body += f"   Productos: {vuln['affected_products'][:100]}{'...' if len(vuln['affected_products']) > 100 else ''}\n\n"
        
        body += "\n" + "=" * 50 + "\n"
        body += "Este reporte fue generado automáticamente por NVD Vulnerability Monitor\n"
        body += "Para más información: nvd-admin show-vulns\n"
        
        return body
    
    def test_email_connection(self) -> bool:
        """Probar conexión de email"""
        self.logger.info("Probando configuración de email...")
        
        try:
            smtp_server = self.config.get('email', 'smtp_server')
            smtp_port = self.config.getint('email', 'smtp_port')
            sender_email = self.config.get('email', 'sender_email')
            sender_password = self.config.get('email', 'sender_password')
            recipient_email = self.config.get('email', 'recipient_email')
            
            # Probar conexión y autenticación
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
            
            self.logger.info("✅ Conexión de email exitosa")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error probando conexión de email: {e}")
            return False
    
    def test_nvd_connection(self) -> bool:
        """Probar conexión con NVD API"""
        self.logger.info("Probando conexión con NVD API...")
        
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
                timeout=15
            )
            response.raise_for_status()
            
            # Verificar rate limits
            if 'X-RateLimit-Remaining' in response.headers:
                remaining = response.headers['X-RateLimit-Remaining']
                self.logger.info(f"Requests restantes: {remaining}")
            
            self.logger.info("✅ Conexión con NVD API exitosa")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error probando conexión con NVD: {e}")
            return False
    
    def run_monitoring_cycle(self):
        """Ejecutar un ciclo completo de monitoreo"""
        start_time = datetime.now()
        self.logger.info("🔄 Iniciando ciclo de monitoreo")
        
        try:
            # Obtener vulnerabilidades
            vulnerabilities = self.fetch_nvd_vulnerabilities()
            
            if vulnerabilities:
                # Guardar en base de datos
                if self.save_to_database(vulnerabilities):
                    # Enviar notificación solo si hay vulnerabilidades nuevas
                    if self.send_email_notification(vulnerabilities):
                        self.logger.info("✅ Ciclo de monitoreo completado exitosamente")
                    else:
                        self.logger.warning("⚠️ Ciclo completado pero falló envío de email")
                else:
                    self.logger.error("❌ Error guardando en base de datos")
            else:
                self.logger.info("ℹ️ No se encontraron nuevas vulnerabilidades")
            
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
    parser = argparse.ArgumentParser(description='NVD Vulnerability Monitor v1.0.0')
    parser.add_argument('--config', default='/etc/nvd-monitor/config.ini', 
                       help='Archivo de configuración')
    parser.add_argument('--test-db', action='store_true', 
                       help='Probar conexión a base de datos')
    parser.add_argument('--test-email', action='store_true', 
                       help='Probar conexión de email')
    parser.add_argument('--test-nvd', action='store_true', 
                       help='Probar conexión con NVD API')
    parser.add_argument('--run-once', action='store_true', 
                       help='Ejecutar una sola vez')
    parser.add_argument('--daemon', action='store_true', 
                       help='Ejecutar como daemon')
    parser.add_argument('--version', action='version', version='NVD Monitor 1.0.0')
    
    args = parser.parse_args()
    
    try:
        monitor = NVDMonitor(args.config)
    except Exception as e:
        print(f"Error inicializando monitor: {e}")
        sys.exit(1)
    
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
        print("  nvd-monitor --test-email       # Probar email")
        print("  nvd-monitor --test-nvd         # Probar NVD API")
        print("  nvd-monitor --run-once         # Ejecutar una vez")

if __name__ == "__main__":
    main()
EOF

    chmod +x "$INSTALL_DIR/nvd_monitor.py"
    log_success "Aplicación principal instalada"
}

# Crear script de configuración post-instalación
create_configuration_script() {
    log_step "Creando script de configuración..."
    
    cat > "$INSTALL_DIR/configure.py" << 'EOF'
#!/usr/bin/env python3
"""
NVD Vulnerability Monitor - Script de Configuración Post-Instalación
Versión: 1.0.0
"""

import mysql.connector
from mysql.connector import Error
import configparser
import getpass
import sys
import os
import re
import secrets
import string
import smtplib
import requests

class NVDConfigurator:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config_file = '/etc/nvd-monitor/config.ini'
        
    def print_banner(self):
        print("=" * 70)
        print("   🛡️  NVD VULNERABILITY MONITOR - CONFIGURACIÓN")
        print("=" * 70)
        print()
    
    def generate_secure_password(self, length=16):
        """Generar contraseña segura"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        return password
    
    def validate_email(self, email):
        """Validar formato de email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}#!/bin/bash

# =============================================================================
# NVD Vulnerability Monitor - Script de Instalación Completo
# Versión: 1.0.0
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
readonly SCRIPT_VERSION="1.0.0"
readonly SUPPORTED_UBUNTU="24.04"
readonly PYTHON_MIN_VERSION="3.10"
readonly PROJECT_NAME="nvd-monitor"
readonly INSTALL_USER="nvd-monitor"
readonly INSTALL_DIR="/opt/nvd-monitor"
readonly CONFIG_DIR="/etc/nvd-monitor"
readonly LOG_DIR="/var/log/nvd-monitor"
readonly DATA_DIR="/var/lib/nvd-monitor"

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
    echo -e "${RED}[ERROR]${NC} $1"
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
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
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
    )
    
    # Actualizar repositorios
    show_progress 1 4 "Actualizando repositorios"
    apt update -qq
    
    # Actualizar sistema
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
    
    # Crear entorno virtual
    show_progress 1 4 "Creando entorno virtual"
    cd "$INSTALL_DIR"
    python3 -m venv venv
    
    # Activar entorno virtual
    show_progress 2 4 "Activando entorno"
    source venv/bin/activate
    
    # Actualizar pip
    show_progress 3 4 "Actualizando pip"
    pip install --upgrade pip -q
    
    # Instalar dependencias
    show_progress 4 4 "Instalando dependencias Python"
    pip install -q \
        requests>=2.31.0 \
        mysql-connector-python>=8.0.33 \
        schedule>=1.2.0 \
        configparser>=5.3.0 \
        tabulate>=0.9.0
    
    # Crear archivo requirements.txt
    cat > requirements.txt << 'EOF'
requests>=2.31.0
mysql-connector-python>=8.0.33
schedule>=1.2.0
configparser>=5.3.0
tabulate>=0.9.0
EOF
    
    deactivate
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
Versión: 1.0.0
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
import threading

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
    
    def fetch_nvd_vulnerabilities(self) -> List[Dict]:
        """Obtener vulnerabilidades desde NVD API"""
        self.logger.info("Consultando NVD API...")
        
        api_key = self.config.get('nvd', 'api_key')
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Calcular fecha desde la última consulta
        hours_back = self.config.getint('monitoring', 'check_interval_hours', fallback=4)
        start_date = (datetime.now() - timedelta(hours=hours_back * 2)).strftime('%Y-%m-%dT%H:%M:%S.000')
        
        headers = {
            'apiKey': api_key,
            'User-Agent': 'NVD-Monitor/1.0'
        }
        
        params = {
            'lastModStartDate': start_date,
            'resultsPerPage': 1000
        }
        
        try:
            self.logger.debug(f"Consultando NVD API con parámetros: {params}")
            response = requests.get(base_url, headers=headers, params=params, timeout=60)
            response.raise_for_status()
            
            data = response.json()
            total_results = data.get('totalResults', 0)
            self.logger.info(f"NVD API devolvió {total_results} resultados")
            
            vulnerabilities = []
            
            for cve in data.get('vulnerabilities', []):
                cve_data = cve.get('cve', {})
                
                # Extraer información de CVSS
                cvss_score = None
                cvss_severity = None
                
                metrics = cve_data.get('metrics', {})
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_v31 = metrics['cvssMetricV31'][0]
                    cvss_score = cvss_v31.get('cvssData', {}).get('baseScore')
                    cvss_severity = cvss_v31.get('cvssData', {}).get('baseSeverity')
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_v30 = metrics['cvssMetricV30'][0]
                    cvss_score = cvss_v30.get('cvssData', {}).get('baseScore')
                    cvss_severity = cvss_v30.get('cvssData', {}).get('baseSeverity')
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    cvss_v2 = metrics['cvssMetricV2'][0]
                    cvss_score = cvss_v2.get('cvssData', {}).get('baseScore')
                    # Mapear severity de CVSS v2 a v3
                    if cvss_score:
                        if cvss_score >= 9.0:
                            cvss_severity = 'CRITICAL'
                        elif cvss_score >= 7.0:
                            cvss_severity = 'HIGH'
                        elif cvss_score >= 4.0:
                            cvss_severity = 'MEDIUM'
                        else:
                            cvss_severity = 'LOW'
                
                # Filtrar por severidad (CRITICAL, HIGH)
                if cvss_severity in ['CRITICAL', 'HIGH']:
                    vulnerability = {
                        'cve_id': cve_data.get('id', ''),
                        'published_date': cve_data.get('published', ''),
                        'last_modified': cve_data.get('lastModified', ''),
                        'cvss_score': cvss_score,
                        'cvss_severity': cvss_severity,
                        'description': self.get_description(cve_data),
                        'references': self.get_references(cve_data),
                        'affected_products': self.get_affected_products(cve_data)
                    }
                    vulnerabilities.append(vulnerability)
                    self.logger.debug(f"Procesada vulnerabilidad: {vulnerability['cve_id']} - {cvss_severity}")
            
            self.logger.info(f"Filtradas {len(vulnerabilities)} vulnerabilidades críticas/altas de {total_results} totales")
            return vulnerabilities
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error de red consultando NVD API: {e}")
            return []
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decodificando respuesta JSON de NVD: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error inesperado consultando NVD API: {e}")
            return []
    
    def get_description(self, cve_data: Dict) -> str:
        """Extraer descripción del CVE"""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        # Si no hay descripción en inglés, tomar la primera disponible
        if descriptions:
            return descriptions[0].get('value', '')
        return 'Sin descripción disponible'
    
    def get_references(self, cve_data: Dict) -> str:
        """Extraer referencias del CVE"""
        references = cve_data.get('references', [])
        ref_urls =
        return re.match(pattern, email) is not None
    
    def get_database_info(self):
        """Solicitar información de la base de datos"""
        print("📊 CONFIGURACIÓN DE BASE DE DATOS")
        print("-" * 50)
        
        # Valores por defecto
        defaults = {
            'host': 'localhost',
            'port': '3306',
            'database': 'nvd_monitor',
            'user': 'nvd_user'
        }
        
        db_config = {}
        
        # Host
        db_config['host'] = input(f"Host de la base de datos [{defaults['host']}]: ").strip()
        if not db_config['host']:
            db_config['host'] = defaults['host']
        
        # Puerto
        while True:
            port_input = input(f"Puerto [{defaults['port']}]: ").strip()
            if not port_input:
                db_config['port'] = int(defaults['port'])
                break
            try:
                db_config['port'] = int(port_input)
                if 1 <= db_config['port'] <= 65535:
                    break
                else:
                    print("❌ El puerto debe estar entre 1 y 65535")
            except ValueError:
                print("❌ Por favor ingrese un número válido")
        
        # Base de datos
        db_config['database'] = input(f"Nombre de la base de datos [{defaults['database']}]: ").strip()
        if not db_config['database']:
            db_config['database'] = defaults['database']
        
        # Usuario
        db_config['user'] = input(f"Usuario de la base de datos [{defaults['user']}]: ").strip()
        if not db_config['user']:
            db_config['user'] = defaults['user']
        
        # Contraseña
        print("\n💡 Opciones de contraseña:")
        print("1. Generar contraseña segura automáticamente (recomendado)")
        print("2. Ingresar contraseña manualmente")
        
        while True:
            choice = input("Seleccione opción [1]: ").strip()
            if not choice:
                choice = "1"
            
            if choice == "1":
                db_config['password'] = self.generate_secure_password()
                print(f"✅ Contraseña generada: {db_config['password']}")
                print("⚠️  IMPORTANTE: Guarde esta contraseña, la necesitará para configurar MySQL")
                input("Presione Enter para continuar...")
                break
            elif choice == "2":
                while True:
                    password = getpass.getpass("Contraseña de la base de datos: ")
                    if len(password) >= 8:
                        db_config['password'] = password
                        break
                    else:
                        print("❌ La contraseña debe tener al menos 8 caracteres")
                break
            else:
                print("❌ Opción inválida")
        
        return db_config
    
    def create_mysql_user_script(self, db_config):
        """Crear script SQL para configurar usuario MySQL"""
        script_path = "/tmp/setup_nvd_mysql.sql"
        
        sql_content = f"""
-- Script de configuración MySQL para NVD Monitor
-- Ejecutar como root: mysql -u root -p < {script_path}

-- Crear base de datos
CREATE DATABASE IF NOT EXISTS {db_config['database']} 
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Crear usuario
CREATE USER IF NOT EXISTS '{db_config['user']}'@'{db_config['host']}' 
IDENTIFIED BY '{db_config['password']}';

-- Otorgar permisos
GRANT ALL PRIVILEGES ON {db_config['database']}.* TO '{db_config['user']}'@'{db_config['host']}';

-- Aplicar cambios
FLUSH PRIVILEGES;

-- Mostrar usuario creado
SELECT User, Host FROM mysql.user WHERE User = '{db_config['user']}';
"""
        
        with open(script_path, 'w') as f:
            f.write(sql_content)
        
        os.chmod(script_path, 0o600)
        
        print(f"\n📄 Script SQL creado en: {script_path}")
        print("🔧 Para configurar MySQL, ejecute:")
        print(f"   sudo mysql -u root -p < {script_path}")
        print()
        
        # Preguntar si quiere ejecutar automáticamente
        auto_setup = input("¿Desea ejecutar la configuración MySQL automáticamente? (y/N): ").strip().lower()
        if auto_setup in ['y', 'yes', 'sí', 's']:
            try:
                import subprocess
                print("🔄 Ejecutando configuración MySQL...")
                result = subprocess.run(['mysql', '-u', 'root', '-p'], 
                                      input=sql_content, text=True, 
                                      capture_output=True)
                if result.returncode == 0:
                    print("✅ Configuración MySQL completada")
                else:
                    print(f"❌ Error en configuración MySQL: {result.stderr}")
                    print("📝 Ejecute manualmente el script SQL")
            except Exception as e:
                print(f"❌ Error ejecutando configuración: {e}")
                print("📝 Ejecute manualmente el script SQL")
    
    def test_db_connection(self, db_config):
        """Probar conexión a la base de datos"""
        print("\n🔍 Probando conexión a la base de datos...")
        
        try:
            connection = mysql.connector.connect(**db_config, connect_timeout=10)
            cursor = connection.cursor()
            
            # Verificar versión
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            print(f"✅ Conexión exitosa")
            print(f"📋 Versión: {version}")
            
            # Detectar tipo
            if 'MariaDB' in version:
                print("📋 Tipo: MariaDB")
            else:
                print("📋 Tipo: MySQL")
            
            cursor.close()
            connection.close()
            return True
            
        except Error as e:
            print(f"❌ Error de conexión: {e}")
            print("\n💡 Posibles soluciones:")
            print("   • Verificar que MySQL/MariaDB esté ejecutándose")
            print("   • Verificar credenciales de usuario")
            print("   • Ejecutar el script SQL de configuración")
            return False
    
    def create_database_tables(self, db_config):
        """Crear tablas necesarias en la base de datos"""
        print("\n🏗️ Creando tablas de la base de datos...")
        
        try:
            connection = mysql.connector.connect(**db_config)
            cursor = connection.cursor()
            
            # Tabla de vulnerabilidades
            create_vulnerabilities_table = """
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
                INDEX idx_severity (cv#!/bin/bash

# =============================================================================
# NVD Vulnerability Monitor - Script de Instalación Completo
# Versión: 1.0.0
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
readonly SCRIPT_VERSION="1.0.0"
readonly SUPPORTED_UBUNTU="24.04"
readonly PYTHON_MIN_VERSION="3.10"
readonly PROJECT_NAME="nvd-monitor"
readonly INSTALL_USER="nvd-monitor"
readonly INSTALL_DIR="/opt/nvd-monitor"
readonly CONFIG_DIR="/etc/nvd-monitor"
readonly LOG_DIR="/var/log/nvd-monitor"
readonly DATA_DIR="/var/lib/nvd-monitor"

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
    echo -e "${RED}[ERROR]${NC} $1"
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
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
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
    )
    
    # Actualizar repositorios
    show_progress 1 4 "Actualizando repositorios"
    apt update -qq
    
    # Actualizar sistema
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
    
    # Crear entorno virtual
    show_progress 1 4 "Creando entorno virtual"
    cd "$INSTALL_DIR"
    python3 -m venv venv
    
    # Activar entorno virtual
    show_progress 2 4 "Activando entorno"
    source venv/bin/activate
    
    # Actualizar pip
    show_progress 3 4 "Actualizando pip"
    pip install --upgrade pip -q
    
    # Instalar dependencias
    show_progress 4 4 "Instalando dependencias Python"
    pip install -q \
        requests>=2.31.0 \
        mysql-connector-python>=8.0.33 \
        schedule>=1.2.0 \
        configparser>=5.3.0 \
        tabulate>=0.9.0
    
    # Crear archivo requirements.txt
    cat > requirements.txt << 'EOF'
requests>=2.31.0
mysql-connector-python>=8.0.33
schedule>=1.2.0
configparser>=5.3.0
tabulate>=0.9.0
EOF
    
    deactivate
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
Versión: 1.0.0
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
import threading

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
    
    def fetch_nvd_vulnerabilities(self) -> List[Dict]:
        """Obtener vulnerabilidades desde NVD API"""
        self.logger.info("Consultando NVD API...")
        
        api_key = self.config.get('nvd', 'api_key')
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Calcular fecha desde la última consulta
        hours_back = self.config.getint('monitoring', 'check_interval_hours', fallback=4)
        start_date = (datetime.now() - timedelta(hours=hours_back * 2)).strftime('%Y-%m-%dT%H:%M:%S.000')
        
        headers = {
            'apiKey': api_key,
            'User-Agent': 'NVD-Monitor/1.0'
        }
        
        params = {
            'lastModStartDate': start_date,
            'resultsPerPage': 1000
        }
        
        try:
            self.logger.debug(f"Consultando NVD API con parámetros: {params}")
            response = requests.get(base_url, headers=headers, params=params, timeout=60)
            response.raise_for_status()
            
            data = response.json()
            total_results = data.get('totalResults', 0)
            self.logger.info(f"NVD API devolvió {total_results} resultados")
            
            vulnerabilities = []
            
            for cve in data.get('vulnerabilities', []):
                cve_data = cve.get('cve', {})
                
                # Extraer información de CVSS
                cvss_score = None
                cvss_severity = None
                
                metrics = cve_data.get('metrics', {})
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_v31 = metrics['cvssMetricV31'][0]
                    cvss_score = cvss_v31.get('cvssData', {}).get('baseScore')
                    cvss_severity = cvss_v31.get('cvssData', {}).get('baseSeverity')
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_v30 = metrics['cvssMetricV30'][0]
                    cvss_score = cvss_v30.get('cvssData', {}).get('baseScore')
                    cvss_severity = cvss_v30.get('cvssData', {}).get('baseSeverity')
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    cvss_v2 = metrics['cvssMetricV2'][0]
                    cvss_score = cvss_v2.get('cvssData', {}).get('baseScore')
                    # Mapear severity de CVSS v2 a v3
                    if cvss_score:
                        if cvss_score >= 9.0:
                            cvss_severity = 'CRITICAL'
                        elif cvss_score >= 7.0:
                            cvss_severity = 'HIGH'
                        elif cvss_score >= 4.0:
                            cvss_severity = 'MEDIUM'
                        else:
                            cvss_severity = 'LOW'
                
                # Filtrar por severidad (CRITICAL, HIGH)
                if cvss_severity in ['CRITICAL', 'HIGH']:
                    vulnerability = {
                        'cve_id': cve_data.get('id', ''),
                        'published_date': cve_data.get('published', ''),
                        'last_modified': cve_data.get('lastModified', ''),
                        'cvss_score': cvss_score,
                        'cvss_severity': cvss_severity,
                        'description': self.get_description(cve_data),
                        'references': self.get_references(cve_data),
                        'affected_products': self.get_affected_products(cve_data)
                    }
                    vulnerabilities.append(vulnerability)
                    self.logger.debug(f"Procesada vulnerabilidad: {vulnerability['cve_id']} - {cvss_severity}")
            
            self.logger.info(f"Filtradas {len(vulnerabilities)} vulnerabilidades críticas/altas de {total_results} totales")
            return vulnerabilities
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error de red consultando NVD API: {e}")
            return []
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decodificando respuesta JSON de NVD: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error inesperado consultando NVD API: {e}")
            return []
    
    def get_description(self, cve_data: Dict) -> str:
        """Extraer descripción del CVE"""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        # Si no hay descripción en inglés, tomar la primera disponible
        if descriptions:
            return descriptions[0].get('value', '')
        return 'Sin descripción disponible'
    
    def get_references(self, cve_data: Dict) -> str:
        """Extraer referencias del CVE"""
        references = cve_data.get('references', [])
        ref_urls =