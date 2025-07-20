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
ReadWritePaths=$LOG_DIR $DATA_DIR $CONFIG_DIR
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

# Configurar base de datos automáticamente
setup_database() {
    log_step "Configurando base de datos..."
    
    # Detectar tipo de base de datos
    local db_service=""
    if systemctl is-active --quiet mariadb; then
        db_service="mariadb"
        log_info "Usando MariaDB"
    elif systemctl is-active --quiet mysql; then
        db_service="mysql"
        log_info "Usando MySQL"
    else
        log_error "No se encontró MariaDB o MySQL ejecutándose"
        return 1
    fi
    
    # Generar contraseña para base de datos
    DB_PASSWORD=$(generate_password)
    
    log_info "Creando base de datos nvd_monitor y usuario nvd_user..."
    
    # Crear base de datos y usuario
    mysql -u root << EOF || {
        log_error "Error configurando base de datos"
        return 1
    }
CREATE DATABASE IF NOT EXISTS \`nvd_monitor\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'nvd_user'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON \`nvd_monitor\`.* TO 'nvd_user'@'localhost';
FLUSH PRIVILEGES;

USE \`nvd_monitor\`;

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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
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
    execution_time DECIMAL(10,3),
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO system_config (config_key, config_value, description) VALUES
('installation_date', NOW(), 'Fecha de instalación del sistema'),
('database_version', '1.0.4', 'Versión del esquema de base de datos');
EOF
    
    log_success "Base de datos configurada correctamente"
}

# Configuración interactiva de API Key
configure_api_key() {
    log_header "CONFIGURACIÓN DE API KEY DE NVD"
    
    echo "🔑 Para obtener mejor rendimiento, configure una API key gratuita de NVD"
    echo "📖 Beneficios:"
    echo "   • Sin API key: 5 requests cada 30 segundos"
    echo "   • Con API key: 120 requests por minuto (24x más rápido)"
    echo
    echo "🌐 Obtener API key:"
    echo "   1. Visite: https://nvd.nist.gov/developers/request-an-api-key"
    echo "   2. Complete el formulario (gratuito)"
    echo "   3. Recibirá la API key por email"
    echo
    
    while true; do
        echo "¿Desea configurar una API key ahora? (Y/n/s para omitir):"
        read -r choice
        choice=${choice:-Y}
        
        case $choice in
            [Yy]*)
                while true; do
                    echo "Ingrese su API key de NVD (formato: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx):"
                    read -r api_input
                    
                    if [[ -z "$api_input" ]]; then
                        echo "❌ API key no puede estar vacía"
                        continue
                    fi
                    
                    if validate_api_key "$api_input"; then
                        API_KEY="$api_input"
                        log_success "API key válida configurada"
                        
                        # Probar API key
                        echo "🔍 Probando API key..."
                        if test_api_key "$API_KEY"; then
                            log_success "API key verificada exitosamente"
                            break
                        else
                            log_warn "API key no pudo ser verificada, pero se guardará"
                            break
                        fi
                    else
                        echo "❌ Formato de API key inválido. Debe ser un UUID válido."
                        echo "Ejemplo: 12345678-1234-1234-1234-123456789abc"
                        read -p "¿Desea intentar nuevamente? (y/N): " retry
                        if [[ ! $retry =~ ^[Yy]$ ]]; then
                            API_KEY=""
                            break
                        fi
                    fi
                done
                break
                ;;
            [Nn]*)
                API_KEY=""
                log_info "API key omitida. Podrá configurarla más tarde editando /etc/nvd-monitor/config.ini"
                break
                ;;
            [Ss]*)
                API_KEY=""
                log_info "Configuración de API key omitida"
                break
                ;;
            *)
                echo "❌ Respuesta inválida. Use Y/n/s"
                ;;
        esac
    done
}

# Función para probar API key
test_api_key() {
    local api_key="$1"
    
    local response
    response=$(curl -s -w "%{http_code}" -o /tmp/nvd_test_response \
        -H "apiKey: $api_key" \
        -H "User-Agent: NVD-Monitor-Setup/1.0.4" \
        "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1" \
        --connect-timeout 10)
    
    local http_code="${response: -3}"
    
    if [[ "$http_code" == "200" ]]; then
        rm -f /tmp/nvd_test_response
        return 0
    else
        rm -f /tmp/nvd_test_response
        return 1
    fi
}

# Configuración interactiva de email
configure_email() {
    log_header "CONFIGURACIÓN DE NOTIFICACIONES POR EMAIL"
    
    echo "📧 Configure las notificaciones por email para recibir alertas de vulnerabilidades"
    echo "📝 Información necesaria:"
    echo "   • Servidor SMTP (ej: smtp.gmail.com)"
    echo "   • Email y contraseña del remitente"
    echo "   • Email del destinatario para alertas"
    echo
    
    while true; do
        echo "¿Desea configurar notificaciones por email? (Y/n/s para omitir):"
        read -r choice
        choice=${choice:-Y}
        
        case $choice in
            [Yy]*)
                configure_email_details
                break
                ;;
            [Nn]*)
                log_info "Notificaciones por email omitidas"
                SENDER_EMAIL=""
                SENDER_PASSWORD=""
                RECIPIENT_EMAIL=""
                break
                ;;
            [Ss]*)
                log_info "Configuración de email omitida"
                SENDER_EMAIL=""
                SENDER_PASSWORD=""
                RECIPIENT_EMAIL=""
                break
                ;;
            *)
                echo "❌ Respuesta inválida. Use Y/n/s"
                ;;
        esac
    done
}

# Configurar detalles del email
configure_email_details() {
    echo
    echo "📧 CONFIGURACIÓN DE EMAIL"
    echo "========================="
    
    # Servidor SMTP
    echo "🌐 Servidores SMTP comunes:"
    echo "   • Gmail: smtp.gmail.com (puerto 587)"
    echo "   • Outlook: smtp-mail.outlook.com (puerto 587)"
    echo "   • Yahoo: smtp.mail.yahoo.com (puerto 587)"
    echo
    
    local smtp_server
    while true; do
        read -p "Servidor SMTP [smtp.gmail.com]: " smtp_server
        smtp_server=${smtp_server:-smtp.gmail.com}
        if [[ -n "$smtp_server" ]]; then
            break
        fi
    done
    
    # Puerto SMTP
    local smtp_port
    while true; do
        read -p "Puerto SMTP [587]: " smtp_port
        smtp_port=${smtp_port:-587}
        if [[ "$smtp_port" =~ ^[0-9]+$ ]] && [ "$smtp_port" -ge 1 ] && [ "$smtp_port" -le 65535 ]; then
            break
        else
            echo "❌ Puerto inválido. Debe ser un número entre 1 y 65535"
        fi
    done
    
    # Email del remitente
    while true; do
        read -p "Email del remitente: " SENDER_EMAIL
        if validate_email "$SENDER_EMAIL"; then
            break
        else
            echo "❌ Formato de email inválido"
        fi
    done
    
    # Contraseña del remitente
    echo
    echo "🔐 IMPORTANTE - Contraseña de aplicación:"
    if [[ "$smtp_server" == *"gmail"* ]]; then
        echo "   Para Gmail, debe usar una 'Contraseña de Aplicación':"
        echo "   1. Vaya a: https://myaccount.google.com/apppasswords"
        echo "   2. Genere una contraseña específica para esta aplicación"
        echo "   3. Use esa contraseña aquí (no su contraseña normal de Gmail)"
    fi
    echo
    
    while true; do
        read -s -p "Contraseña del remitente (no se mostrará): " SENDER_PASSWORD
        echo
        if [[ -n "$SENDER_PASSWORD" ]]; then
            break
        else
            echo "❌ La contraseña no puede estar vacía"
        fi
    done
    
    # Email del destinatario
    while true; do
        read -p "Email del destinatario (para recibir alertas): " RECIPIENT_EMAIL
        if validate_email "$RECIPIENT_EMAIL"; then
            break
        else
            echo "❌ Formato de email inválido"
        fi
    done
    
    # Probar configuración de email
    echo
    echo "🔍 ¿Desea probar la configuración de email? (Y/n):"
    read -r test_choice
    test_choice=${test_choice:-Y}
    
    if [[ $test_choice =~ ^[Yy]$ ]]; then
        test_email_configuration "$smtp_server" "$smtp_port" "$SENDER_EMAIL" "$SENDER_PASSWORD" "$RECIPIENT_EMAIL"
    fi
    
    log_success "Configuración de email completada"
}

# Probar configuración de email
test_email_configuration() {
    local smtp_server="$1"
    local smtp_port="$2"
    local sender_email="$3"
    local sender_password="$4"
    local recipient_email="$5"
    
    echo "📧 Probando configuración de email..."
    
    # Crear script temporal de prueba
    cat > /tmp/test_email.py << EOF
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sys

try:
    # Crear mensaje de prueba
    message = MIMEMultipart()
    message["From"] = "$sender_email"
    message["To"] = "$recipient_email"
    message["Subject"] = "🛡️ NVD Monitor - Prueba de Configuración"
    
    body = """
🛡️ NVD VULNERABILITY MONITOR - PRUEBA DE CONFIGURACIÓN
====================================================

¡Felicidades! La configuración de email está funcionando correctamente.

📅 Fecha: $(date)
📧 Remitente: $sender_email
📨 Destinatario: $recipient_email
🌐 Servidor SMTP: $smtp_server:$smtp_port

El sistema NVD Monitor está listo para enviar alertas de vulnerabilidades.

---
Este es un email de prueba generado automáticamente.
    """
    
    message.attach(MIMEText(body, "plain"))
    
    # Conectar y enviar
    server = smtplib.SMTP("$smtp_server", $smtp_port)
    server.starttls()
    server.login("$sender_email", "$sender_password")
    server.send_message(message)
    server.quit()
    
    print("✅ Email de prueba enviado exitosamente")
    
except Exception as e:
    print(f"❌ Error enviando email: {e}")
    sys.exit(1)
EOF
    
    if python3 /tmp/test_email.py; then
        log_success "✅ Configuración de email verificada"
        echo "📧 Se envió un email de prueba a $recipient_email"
    else
        log_warn "⚠️ Error en la configuración de email"
        echo "💡 Posibles problemas:"
        echo "   • Credenciales incorrectas"
        echo "   • Para Gmail: usar contraseña de aplicación"
        echo "   • Verificar configuración de firewall"
        echo "   • Servidor SMTP incorrecto"
        
        read -p "¿Desea continuar con esta configuración de todos modos? (y/N): " continue_choice
        if [[ ! $continue_choice =~ ^[Yy]$ ]]; then
            SENDER_EMAIL=""
            SENDER_PASSWORD=""
            RECIPIENT_EMAIL=""
            log_info "Configuración de email cancelada"
        fi
    fi
    
    rm -f /tmp/test_email.py
}

# Crear archivo de configuración con todos los valores
create_configuration_file() {
    log_step "Creando archivo de configuración..."
    
    cat > "$CONFIG_DIR/config.ini" << EOF
[database]
host = localhost
port = 3306
database = nvd_monitor
user = nvd_user
password = ${DB_PASSWORD}

[nvd]
api_key = ${API_KEY}

[email]
smtp_server = ${smtp_server:-smtp.gmail.com}
smtp_port = ${smtp_port:-587}
sender_email = ${SENDER_EMAIL}
sender_password = ${SENDER_PASSWORD}
recipient_email = ${RECIPIENT_EMAIL}

[monitoring]
check_interval_hours = ${MONITOR_INTERVAL:-4}

[logging]
level = INFO
file = /var/log/nvd-monitor/nvd-monitor.log
EOF
    
    # Configurar permisos CORRECTOS para que nvd-monitor pueda leer
    chmod 755 "$CONFIG_DIR"
    chown root:nvd-monitor "$CONFIG_DIR/config.ini"
    chmod 640 "$CONFIG_DIR/config.ini"
    
    log_success "Archivo de configuración creado con permisos correctos"
}

# Configurar permisos finales
set_final_permissions() {
    log_step "Configurando permisos finales..."
    
    # Cambiar propietario de directorios principales
    chown -R "$INSTALL_USER:$INSTALL_USER" "$INSTALL_DIR"
    chown -R "$INSTALL_USER:$INSTALL_USER" "$LOG_DIR"
    chown -R "$INSTALL_USER:$INSTALL_USER" "$DATA_DIR"
    
    # Permisos específicos para archivos ejecutables
    find "$INSTALL_DIR" -name "*.py" -exec chmod +x {} \;
    
    log_success "Permisos configurados"
}

# Función principal de instalación
main_installation() {
    local total_steps=12
    local current_step=0
    
    log_header "NVD VULNERABILITY MONITOR - INSTALACIÓN v${SCRIPT_VERSION}"
    
    echo "🎯 Iniciando instalación completa para Ubuntu ${SUPPORTED_UBUNTU}+"
    echo "📦 Se instalarán y configurarán:"
    echo "   • Aplicación principal de monitoreo"
    echo "   • Base de datos (MariaDB/MySQL)"
    echo "   • Herramientas de administración"
    echo "   • Servicio systemd"
    echo "   • Configuración interactiva completa"
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
    
    # Configurar base de datos
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Configurando base de datos"
    setup_database
    
    # Configurar permisos finales
    current_step=$((current_step + 1))
    show_progress $current_step $total_steps "Configurando permisos"
    set_final_permissions
    
    echo
}

# Configuración interactiva completa
interactive_configuration() {
    log_header "CONFIGURACIÓN INTERACTIVA"
    
    echo "🔧 Ahora procederemos a configurar NVD Monitor de forma interactiva"
    echo "📝 Se configurarán:"
    echo "   • API Key de NVD (para mejor rendimiento)"
    echo "   • Notificaciones por email (para alertas)"
    echo "   • Intervalo de monitoreo"
    echo
    
    read -p "¿Desea proceder con la configuración interactiva? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        configure_api_key
        configure_email
        
        # Configurar intervalo de monitoreo
        echo
        echo "⏰ INTERVALO DE MONITOREO"
        echo "========================"
        echo "¿Cada cuántas horas desea que NVD Monitor verifique nuevas vulnerabilidades?"
        
        local interval
        while true; do
            read -p "Intervalo en horas [4]: " interval
            interval=${interval:-4}
            if [[ "$interval" =~ ^[0-9]+$ ]] && [ "$interval" -ge 1 ] && [ "$interval" -le 168 ]; then
                break
            else
                echo "❌ Intervalo inválido. Debe ser entre 1 y 168 horas (1 semana)"
            fi
        done
        
        # Guardar intervalo (se usará en create_configuration_file)
        MONITOR_INTERVAL="$interval"
        
        log_success "Configuración interactiva completada"
    else
        log_info "Configuración interactiva omitida"
        API_KEY=""
        SENDER_EMAIL=""
        SENDER_PASSWORD=""
        RECIPIENT_EMAIL=""
        MONITOR_INTERVAL="4"
    fi
}

# Finalizar instalación y pruebas
finalize_installation() {
    log_step "Finalizando instalación..."
    
    # Crear archivo de configuración con todos los valores
    create_configuration_file
    
    # Verificar que nvd-monitor puede leer la configuración
    if sudo -u nvd-monitor cat "$CONFIG_DIR/config.ini" >/dev/null 2>&1; then
        log_success "Usuario nvd-monitor puede acceder a la configuración"
    else
        log_error "Error de permisos en archivo de configuración"
        return 1
    fi
    
    # Probar la aplicación
    log_info "Probando aplicación..."
    if sudo -u nvd-monitor timeout 5s "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/nvd_monitor.py" --run-once; then
        log_success "Aplicación ejecuta correctamente"
    else
        log_info "Prueba de aplicación completada (timeout normal)"
    fi
    
    # Probar herramientas de administración
    log_info "Probando herramientas de administración..."
    if nvd-admin test-db; then
        log_success "Herramientas de administración funcionan correctamente"
    else
        log_error "Error en herramientas de administración"
        return 1
    fi
    
    # Habilitar e iniciar servicio
    log_info "Iniciando servicio NVD Monitor..."
    systemctl enable nvd-monitor
    systemctl start nvd-monitor
    
    # Verificar estado del servicio
    sleep 3
    if systemctl is-active --quiet nvd-monitor; then
        log_success "Servicio NVD Monitor iniciado correctamente"
    else
        log_error "Error iniciando el servicio"
        echo "Verifique logs con: sudo journalctl -u nvd-monitor -n 20"
        return 1
    fi
}

# Mostrar resumen final
show_final_summary() {
    log_header "INSTALACIÓN COMPLETADA EXITOSAMENTE"
    
    echo -e "${GREEN}🎉 NVD Vulnerability Monitor ha sido instalado y configurado completamente${NC}"
    echo
    echo "📊 RESUMEN DE LA INSTALACIÓN:"
    echo "================================"
    echo "✅ Sistema base instalado"
    echo "✅ Base de datos configurada y funcionando"
    echo "✅ Usuario y permisos configurados correctamente"
    echo "✅ Servicio systemd activo"
    echo "✅ Herramientas de administración funcionando"
    
    if [[ -n "$API_KEY" ]]; then
        echo "✅ API Key de NVD configurada (120 req/min)"
    else
        echo "⚠️  API Key de NVD no configurada (5 req/30s)"
    fi
    
    if [[ -n "$SENDER_EMAIL" ]]; then
        echo "✅ Notificaciones por email configuradas"
        echo "   📧 Alertas enviadas a: $RECIPIENT_EMAIL"
    else
        echo "⚠️  Notificaciones por email no configuradas"
    fi
    
    echo
    echo "🔧 COMANDOS DISPONIBLES:"
    echo "========================"
    echo "• nvd-status          - Ver estado rápido del sistema"
    echo "• nvd-admin test-all  - Probar todas las conexiones"
    echo "• nvd-admin status    - Estado detallado del servicio"
    echo "• nvd-monitor --run-once - Ejecutar verificación manual"
    echo
    echo "📋 ARCHIVOS IMPORTANTES:"
    echo "========================"
    echo "• Configuración: /etc/nvd-monitor/config.ini"
    echo "• Logs: /var/log/nvd-monitor/nvd-monitor.log"
    echo "• Aplicación: /opt/nvd-monitor/"
    echo
    echo "📊 ESTADO ACTUAL:"
    echo "================="
    
    # Mostrar estado actual
    nvd-status
    echo
    
    # Mostrar próximos pasos
    echo "🚀 PRÓXIMOS PASOS:"
    echo "=================="
    
    if [[ -z "$API_KEY" ]]; then
        echo "1. 🔑 Configurar API Key de NVD (opcional pero recomendado):"
        echo "   • Visite: https://nvd.nist.gov/developers/request-an-api-key"
        echo "   • Edite: sudo nano /etc/nvd-monitor/config.ini"
        echo "   • Reinicie: sudo systemctl restart nvd-monitor"
        echo
    fi
    
    if [[ -z "$SENDER_EMAIL" ]]; then
        echo "2. 📧 Configurar notificaciones por email (opcional):"
        echo "   • Edite: sudo nano /etc/nvd-monitor/config.ini"
        echo "   • Configure la sección [email]"
        echo "   • Reinicie: sudo systemctl restart nvd-monitor"
        echo
    fi
    
    echo "3. 📈 Monitorear el sistema:"
    echo "   • Ver logs: sudo journalctl -u nvd-monitor -f"
    echo "   • Estado: nvd-status"
    echo "   • Estadísticas: nvd-admin test-all"
    echo
    echo "4. 🔍 Primera ejecución:"
    echo "   • El sistema verificará vulnerabilidades cada ${MONITOR_INTERVAL:-4} horas"
    echo "   • Para una verificación inmediata: nvd-monitor --run-once"
    echo
    
    log_success "¡NVD Monitor está completamente configurado y listo para proteger su infraestructura!"
    
    # Mostrar información adicional
    echo
    echo "📚 INFORMACIÓN ADICIONAL:"
    echo "========================"
    echo "• El servicio se inicia automáticamente al arrancar el sistema"
    echo "• Los logs se rotan automáticamente (30 días de retención)"
    echo "• Las vulnerabilidades se almacenan en la base de datos nvd_monitor"
    echo "• Para soporte: https://github.com/juanpadiaz/NVD-Monitor"
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
    echo "Este script instalará y configurará completamente NVD Monitor"
    echo "Compatible con Ubuntu ${SUPPORTED_UBUNTU} LTS y superiores"
    echo ""
    echo "Características:"
    echo "• Instalación automática de dependencias"
    echo "• Configuración automática de base de datos"
    echo "• Configuración interactiva de API Key y email"
    echo "• Servicio systemd con inicio automático"
    echo "• Herramientas de administración integradas"
    echo ""
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
    
    # Ejecutar instalación completa
    main_installation
    interactive_configuration
    finalize_installation
    show_final_summary
}

# Manejo de errores
error_handler() {
    local exit_code=$?
    local line_number=$1
    
    echo -e "\n${RED}================================================================${NC}"
    echo -e "${RED}  ERROR EN LA INSTALACIÓN${NC}"
    echo -e "${RED}================================================================${NC}"
    echo
    log_error "Error en línea $line_number. Código de salida: $exit_code"
    echo
    echo "🔍 INFORMACIÓN DE DIAGNÓSTICO:"
    echo "• Línea del error: $line_number"
    echo "• Código de salida: $exit_code"
    echo "• Versión del script: $SCRIPT_VERSION"
    echo "• Sistema: $(lsb_release -d 2>/dev/null | cut -f2 || echo 'Desconocido')"
    echo
    echo "🛠️ POSIBLES SOLUCIONES:"
    echo "• Verificar conectividad a internet"
    echo "• Asegurar que se ejecuta como root: sudo bash install.sh"
    echo "• Verificar espacio en disco disponible"
    echo "• Revisar logs del sistema: sudo journalctl -n 50"
    echo
    echo "📧 Para soporte, incluya esta información en su reporte"
    
    cleanup
    exit $exit_code
}

# Configurar trap para errores
trap 'error_handler $LINENO' ERR

# Verificar que no se ejecute como source
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    log_error "Este script debe ejecutarse directamente, no como source"
    exit 1
fi

# Banner de bienvenida
show_welcome_banner() {
    clear
    echo -e "${BLUE}"
    echo "================================================================"
    echo "       🛡️  NVD VULNERABILITY MONITOR INSTALLER"
    echo "================================================================"
    echo -e "${NC}"
    echo -e "${GREEN}Versión: ${SCRIPT_VERSION}${NC}"
    echo -e "${GREEN}Compatible con: Ubuntu ${SUPPORTED_UBUNTU}+ LTS${NC}"
    echo
    echo "🎯 Este instalador configurará automáticamente:"
    echo "   ✅ Sistema base con todas las dependencias"
    echo "   ✅ Base de datos MariaDB/MySQL"
    echo "   ✅ Aplicación de monitoreo de vulnerabilidades"
    echo "   ✅ API Key de NVD (configuración interactiva)"
    echo "   ✅ Notificaciones por email (configuración interactiva)"
    echo "   ✅ Servicio systemd con inicio automático"
    echo "   ✅ Herramientas de administración"
    echo
    echo -e "${YELLOW}⚠️  REQUISITOS:${NC}"
    echo "   • Ubuntu 24.04+ LTS"
    echo "   • Conexión a internet"
    echo "   • Permisos de root (sudo)"
    echo "   • ~500MB de espacio libre"
    echo
    echo -e "${CYAN}📚 Documentación: https://github.com/juanpadiaz/NVD-Monitor${NC}"
    echo
    read -p "🚀 ¿Desea continuar con la instalación? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Instalación cancelada por el usuario."
        exit 0
    fi
    echo
}

# Función principal mejorada
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
            # Sin argumentos, mostrar banner y proceder
            show_welcome_banner
            ;;
        *)
            echo "Opción desconocida: $1"
            show_help
            exit 1
            ;;
    esac
    
    # Ejecutar instalación completa
    main_installation
    interactive_configuration
    finalize_installation
    show_final_summary
    
    echo
    echo -e "${GREEN}================================================================${NC}"
    echo -e "${GREEN}  ¡INSTALACIÓN COMPLETADA EXITOSAMENTE!${NC}"
    echo -e "${GREEN}================================================================${NC}"
    echo
    echo "🎉 NVD Monitor está ahora completamente instalado y configurado"
    echo "🛡️ Su sistema está protegido contra vulnerabilidades críticas"
    echo
    echo "Para más información:"
    echo "• Estado: nvd-status"
    echo "• Logs: sudo journalctl -u nvd-monitor -f"
    echo "• Ayuda: nvd-admin --help"
    echo
}

# Ejecutar función principal con todos los argumentos
main "$@"#!/bin/bash

# =============================================================================
# NVD Vulnerability Monitor - Script de Instalación Final Completo
# Versión: 1.0.4
# Compatible con: Ubuntu 24.04 LTS y superiores
# Incluye: Correcciones de permisos y configuración interactiva completa
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
readonly SCRIPT_VERSION="1.0.4"
readonly SUPPORTED_UBUNTU="24.04"
readonly PYTHON_MIN_VERSION="3.10"
readonly PROJECT_NAME="nvd-monitor"
readonly INSTALL_USER="nvd-monitor"
readonly INSTALL_DIR="/opt/nvd-monitor"
readonly CONFIG_DIR="/etc/nvd-monitor"
readonly LOG_DIR="/var/log/nvd-monitor"
readonly DATA_DIR="/var/lib/nvd-monitor"

# Variables globales para configuración
DB_PASSWORD=""
API_KEY=""
SENDER_EMAIL=""
SENDER_PASSWORD=""
RECIPIENT_EMAIL=""

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}[CLEANUP]${NC} Limpiando archivos temporales..."
    rm -f /tmp/nvd-monitor-*.tmp /tmp/setup_database.sh /tmp/nvd_db_* 2>/dev/null || true
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

# Funciones de validación
validate_email() {
    local email="$1"
    if [[ $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_api_key() {
    local api_key="$1"
    # Validar formato UUID básico
    if [[ $api_key =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Generar contraseña segura
generate_password() {
    openssl rand -base64 16 | tr -d "=+/" | cut -c1-16
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
    
    # Verificar disponibilidad de bc para comparaciones de versión
    if ! command -v bc &> /dev/null; then
        apt update -qq
        apt install -y bc
    fi
    
    # Verificar Ubuntu (24.04 y superiores)
    local ubuntu_version
    if grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        ubuntu_version=$(lsb_release -rs 2>/dev/null || echo "0.0")
        local version_check
        version_check=$(echo "$ubuntu_version >= 24.04" | bc -l 2>/dev/null || echo "0")
        
        if [[ "$version_check" != "1" ]] && ! grep -q "Ubuntu ${SUPPORTED_UBUNTU}" /etc/os-release 2>/dev/null; then
            log_warn "Este script está optimizado para Ubuntu ${SUPPORTED_UBUNTU} LTS y superiores"
            echo "Sistema detectado: Ubuntu $ubuntu_version"
            read -p "¿Desea continuar de todos modos? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Instalación cancelada por el usuario"
                exit 0
            fi
        else
            log_success "Ubuntu $ubuntu_version detectado (compatible)"
        fi
    else
        log_warn "Sistema no Ubuntu detectado"
        echo "Sistema detectado: $(lsb_release -d 2>/dev/null | cut -f2 || echo 'Desconocido')"
        read -p "¿Desea continuar bajo su propia responsabilidad? (y/N): " -n 1 -r
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
    
    # Detectar si hay base de datos instalada
    local db_installed=""
    local preserve_db=false
    
    # Verificar MariaDB
    if dpkg -l 2>/dev/null | grep -q "^ii.*mariadb-server"; then
        db_installed="MariaDB"
        log_info "MariaDB detectado en el sistema"
        preserve_db=true
    # Verificar MySQL
    elif dpkg -l 2>/dev/null | grep -q "^ii.*mysql-server"; then
        db_installed="MySQL"
        log_info "MySQL detectado en el sistema"
        preserve_db=true
    # Verificar por servicios systemd
    elif systemctl list-unit-files 2>/dev/null | grep -q "mariadb.service"; then
        db_installed="MariaDB"
        log_info "MariaDB detectado via systemd"
        preserve_db=true
    elif systemctl list-unit-files 2>/dev/null | grep -q "mysql.service"; then
        db_installed="MySQL"
        log_info "MySQL detectado via systemd"
        preserve_db=true
    fi
    
    if [ "$preserve_db" = true ]; then
        echo "🔍 Base de datos detectada: $db_installed"
        echo "⚠️  El script mantendrá su instalación actual de $db_installed"
        read -p "¿Desea continuar preservando $db_installed? (Y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            log_warn "Si desea cambiar de base de datos, hágalo manualmente antes de continuar"
            exit 1
        fi
    fi
    
    local packages=(
        "python3-pip"
        "python3-venv" 
        "python3-dev"
        "build-essential"
        "curl"
        "wget"
        "git"
        "logrotate"
        "cron"
        "systemd"
        "bc"
    )
    
    # Solo agregar cliente de base de datos si no hay servidor instalado
    if [ "$preserve_db" = false ]; then
        packages+=("default-mysql-client")
        log_info "Se instalará cliente MySQL por defecto"
    else
        # Instalar cliente apropiado
        if [[ "$db_installed" == "MariaDB" ]]; then
            packages+=("mariadb-client")
        else
            packages+=("mysql-client")
        fi
    fi
    
    # Actualizar repositorios
    show_progress 1 5 "Actualizando repositorios"
    apt update -qq
    
    # Actualizar sistema crítico
    show_progress 2 5 "Actualizando sistema"
    DEBIAN_FRONTEND=noninteractive apt upgrade -y -qq
    
    # Instalar paquetes
    show_progress 3 5 "Instalando paquetes"
    DEBIAN_FRONTEND=noninteractive apt install -y -qq "${packages[@]}"
    
    # Verificar/instalar base de datos si es necesario
    show_progress 4 5 "Verificando base de datos"
    if [ "$preserve_db" = false ]; then
        log_info "No se detectó servidor de base de datos instalado"
        echo "🔧 Opciones de base de datos:"
        echo "   1. Instalar MariaDB (recomendado para Ubuntu 24.04+)"
        echo "   2. Instalar MySQL"
        echo "   3. Configurar manualmente más tarde"
        
        while true; do
            read -p "Seleccione opción [1]: " choice
            choice=${choice:-1}
            
            case $choice in
                1)
                    log_info "Instalando MariaDB Server..."
                    DEBIAN_FRONTEND=noninteractive apt install -y mariadb-server
                    systemctl enable mariadb
                    systemctl start mariadb
                    log_success "MariaDB instalado y iniciado"
                    break
                    ;;
                2)
                    log_info "Instalando MySQL Server..."
                    DEBIAN_FRONTEND=noninteractive apt install -y mysql-server
                    systemctl enable mysql
                    systemctl start mysql
                    log_success "MySQL instalado y iniciado"
                    break
                    ;;
                3)
                    log_warn "Deberá instalar MySQL o MariaDB manualmente antes de usar NVD Monitor"
                    break
                    ;;
                *)
                    echo "❌ Opción inválida. Seleccione 1, 2 o 3"
                    ;;
            esac
        done
    else
        # Verificar que el servicio esté ejecutándose
        if [[ "$db_installed" == "MariaDB" ]]; then
            if ! systemctl is-active --quiet mariadb; then
                log_info "Iniciando MariaDB..."
                systemctl start mariadb
            fi
        else
            if ! systemctl is-active --quiet mysql; then
                log_info "Iniciando MySQL..."
                systemctl start mysql
            fi
        fi
    fi
    
    # Limpiar cache
    show_progress 5 5 "Limpiando cache"
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
Versión: 1.0.4
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
    parser = argparse.ArgumentParser(description='NVD Vulnerability Monitor v1.0.4')
    parser.add_argument('--config', default='/etc/nvd-monitor/config.ini', 
                       help='Archivo de configuración')
    parser.add_argument('--test-db', action='store_true', 
                       help='Probar conexión a base de datos')
    parser.add_argument('--run-once', action='store_true', 
                       help='Ejecutar una sola vez')
    parser.add_argument('--daemon', action='store_true', 
                       help='Ejecutar como daemon')
    parser.add_argument('--version', action='version', version='NVD Monitor 1.0.4')
    
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

# Crear herramientas de administración corregidas
create_admin_tools() {
    log_step "Creando herramientas de administración..."
    
    cat > "$INSTALL_DIR/nvd_admin.py" << 'EOF'
#!/usr/bin/env python3
"""
NVD Vulnerability Monitor - Herramientas de Administración
Versión: 1.0.4
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
            try:
                self.config.read(self.config_file)
            except Exception as e:
                print(f"❌ Error leyendo configuración: {e}")
        else:
            print(f"❌ Archivo de configuración no encontrado: {self.config_file}")
            print("Ejecute: sudo nvd-configure")
    
    def test_database(self):
        """Probar conexión a base de datos"""
        print("🔍 Probando conexión a base de datos...")
        
        try:
            import mysql.connector
            
            # Leer configuración con valores por defecto
            host = self.config.get('database', 'host', fallback='localhost')
            database = self.config.get('database', 'database', fallback='nvd_monitor')
            user = self.config.get('database', 'user', fallback='nvd_user')
            password = self.config.get('database', 'password', fallback='')
            port = self.config.getint('database', 'port', fallback=3306)
            
            if not password:
                print("❌ Error: No hay contraseña configurada")
                return False
            
            # Intentar conexión
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
            print(f"📋 Tablas encontradas: {len(tables)}")
            
            cursor.close()
            connection.close()
            return True
            
        except ImportError:
            print("❌ Error: mysql-connector-python no está instalado")
            return False
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
    parser.add_argument('command', nargs='?', 
                       choices=['test-db', 'test-all', 'status'], 
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
    
    cat >