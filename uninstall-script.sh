#!/bin/bash

# =============================================================================
# NVD Vulnerability Monitor - Script de Desinstalación Interactivo
# Versión: 1.0.0
# Compatible con: Ubuntu 20.04+ LTS
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
readonly SCRIPT_VERSION="1.0.0"
readonly INSTALL_USER="nvd-monitor"
readonly INSTALL_DIR="/opt/nvd-monitor"
readonly CONFIG_DIR="/etc/nvd-monitor"
readonly LOG_DIR="/var/log/nvd-monitor"
readonly DATA_DIR="/var/lib/nvd-monitor"
readonly BACKUP_DIR="$(pwd)/nvd-monitor-backups"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Variables para tracking
COMPONENTS_TO_REMOVE=()
BACKUP_DB=false
REMOVE_DB=false
REMOVE_DB_USER=false
REMOVE_SYSTEM_USER=false
REMOVE_LOGS=false
DB_PASSWORD=""

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

# Banner de bienvenida
show_welcome_banner() {
    clear
    echo -e "${RED}"
    echo "================================================================"
    echo "       🗑️  NVD MONITOR - DESINSTALADOR INTERACTIVO"
    echo "================================================================"
    echo -e "${NC}"
    echo -e "${YELLOW}⚠️  ADVERTENCIA: Este script eliminará NVD Monitor del sistema${NC}"
    echo
    echo "📋 Componentes detectados:"
    check_installed_components
    echo
    read -p "¿Desea continuar con la desinstalación? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Desinstalación cancelada."
        exit 0
    fi
}

# Verificar componentes instalados
check_installed_components() {
    local found=false
    
    # Verificar servicio
    if systemctl list-unit-files | grep -q "nvd-monitor.service"; then
        echo "  ✓ Servicio systemd: nvd-monitor"
        found=true
    fi
    
    # Verificar directorios
    [[ -d "$INSTALL_DIR" ]] && echo "  ✓ Directorio de aplicación: $INSTALL_DIR" && found=true
    [[ -d "$CONFIG_DIR" ]] && echo "  ✓ Directorio de configuración: $CONFIG_DIR" && found=true
    [[ -d "$LOG_DIR" ]] && echo "  ✓ Directorio de logs: $LOG_DIR" && found=true
    [[ -d "$DATA_DIR" ]] && echo "  ✓ Directorio de datos: $DATA_DIR" && found=true
    
    # Verificar comandos
    [[ -f "/usr/local/bin/nvd-monitor" ]] && echo "  ✓ Comando: nvd-monitor" && found=true
    [[ -f "/usr/local/bin/nvd-admin" ]] && echo "  ✓ Comando: nvd-admin" && found=true
    [[ -f "/usr/local/bin/nvd-status" ]] && echo "  ✓ Comando: nvd-status" && found=true
    
    # Verificar usuario del sistema
    if id "$INSTALL_USER" &>/dev/null; then
        echo "  ✓ Usuario del sistema: $INSTALL_USER"
        found=true
    fi
    
    # Verificar base de datos
    if command -v mysql &>/dev/null; then
        if mysql -u root -e "SHOW DATABASES;" 2>/dev/null | grep -q "nvd_monitor"; then
            echo "  ✓ Base de datos: nvd_monitor"
            found=true
        elif sudo mysql -u root -e "SHOW DATABASES;" 2>/dev/null | grep -q "nvd_monitor"; then
            echo "  ✓ Base de datos: nvd_monitor"
            found=true
        fi
    fi
    
    if ! $found; then
        echo "  ❌ No se encontraron componentes de NVD Monitor instalados"
        exit 0
    fi
}

# Verificar prerrequisitos
check_prerequisites() {
    log_step "Verificando prerrequisitos..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root"
        echo "Uso: sudo bash uninstall.sh"
        exit 1
    fi
    
    log_success "Prerrequisitos verificados"
}

# Detener servicio
stop_service() {
    log_step "Deteniendo servicio..."
    
    if systemctl is-active --quiet nvd-monitor; then
        systemctl stop nvd-monitor
        log_success "Servicio detenido"
    else
        log_info "Servicio no estaba activo"
    fi
    
    if systemctl is-enabled --quiet nvd-monitor 2>/dev/null; then
        systemctl disable nvd-monitor
        log_success "Servicio deshabilitado"
    fi
}

# Obtener credenciales de base de datos
get_db_credentials() {
    if [[ -f "$CONFIG_DIR/config.ini" ]]; then
        DB_PASSWORD=$(grep "^password" "$CONFIG_DIR/config.ini" 2>/dev/null | cut -d'=' -f2 | xargs || echo "")
        if [[ -n "$DB_PASSWORD" ]]; then
            log_info "Credenciales de base de datos obtenidas de la configuración"
            return 0
        fi
    fi
    return 1
}

# Respaldar base de datos
backup_database() {
    log_step "Respaldando base de datos..."
    
    # Crear directorio de respaldos
    mkdir -p "$BACKUP_DIR"
    
    local backup_file="$BACKUP_DIR/nvd_monitor_backup_${TIMESTAMP}.sql"
    local mysql_cmd=""
    
    # Determinar comando MySQL
    if mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
        mysql_cmd="mysql -u root"
    elif sudo mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
        mysql_cmd="sudo mysql -u root"
    else
        log_error "No se pudo conectar a MySQL/MariaDB para respaldar"
        return 1
    fi
    
    # Verificar si existe la base de datos
    if ! $mysql_cmd -e "SHOW DATABASES;" | grep -q "nvd_monitor"; then
        log_warn "Base de datos nvd_monitor no encontrada"
        return 1
    fi
    
    log_info "Creando respaldo en: $backup_file"
    
    # Realizar respaldo
    if mysqldump -u root nvd_monitor > "$backup_file" 2>/dev/null || \
       sudo mysqldump -u root nvd_monitor > "$backup_file" 2>/dev/null; then
        
        # Comprimir respaldo
        gzip "$backup_file"
        backup_file="${backup_file}.gz"
        
        local size=$(du -h "$backup_file" | cut -f1)
        log_success "Base de datos respaldada: $backup_file ($size)"
        
        # Crear archivo de información
        cat > "$BACKUP_DIR/restore_info_${TIMESTAMP}.txt" << EOF
NVD Monitor - Información de Respaldo
=====================================
Fecha: $(date)
Archivo: $(basename "$backup_file")
Base de datos: nvd_monitor
Usuario BD: nvd_user

Para restaurar:
1. Descomprimir: gunzip $(basename "$backup_file")
2. Crear base de datos: mysql -u root -e "CREATE DATABASE nvd_monitor;"
3. Crear usuario: mysql -u root -e "CREATE USER 'nvd_user'@'localhost' IDENTIFIED BY 'nueva_contraseña';"
4. Otorgar permisos: mysql -u root -e "GRANT ALL PRIVILEGES ON nvd_monitor.* TO 'nvd_user'@'localhost';"
5. Restaurar: mysql -u root nvd_monitor < $(basename "${backup_file%.gz}")

Nota: Deberá reinstalar NVD Monitor y actualizar la configuración con las nuevas credenciales.
EOF
        
        return 0
    else
        log_error "Error al respaldar la base de datos"
        return 1
    fi
}

# Respaldar configuración
backup_configuration() {
    log_step "Respaldando configuración y logs importantes..."
    
    mkdir -p "$BACKUP_DIR/config"
    mkdir -p "$BACKUP_DIR/logs"
    
    # Respaldar configuración
    if [[ -d "$CONFIG_DIR" ]]; then
        cp -r "$CONFIG_DIR"/* "$BACKUP_DIR/config/" 2>/dev/null || true
        log_info "Configuración respaldada"
    fi
    
    # Respaldar últimos logs
    if [[ -d "$LOG_DIR" ]]; then
        # Copiar solo los últimos 1000 líneas de logs para referencia
        if [[ -f "$LOG_DIR/nvd-monitor.log" ]]; then
            tail -n 1000 "$LOG_DIR/nvd-monitor.log" > "$BACKUP_DIR/logs/nvd-monitor-last-1000.log" 2>/dev/null || true
        fi
        log_info "Logs recientes respaldados"
    fi
    
    # Crear archivo de resumen
    cat > "$BACKUP_DIR/uninstall_summary_${TIMESTAMP}.txt" << EOF
NVD Monitor - Resumen de Desinstalación
========================================
Fecha: $(date)
Versión desinstalada: 1.0.9

Componentes eliminados:
$(printf '%s\n' "${COMPONENTS_TO_REMOVE[@]}" | sed 's/^/- /')

Respaldos creados:
$(ls -la "$BACKUP_DIR" | grep -E "\.(sql\.gz|txt)$" | awk '{print "- " $9}')

Ubicación de respaldos: $BACKUP_DIR

Para reinstalar:
1. git clone https://github.com/juanpadiaz/nvd-monitor.git
2. cd nvd-monitor
3. sudo bash install_final.sh
EOF
}

# Menú interactivo de selección
interactive_menu() {
    log_header "SELECCIÓN DE COMPONENTES A ELIMINAR"
    
    echo "Seleccione qué componentes desea eliminar:"
    echo
    
    # Base de datos
    if command -v mysql &>/dev/null && mysql -u root -e "SHOW DATABASES;" 2>/dev/null | grep -q "nvd_monitor"; then
        echo -e "${YELLOW}📊 BASE DE DATOS${NC}"
        read -p "  ¿Respaldar base de datos antes de eliminar? (Y/n): " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Nn]$ ]] && BACKUP_DB=true
        
        read -p "  ¿Eliminar base de datos nvd_monitor? (y/N): " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && REMOVE_DB=true && COMPONENTS_TO_REMOVE+=("Base de datos nvd_monitor")
        
        read -p "  ¿Eliminar usuario de base de datos nvd_user? (y/N): " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && REMOVE_DB_USER=true && COMPONENTS_TO_REMOVE+=("Usuario BD nvd_user")
        echo
    fi
    
    # Usuario del sistema
    if id "$INSTALL_USER" &>/dev/null; then
        echo -e "${YELLOW}👤 USUARIO DEL SISTEMA${NC}"
        read -p "  ¿Eliminar usuario del sistema $INSTALL_USER? (y/N): " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && REMOVE_SYSTEM_USER=true && COMPONENTS_TO_REMOVE+=("Usuario sistema $INSTALL_USER")
        echo
    fi
    
    # Logs
    if [[ -d "$LOG_DIR" ]]; then
        echo -e "${YELLOW}📝 LOGS${NC}"
        read -p "  ¿Eliminar todos los logs? (y/N): " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && REMOVE_LOGS=true && COMPONENTS_TO_REMOVE+=("Directorio de logs")
        echo
    fi
    
    # Agregar componentes estándar que siempre se eliminan
    COMPONENTS_TO_REMOVE+=("Servicio systemd")
    COMPONENTS_TO_REMOVE+=("Directorio de aplicación")
    COMPONENTS_TO_REMOVE+=("Directorio de configuración")
    COMPONENTS_TO_REMOVE+=("Directorio de datos")
    COMPONENTS_TO_REMOVE+=("Comandos del sistema")
    
    # Confirmar selección
    echo -e "${YELLOW}📋 RESUMEN DE COMPONENTES A ELIMINAR:${NC}"
    printf '%s\n' "${COMPONENTS_TO_REMOVE[@]}" | sed 's/^/  • /'
    echo
    
    read -p "¿Confirmar eliminación de estos componentes? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warn "Desinstalación cancelada por el usuario"
        exit 0
    fi
}

# Eliminar base de datos
remove_database() {
    if [[ "$REMOVE_DB" == true ]] || [[ "$REMOVE_DB_USER" == true ]]; then
        log_step "Eliminando componentes de base de datos..."
        
        local mysql_cmd=""
        if mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            mysql_cmd="mysql -u root"
        elif sudo mysql -u root -e "SELECT 1;" &>/dev/null 2>&1; then
            mysql_cmd="sudo mysql -u root"
        else
            log_error "No se pudo conectar a MySQL/MariaDB"
            return 1
        fi
        
        if [[ "$REMOVE_DB" == true ]]; then
            log_info "Eliminando base de datos nvd_monitor..."
            $mysql_cmd -e "DROP DATABASE IF EXISTS nvd_monitor;" 2>/dev/null || true
            log_success "Base de datos eliminada"
        fi
        
        if [[ "$REMOVE_DB_USER" == true ]]; then
            log_info "Eliminando usuario nvd_user..."
            $mysql_cmd -e "DROP USER IF EXISTS 'nvd_user'@'localhost';" 2>/dev/null || true
            log_success "Usuario de base de datos eliminado"
        fi
    fi
}

# Eliminar archivos del sistema
remove_system_files() {
    log_step "Eliminando archivos del sistema..."
    
    # Eliminar servicio systemd
    if [[ -f "/etc/systemd/system/nvd-monitor.service" ]]; then
        rm -f "/etc/systemd/system/nvd-monitor.service"
        systemctl daemon-reload
        log_info "Servicio systemd eliminado"
    fi
    
    # Eliminar comandos
    local commands=("/usr/local/bin/nvd-monitor" "/usr/local/bin/nvd-admin" "/usr/local/bin/nvd-status")
    for cmd in "${commands[@]}"; do
        if [[ -f "$cmd" ]]; then
            rm -f "$cmd"
            log_info "Comando $(basename "$cmd") eliminado"
        fi
    done
    
    # Eliminar directorios
    local dirs_to_remove=()
    
    # Siempre eliminar estos
    dirs_to_remove+=("$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR")
    
    # Logs solo si se seleccionó
    [[ "$REMOVE_LOGS" == true ]] && dirs_to_remove+=("$LOG_DIR")
    
    for dir in "${dirs_to_remove[@]}"; do
        if [[ -d "$dir" ]]; then
            rm -rf "$dir"
            log_info "Directorio $dir eliminado"
        fi
    done
    
    # Eliminar archivo de logrotate si existe
    if [[ -f "/etc/logrotate.d/nvd-monitor" ]]; then
        rm -f "/etc/logrotate.d/nvd-monitor"
        log_info "Configuración de logrotate eliminada"
    fi
    
    log_success "Archivos del sistema eliminados"
}

# Eliminar usuario del sistema
remove_system_user() {
    if [[ "$REMOVE_SYSTEM_USER" == true ]]; then
        log_step "Eliminando usuario del sistema..."
        
        if id "$INSTALL_USER" &>/dev/null; then
            # Eliminar usuario del grupo de otros usuarios
            for user in $(getent group "$INSTALL_USER" 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
                if [[ "$user" != "$INSTALL_USER" ]]; then
                    gpasswd -d "$user" "$INSTALL_USER" 2>/dev/null || true
                fi
            done
            
            # Eliminar usuario
            userdel "$INSTALL_USER" 2>/dev/null || true
            log_success "Usuario $INSTALL_USER eliminado"
            
            # Eliminar grupo si existe
            if getent group "$INSTALL_USER" &>/dev/null; then
                groupdel "$INSTALL_USER" 2>/dev/null || true
                log_success "Grupo $INSTALL_USER eliminado"
            fi
        fi
    fi
}

# Limpieza final
final_cleanup() {
    log_step "Realizando limpieza final..."
    
    # Eliminar archivos temporales
    rm -f /tmp/nvd-monitor-* /tmp/nvd_* /tmp/fix_* /tmp/test_* 2>/dev/null || true
    
    # Verificar si quedan archivos
    local remaining_files=0
    [[ -d "$INSTALL_DIR" ]] && ((remaining_files++))
    [[ -d "$CONFIG_DIR" ]] && ((remaining_files++))
    [[ -d "$LOG_DIR" ]] && ((remaining_files++))
    [[ -d "$DATA_DIR" ]] && ((remaining_files++))
    [[ -f "/usr/local/bin/nvd-monitor" ]] && ((remaining_files++))
    
    if [[ $remaining_files -eq 0 ]]; then
        log_success "Limpieza completa"
    else
        log_warn "Algunos archivos no pudieron ser eliminados"
    fi
}

# Mostrar resumen final
show_summary() {
    log_header "DESINSTALACIÓN COMPLETADA"
    
    echo -e "${GREEN}✅ NVD Monitor ha sido desinstalado${NC}"
    echo
    
    if [[ -d "$BACKUP_DIR" ]]; then
        echo "📁 RESPALDOS CREADOS EN: $BACKUP_DIR"
        echo
        ls -la "$BACKUP_DIR" | grep -E "\.(sql\.gz|txt)$" | while read -r line; do
            echo "  • $(echo "$line" | awk '{print $9}')"
        done
        echo
        echo "💡 IMPORTANTE:"
        echo "  • Los respaldos se han guardado en: $BACKUP_DIR"
        echo "  • Revise restore_info_*.txt para instrucciones de restauración"
        echo "  • Guarde estos archivos en un lugar seguro si los necesita"
    fi
    
    echo
    echo "🧹 COMPONENTES ELIMINADOS:"
    printf '%s\n' "${COMPONENTS_TO_REMOVE[@]}" | sed 's/^/  ✓ /'
    
    # Verificar si queda algo
    echo
    echo "🔍 VERIFICACIÓN FINAL:"
    local all_clean=true
    
    if systemctl list-unit-files 2>/dev/null | grep -q "nvd-monitor"; then
        echo "  ⚠️  Servicio systemd aún presente"
        all_clean=false
    fi
    
    if id "$INSTALL_USER" &>/dev/null 2>/dev/null; then
        echo "  ⚠️  Usuario $INSTALL_USER aún existe"
        all_clean=false
    fi
    
    if command -v mysql &>/dev/null; then
        if mysql -u root -e "SHOW DATABASES;" 2>/dev/null | grep -q "nvd_monitor"; then
            echo "  ⚠️  Base de datos nvd_monitor aún existe"
            all_clean=false
        fi
    fi
    
    if $all_clean; then
        echo "  ✅ Sistema limpio - No quedan componentes de NVD Monitor"
    else
        echo
        echo "  Algunos componentes no fueron eliminados según su elección"
    fi
    
    echo
    echo "📚 Para reinstalar NVD Monitor:"
    echo "  1. git clone https://github.com/juanpadiaz/nvd-monitor.git"
    echo "  2. cd nvd-monitor"
    echo "  3. sudo bash install_final.sh"
    echo
    log_success "¡Desinstalación finalizada!"
}

# Función principal
main() {
    # Manejo de argumentos
    case "${1:-}" in
        -h|--help)
            echo "NVD Monitor - Script de Desinstalación v${SCRIPT_VERSION}"
            echo "Uso: sudo bash uninstall.sh [opciones]"
            echo
            echo "Este script eliminará de forma interactiva los componentes"
            echo "de NVD Monitor instalados en el sistema."
            echo
            echo "Opciones:"
            echo "  -h, --help     Mostrar esta ayuda"
            echo "  -f, --force    Eliminar todo sin confirmación (¡usar con cuidado!)"
            echo
            echo "Ejemplos:"
            echo "  sudo bash uninstall.sh          # Desinstalación interactiva"
            echo "  sudo bash uninstall.sh --force  # Eliminar todo automáticamente"
            exit 0
            ;;
        -f|--force)
            log_warn "Modo forzado activado - Se eliminará todo sin confirmación"
            BACKUP_DB=true
            REMOVE_DB=true
            REMOVE_DB_USER=true
            REMOVE_SYSTEM_USER=true
            REMOVE_LOGS=true
            COMPONENTS_TO_REMOVE=("TODOS los componentes de NVD Monitor")
            ;;
    esac
    
    show_welcome_banner
    check_prerequisites
    
    # Si no es modo forzado, mostrar menú interactivo
    if [[ "${1:-}" != "-f" ]] && [[ "${1:-}" != "--force" ]]; then
        interactive_menu
    fi
    
    # Obtener credenciales antes de eliminar configuración
    get_db_credentials
    
    # Detener servicio primero
    stop_service
    
    # Respaldar si se solicitó
    if [[ "$BACKUP_DB" == true ]]; then
        backup_database
    fi
    backup_configuration
    
    # Eliminar componentes
    remove_database
    remove_system_files
    remove_system_user
    final_cleanup
    
    # Mostrar resumen
    show_summary
}

# Manejo de errores
error_handler() {
    local exit_code=$?
    local line_number=$1
    
    echo -e "\n${RED}================================================================${NC}"
    echo -e "${RED}  ERROR DURANTE LA DESINSTALACIÓN${NC}"
    echo -e "${RED}================================================================${NC}"
    echo
    log_error "Error en línea $line_number (código: $exit_code)"
    echo
    echo "La desinstalación no se completó correctamente."
    echo "Algunos componentes pueden haber sido eliminados parcialmente."
    echo
    echo "Para ayuda, ejecute: sudo bash uninstall.sh --help"
    
    exit $exit_code
}

trap 'error_handler $LINENO' ERR

# Ejecutar función principal
main "$@"