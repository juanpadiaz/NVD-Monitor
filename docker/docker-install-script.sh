#!/bin/bash
# Script simplificado para instalación dentro del contenedor Docker
# Este script configura los componentes necesarios sin interacción

set -e

echo "Configurando NVD Monitor en contenedor Docker..."

# Crear estructura de directorios
mkdir -p /opt/nvd-monitor /etc/nvd-monitor /var/log/nvd-monitor /var/lib/nvd-monitor/scripts

# Configurar permisos
chown -R nvd-monitor:nvd-monitor /opt/nvd-monitor /var/log/nvd-monitor /var/lib/nvd-monitor
chmod 750 /etc/nvd-monitor

# El resto de la configuración se hace en el entrypoint.sh
echo "Configuración base completada"