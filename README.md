# NVD Vulnerability Monitor

Sistema de monitoreo automatizado de vulnerabilidades críticas y de alto riesgo desde la National Vulnerability Database (NVD), específicamente diseñado para Ubuntu 24.04.

## 📋 Descripción

NVD Monitor es una aplicación Python que:
- Consulta la NVD API para obtener vulnerabilidades críticas y de alto riesgo
- Filtra vulnerabilidades zero-day y de alta severidad (CRITICAL/HIGH)
- Almacena la información en una base de datos MySQL/MariaDB
- Envía notificaciones por correo electrónico
- Ejecuta verificaciones automáticas cada 4 horas (configurable)
- Proporciona comandos de administración y monitoreo

## 🏗️ Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────┐
│                    NVD Monitor System                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────┐ │
│  │   NVD API   │───▶│  NVD Monitor │───▶│  MySQL/MariaDB  │ │
│  │             │    │              │    │                 │ │
│  │ - CVE Data  │    │ - Filtering  │    │ - Vulnerabilities│ │
│  │ - CVSS      │    │ - Processing │    │ - Monitoring Logs│ │
│  │ - Metadata  │    │ - Scheduling │    │ - Statistics     │ │
│  └─────────────┘    └──────────────┘    └─────────────────┘ │
│                             │                               │
│                             ▼                               │
│                    ┌──────────────┐                         │
│                    │ Email Server │                         │
│                    │              │                         │
│                    │ - SMTP       │                         │
│                    │ - HTML Reports│                        │
│                    │ - Alerts     │                         │
│                    └──────────────┘                         │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                   System Components                         │
│                                                             │
│ • systemd service (nvd-monitor.service)                     │
│ • Configuration management (/etc/nvd-monitor/)              │
│ • Logging system (/var/log/nvd-monitor/)                   │
│ • Administrative commands (nvd-admin)                       │
│ • Backup utilities                                          │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Estructura del Sistema de Archivos

```
/opt/nvd-monitor/                     # Aplicación principal
├── nvd-monitor.py                    # Script principal
├── configure.py                      # Script de configuración
├── venv/                            # Entorno virtual Python
├── requirements.txt                 # Dependencias Python
└── README.md                        # Documentación

/etc/nvd-monitor/                     # Configuración
├── config.ini                       # Archivo de configuración principal
└── backup-config.ini                # Respaldo de configuración

/var/log/nvd-monitor/                 # Logs del sistema
├── nvd-monitor.log                   # Log principal de la aplicación
├── error.log                         # Logs de errores
└── access.log                        # Logs de acceso API

/var/lib/nvd-monitor/                 # Datos y respaldos
├── backup_*.sql                      # Respaldos de base de datos
├── cache/                           # Cache de datos NVD
└── reports/                         # Reportes generados

/usr/local/bin/                       # Comandos globales
├── nvd-monitor                       # Comando principal
└── nvd-admin                         # Comandos de administración

/etc/systemd/system/                  # Servicio del sistema
└── nvd-monitor.service               # Archivo de servicio systemd
```

## 🚀 Instalación

### Prerrequisitos

- Ubuntu 24.04 LTS
- MySQL 8.0+ o MariaDB 10.6+
- Python 3.10+
- Acceso root/sudo
- Conexión a Internet
- API Key de NVD (gratuita)

### Proceso de Instalación

1. **Descargar e instalar el sistema:**

```bash
# Clonar o descargar los archivos del sistema
wget https://github.com/juanpadiaz/nvd-monitor/archive/main.zip
unzip main.zip
cd nvd-monitor-main

# Ejecutar instalación como root
sudo bash install.sh
```

2. **Configurar el sistema:**

```bash
# El script de instalación preguntará si desea configurar ahora
# O puede ejecutar manualmente:
sudo python3 /opt/nvd-monitor/configure.py
```

3. **Obtener API Key de NVD:**

   - Visitar: https://nvd.nist.gov/developers/request-an-api-key
   - Completar el formulario de registro
   - Recibir la API key por email

4. **Configurar base de datos:**

   El script de configuración solicitará:
   - Host de la base de datos
   - Puerto (por defecto 3306)
   - Nombre de la base de datos
   - Usuario y contraseña
   - Validará la conexión y creará las tablas necesarias

5. **Configurar email:**
   
   - Servidor SMTP (ejemplo: smtp.gmail.com)
   - Puerto SMTP (ejemplo: 587)
   - Credenciales del remitente
   - Email del destinatario

6. **Iniciar el servicio:**

```bash
# Habilitar e iniciar el servicio
sudo systemctl enable nvd-monitor
sudo systemctl start nvd-monitor

# Verificar estado
sudo systemctl status nvd-monitor
```

## ⚙️ Configuración

### Archivo de Configuración

El archivo `/etc/nvd-monitor/config.ini` contiene todas las configuraciones:

```ini
[database]
host = localhost
port = 3306
database = nvd_monitor
user = nvd_user
password = secure_password

[nvd]
api_key = tu-api-key-aqui

[email]
smtp_server = smtp.gmail.com
smtp_port = 587
sender_email = monitor@tudominio.com
sender_password = password-aplicacion
recipient_email = admin@tudominio.com

[monitoring]
check_interval_hours = 4

[logging]
level = INFO
file = /var/log/nvd-monitor/nvd-monitor.log
```

### Parámetros de Configuración

| Sección | Parámetro | Descripción | Predeterminado |
|---------|-----------|-------------|----------------|
| database | host | Servidor de base de datos | localhost |
| database | port | Puerto de conexión | 3306 |
| database | database | Nombre de la base de datos | nvd_monitor |
| database | user | Usuario de la base de datos | - |
| database | password | Contraseña de la base de datos | - |
| nvd | api_key | API Key de NVD | - |
| email | smtp_server | Servidor SMTP | smtp.gmail.com |
| email | smtp_port | Puerto SMTP | 587 |
| email | sender_email | Email del remitente | - |
| email | sender_password | Contraseña del remitente | - |
| email | recipient_email | Email del destinatario | - |
| monitoring | check_interval_hours | Intervalo de verificación | 4 |
| logging | level | Nivel de logging | INFO |
| logging | file | Archivo de log | /var/log/nvd-monitor/nvd-monitor.log |

## 🔧 Comandos de Administración

### Comandos Principales

```bash
# Probar conexiones
nvd-monitor --test-db              # Probar base de datos
nvd-monitor --test-email           # Probar email
nvd-monitor --test-nvd             # Probar NVD API

# Ejecutar manualmente
nvd-monitor --run-once             # Ejecutar una verificación
nvd-monitor --daemon               # Ejecutar como daemon
```

### Comandos Administrativos Avanzados

```bash
# Instalar comando administrativo (crear nvd-admin)
sudo cp /opt/nvd-monitor/admin-commands.py /usr/local/bin/nvd-admin
sudo chmod +x /usr/local/bin/nvd-admin
sudo pip3 install tabulate  # Para mostrar tablas

# Usar comandos administrativos
nvd-admin test-all                 # Probar todas las conexiones
nvd-admin show-vulns --limit 20    # Mostrar últimas vulnerabilidades
nvd-admin show-vulns --severity CRITICAL  # Solo críticas
nvd-admin stats                    # Mostrar estadísticas
nvd-admin logs --limit 50          # Mostrar logs
nvd-admin config                   # Mostrar configuración
nvd-admin check                    # Ejecutar verificación manual
nvd-admin backup                   # Crear respaldo de BD
```

### Gestión del Servicio

```bash
# Control del servicio
sudo systemctl start nvd-monitor      # Iniciar
sudo systemctl stop nvd-monitor       # Detener
sudo systemctl restart nvd-monitor    # Reiniciar
sudo systemctl status nvd-monitor     # Ver estado

# Logs del servicio
sudo journalctl -u nvd-monitor -f     # Ver logs en tiempo real
sudo journalctl -u nvd-monitor --since "1 hour ago"  # Logs de la última hora
```

## 📊 Monitoreo y Logs

### Archivos de Log

- **Aplicación**: `/var/log/nvd-monitor/nvd-monitor.log`
- **Sistema**: `journalctl -u nvd-monitor`
- **Errores**: Incluidos en los logs principales

### Verificación de Estado

```bash
# Estado general del sistema
systemctl status nvd-monitor

# Últimas vulnerabilidades detectadas
nvd-admin show-vulns --limit 10

# Estadísticas del sistema
nvd-admin stats

# Verificar conectividad
nvd-admin test-all
```

## 🛠️ Mantenimiento

### Respaldos Regulares

```bash
# Crear respaldo manual
nvd-admin backup

# Respaldo con nombre específico
nvd-admin backup --output /backup/nvd-$(date +%Y%m%d).sql

# Automatizar respaldos (agregar a crontab)
0 2 * * 0 /usr/local/bin/nvd-admin backup
```

### Limpieza de Logs

```bash
# Rotar logs (agregar a logrotate)
sudo nano /etc/logrotate.d/nvd-monitor

# Contenido del archivo logrotate:
/var/log/nvd-monitor/*.log {
    daily
    missingok
    rotate 30
    compress
    notifempty
    create 644 nvd-monitor nvd-monitor
    postrotate
        systemctl reload nvd-monitor || true
    endscript
}
```

### Actualizaciones

```bash
# Actualizar dependencias
sudo /opt/nvd-monitor/venv/bin/pip install --upgrade -r /opt/nvd-monitor/requirements.txt

# Reiniciar servicio después de actualizaciones
sudo systemctl restart nvd-monitor
```

## 🔍 Solución de Problemas

### Problemas Comunes

1. **Error de conexión a base de datos:**
```bash
nvd-admin test-db
# Verificar credenciales en /etc/nvd-monitor/config.ini
# Verificar que MySQL/MariaDB esté ejecutándose
sudo systemctl status mysql
```

2. **Error de API de NVD:**
```bash
nvd-admin test-nvd
# Verificar API key válida
# Verificar conectividad a internet
# Revisar límites de rate (120 requests por minuto con API key)
```

3. **Error de envío de email:**
```bash
nvd-admin test-email
# Verificar credenciales SMTP
# Para Gmail: usar contraseña de aplicación
# Verificar configuración de firewall
```

4. **Servicio no inicia:**
```bash
sudo journalctl -u nvd-monitor --since "10 minutes ago"
# Revisar permisos de archivos
sudo chown -R nvd-monitor:nvd-monitor /opt/nvd-monitor
# Verificar configuración
nvd-admin config
```

### Logs de Diagnóstico

```bash
# Ver logs detallados
sudo journalctl -u nvd-monitor -f

# Aumentar nivel de logging
sudo nano /etc/nvd-monitor/config.ini
# Cambiar level = DEBUG
sudo systemctl restart nvd-monitor
```

## 📧 Formato de Notificaciones

Las notificaciones por email incluyen:

- **Asunto**: "Alertas de Vulnerabilidades Críticas - YYYY-MM-DD HH:MM"
- **Contenido HTML** con:
  - Número total de vulnerabilidades detectadas
  - Detalles de cada CVE (ID, puntuación CVSS, descripción)
  - Productos afectados
  - Enlaces a referencias
  - Clasificación por severidad (crítica/alta)

## 🔐 Seguridad

### Buenas Prácticas

1. **Permisos de archivos:**
```bash
# Configuración solo readable por owner
chmod 600 /etc/nvd-monitor/config.ini
# Usuario del sistema sin shell
usermod -s /bin/false nvd-monitor
```

2. **Base de datos:**
   - Usuario dedicado con permisos mínimos
   - Conexiones solo desde localhost
   - Respaldos regulares encriptados

3. **Email:**
   - Usar contraseñas de aplicación específicas
   - Configurar SPF/DKIM en el dominio
   - Monitorear logs de envío

4. **API:**
   - Proteger API key de NVD
   - Monitorear límites de rate
   - Usar HTTPS para todas las conexiones

## 📈 Escalabilidad

### Para Entornos Grandes

1. **Base de datos:**
   - Usar MySQL/MariaDB dedicado
   - Configurar índices adicionales
   - Implementar particionado por fechas

2. **Múltiples instancias:**
   - Configurar diferentes intervalos
   - Balancear carga de API requests
   - Centralizar base de datos

3. **Monitoreo avanzado:**
   - Integrar con Prometheus/Grafana
   - Alertas por Slack/Teams
   - Dashboard de métricas

## 📚 Referencias

- [NVD API Documentation](https://nvd.nist.gov/developers)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [Ubuntu 24.04 Documentation](https://ubuntu.com/server/docs)
- [MySQL 8.0 Reference](https://dev.mysql.com/doc/refman/8.0/en/)
- [Python MySQL Connector](https://dev.mysql.com/doc/connector-python/en/)

## 🤝 Soporte

Para reportar problemas o solicitar características:

1. Revisar los logs de diagnóstico
2. Ejecutar comandos de prueba
3. Verificar configuración
4. Consultar documentación de APIs externos

---

### Información de Contacto

- Desarrollador: Juan Pablo Díaz Ezcurdia [jpdiaz.com](https://jpdiaz.com/)
- Versión: 1.0.0
- Licencia: LGPL-2.1 license
- Última actualización: Julio 2025

Nota: Este sistema está diseñado para complementar, no reemplazar, las herramientas de seguridad existentes. Siempre valide los resultados y mantenga actualizadas las fuentes de threat intelligence.
