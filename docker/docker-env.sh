# Archivo de ejemplo de variables de entorno para NVD Monitor Docker
# Copiar a .env y configurar con sus valores

# ===== CONFIGURACIÓN DE NVD API =====
# Obtener en: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=your-nvd-api-key-here

# ===== CONFIGURACIÓN DE EMAIL =====
# Servidor SMTP (ejemplos: smtp.gmail.com, smtp-mail.outlook.com, smtp.office365.com)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587

# Credenciales del remitente
# Para Gmail: usar contraseña de aplicación, no la contraseña regular
# Generar en: https://myaccount.google.com/apppasswords
SENDER_EMAIL=alerts@yourdomain.com
SENDER_PASSWORD=your-app-password-here

# Destinatarios (separar múltiples con comas)
RECIPIENT_EMAIL=admin@yourdomain.com,security@yourdomain.com

# ===== CONFIGURACIÓN DE MONITOREO =====
# Intervalo de verificación en horas (por defecto: 4)
CHECK_INTERVAL=4

# ===== CONFIGURACIÓN DE BASE DE DATOS =====
# Contraseña root de MySQL/MariaDB (se genera automáticamente si no se especifica)
DB_ROOT_PASSWORD=strong_password_here

# ===== CONFIGURACIÓN DE SISTEMA =====
# Timezone (por defecto: UTC)
TZ=America/Mexico_City

# ===== RUTAS DE DATOS (OPCIONAL) =====
# Por defecto se crean en ./data/
# DATA_PATH=./data/mysql
# CONFIG_PATH=./data/config
# LOGS_PATH=./data/logs
# BACKUPS_PATH=./data/backups