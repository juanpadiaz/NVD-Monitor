# 🐳 NVD Monitor - Guía de Docker

## Inicio Rápido

### 1. Configuración Básica

```bash
# Clonar el repositorio
git clone https://github.com/juanpadiaz/nvd-monitor.git
cd nvd-monitor/docker

# Copiar archivo de variables de entorno
cp .env.example .env

# Editar .env con tus valores
nano .env
```

### 2. Construcción y Ejecución

```bash
# Construir la imagen
docker build -t nvd-monitor:latest .

# Ejecutar con docker-compose (recomendado)
docker-compose up -d

# O ejecutar directamente con docker
docker run -d \
  --name nvd-monitor \
  --env-file .env \
  -v nvd-data:/var/lib/mysql \
  -v nvd-logs:/var/log/nvd-monitor \
  nvd-monitor:latest
```

## 📋 Variables de Entorno Requeridas

| Variable | Descripción | Ejemplo |
|----------|-------------|---------|
| `NVD_API_KEY` | API Key de NVD (opcional pero recomendado) | `abcd1234-5678-90ef-ghij-klmnopqrstuv` |
| `SENDER_EMAIL` | Email remitente para alertas | `alerts@tudominio.com` |
| `SENDER_PASSWORD` | Contraseña del email remitente | `app-password-123` |
| `RECIPIENT_EMAIL` | Email(s) destinatario(s) | `admin@tudominio.com,security@tudominio.com` |

## 🔧 Comandos Útiles

### Ver logs
```bash
# Logs en tiempo real
docker logs -f nvd-monitor

# Últimas 100 líneas
docker logs --tail 100 nvd-monitor
```

### Ejecutar comandos administrativos
```bash
# Estado del sistema
docker exec nvd-monitor nvd-admin status

# Probar email
docker exec nvd-monitor nvd-admin test-email

# Ver vulnerabilidades
docker exec nvd-monitor nvd-admin show-vulns --limit 10

# Ejecutar verificación manual
docker exec nvd-monitor nvd-monitor --run-once
```

### Gestión del contenedor
```bash
# Detener
docker-compose stop

# Iniciar
docker-compose start

# Reiniciar
docker-compose restart

# Eliminar (preserva volúmenes)
docker-compose down

# Eliminar todo (incluye volúmenes)
docker-compose down -v
```

## 📁 Persistencia de Datos

Los siguientes directorios son persistentes mediante volúmenes Docker:

- `/var/lib/mysql` - Base de datos MySQL
- `/etc/nvd-monitor` - Configuración
- `/var/log/nvd-monitor` - Logs
- `/var/lib/nvd-monitor/backups` - Respaldos

### Acceder a los datos localmente

Con docker-compose, los datos se almacenan en:
```
./data/
├── mysql/       # Base de datos
├── config/      # Configuración
├── logs/        # Logs
└── backups/     # Respaldos
```

## 🔒 Seguridad

### Mejores Prácticas

1. **Nunca commits el archivo .env** - Contiene credenciales sensibles
2. **Usa contraseñas fuertes** - Especialmente para la base de datos
3. **Limita los recursos** - Ajusta los límites en docker-compose.yml
4. **Actualiza regularmente** - Mantén la imagen actualizada

### Configuración de red segura

El docker-compose.yml incluye una red aislada por defecto. Para mayor seguridad:

```yaml
# Agregar al docker-compose.yml
services:
  nvd-monitor:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /run
```

## 🔍 Troubleshooting

### El contenedor no inicia

```bash
# Ver logs detallados
docker logs nvd-monitor

# Verificar que los directorios de datos existan
mkdir -p data/{mysql,config,logs,backups}

# Verificar permisos
ls -la data/
```

### Error de conexión a base de datos

```bash
# Verificar que MySQL esté ejecutándose
docker exec nvd-monitor supervisorctl status

# Probar conexión
docker exec nvd-monitor nvd-admin test-db
```

### No se envían emails

```bash
# Verificar configuración
docker exec nvd-monitor cat /etc/nvd-monitor/config.ini | grep email

# Probar envío
docker exec nvd-monitor nvd-admin test-email
```

## 🚀 Producción

### Health Check

El contenedor incluye un health check automático. Verificar estado:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

### Monitoreo

Para integrar con sistemas de monitoreo:

```bash
# Prometheus metrics (futuro)
curl http://localhost:9090/metrics

# Health endpoint (futuro)
curl http://localhost:9090/health
```

### Backup automatizado

Habilitar el servicio de backup:

```bash
docker-compose --profile backup up -d
```

## 📊 Métricas y Logs

### Configurar logging externo

```yaml
# docker-compose.yml
services:
  nvd-monitor:
    logging:
      driver: syslog
      options:
        syslog-address: "tcp://192.168.1.100:514"
        tag: "nvd-monitor"
```

### Rotar logs automáticamente

Los logs se rotan automáticamente dentro del contenedor. Para acceder:

```bash
# Ver logs rotados
docker exec nvd-monitor ls -la /var/log/nvd-monitor/
```

## 🔄 Actualización

```bash
# 1. Detener el contenedor
docker-compose stop

# 2. Actualizar el código
git pull

# 3. Reconstruir la imagen
docker-compose build --no-cache

# 4. Iniciar con la nueva versión
docker-compose up -d
```

## 🆘 Soporte

Para problemas específicos de Docker:

1. Verificar los logs completos
2. Revisar la configuración en .env
3. Confirmar que los volúmenes tienen los permisos correctos
4. Abrir un issue en GitHub con los detalles

---

**Nota**: Para instalación sin Docker, consulta el README principal del proyecto.
