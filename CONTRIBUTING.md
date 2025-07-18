# Guía de Contribución

¡Gracias por tu interés en contribuir a NVD Monitor! 🎉

## 📋 Tabla de Contenidos

- [Código de Conducta](#código-de-conducta)
- [¿Cómo puedo contribuir?](#cómo-puedo-contribuir)
- [Configuración del entorno](#configuración-del-entorno)
- [Proceso de desarrollo](#proceso-de-desarrollo)
- [Estándares de código](#estándares-de-código)
- [Tests](#tests)
- [Documentación](#documentación)

## Código de Conducta

Este proyecto adhiere al código de conducta de [Contributor Covenant](https://www.contributor-covenant.org/). Al participar, se espera que mantengas este código.

## ¿Cómo puedo contribuir?

### 🐛 Reportar Bugs

Antes de crear un issue:
- Verifica que no exista ya un issue similar
- Usa la plantilla de bug report
- Incluye información detallada del entorno
- Proporciona pasos para reproducir el problema

### 💡 Sugerir Mejoras

- Usa la plantilla de feature request
- Explica claramente el problema que resuelve
- Describe la solución propuesta
- Considera alternativas

### 🔧 Contribuir Código

1. **Fork** el repositorio
2. **Crea** una rama para tu feature (`git checkout -b feature/amazing-feature`)
3. **Implementa** tus cambios
4. **Añade** tests para nuevas funcionalidades
5. **Asegúrate** de que todos los tests pasen
6. **Commit** tus cambios (`git commit -m 'Add amazing feature'`)
7. **Push** a la rama (`git push origin feature/amazing-feature`)
8. **Abre** un Pull Request

## Configuración del entorno

### Prerrequisitos

- Ubuntu 24.04 LTS (recomendado)
- Python 3.10+
- MySQL 8.0+ o MariaDB 10.6+
- Git

### Setup para desarrollo

```bash
# 1. Fork y clonar
git clone https://github.com/tu-usuario/nvd-monitor.git
cd nvd-monitor

# 2. Crear entorno virtual
python3 -m venv dev-venv
source dev-venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 4. Configurar pre-commit hooks
pre-commit install

# 5. Ejecutar tests
python -m pytest tests/
```

### Herramientas de desarrollo

```bash
# Instalar herramientas de calidad de código
pip install black pylint mypy pytest pytest-cov

# Formatear código
black src/

# Linting
pylint src/

# Type checking
mypy src/

# Tests con cobertura
pytest --cov=src tests/
```

## Proceso de desarrollo

### Branching Strategy

- `main` - Código estable en producción
- `develop` - Rama de desarrollo principal
- `feature/*` - Nuevas funcionalidades
- `bugfix/*` - Corrección de bugs
- `hotfix/*` - Fixes urgentes para producción

### Commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

body (opcional)

footer (opcional)
```

**Tipos:**
- `feat` - Nueva funcionalidad
- `fix` - Corrección de bug
- `docs` - Cambios en documentación
- `style` - Formateo, sin cambios de código
- `refactor` - Refactoring de código
- `test` - Añadir o modificar tests
- `chore` - Mantenimiento

**Ejemplos:**
```
feat(monitor): add zero-day detection algorithm
fix(email): resolve SMTP connection timeout
docs(readme): update installation instructions
```

## Estándares de código

### Python

- **Formato**: Black (line length: 88)
- **Linting**: Pylint (score mínimo: 8.0)
- **Type hints**: Obligatorio para funciones públicas
- **Docstrings**: Google style para clases y funciones públicas

```python
def process_vulnerability(cve_data: Dict[str, Any]) -> Optional[Vulnerability]:
    """Process CVE data into internal vulnerability format.
    
    Args:
        cve_data: Raw CVE data from NVD API
        
    Returns:
        Processed vulnerability object or None if invalid
        
    Raises:
        ValidationError: If CVE data format is invalid
    """
    pass
```

### Estructura de archivos

```
src/
├── nvd_monitor/
│   ├── __init__.py
│   ├── core/           # Lógica principal
│   ├── api/            # Clientes de API
│   ├── database/       # Capa de datos
│   ├── notifications/  # Sistema de alertas
│   └── utils/          # Utilidades
tests/
├── unit/               # Tests unitarios
├── integration/        # Tests de integración
└── fixtures/           # Datos de prueba
```

## Tests

### Tipos de tests

1. **Unit tests** - Funciones individuales
2. **Integration tests** - Componentes integrados
3. **System tests** - Sistema completo
4. **Performance tests** - Rendimiento

### Ejecutar tests

```bash
# Todos los tests
pytest

# Tests específicos
pytest tests/unit/test_monitor.py

# Con cobertura
pytest --cov=src --cov-report=html

# Tests de integración (requiere BD)
pytest tests/integration/ --db-url=mysql://user:pass@localhost/test_db
```

### Escribir tests

```python
import pytest
from nvd_monitor.core.monitor import NVDMonitor

class TestNVDMonitor:
    
    def test_filter_critical_vulnerabilities(self):
        """Test filtering of critical vulnerabilities."""
        monitor = NVDMonitor()
        vulns = [
            {"cvss_severity": "CRITICAL", "cvss_score": 9.8},
            {"cvss_severity": "LOW", "cvss_score": 2.1},
        ]
        
        filtered = monitor.filter_vulnerabilities(vulns)
        
        assert len(filtered) == 1
        assert filtered[0]["cvss_severity"] == "CRITICAL"
```

## Documentación

### Actualizar documentación

- README.md para cambios de instalación/uso
- docs/ para documentación técnica detallada
- Comentarios en código para lógica compleja
- CHANGELOG.md para todos los cambios

### Generar documentación

```bash
# Documentación de API
pdoc --html src/nvd_monitor

# Documentación de esquema de BD
schemaspy -t mysql -host localhost -db nvd_monitor -u user -p password -o docs/db
```

## Pull Request Process

### Checklist antes de enviar

- [ ] Código formateado con Black
- [ ] Pylint score ≥ 8.0
- [ ] Todos los tests pasan
- [ ] Cobertura de tests ≥ 90% para nuevo código
- [ ] Documentación actualizada
- [ ] CHANGELOG.md actualizado
- [ ] Type hints añadidos
- [ ] Tests añadidos para nueva funcionalidad

### Template de PR

```markdown
## Descripción
Descripción clara de los cambios realizados.

## Tipo de cambio
- [ ] Bug fix
- [ ] Nueva funcionalidad
- [ ] Breaking change
- [ ] Actualización de documentación

## ¿Cómo ha sido probado?
Describe las pruebas realizadas.

## Checklist
- [ ] Mi código sigue las convenciones del proyecto
- [ ] He realizado self-review de mi código
- [ ] He añadido tests que prueban mi cambio
- [ ] Todos los tests existentes pasan
- [ ] He actualizado la documentación
```

## Áreas de contribución

### 🔧 Desarrollo

- Nuevas funcionalidades
- Optimización de rendimiento
- Corrección de bugs
- Refactoring de código

### 📚 Documentación

- Mejorar README y guías
- Crear tutoriales
- Traducir documentación
- Documentar APIs

### 🧪 Testing

- Añadir tests unitarios
- Crear tests de integración
- Automatizar tests
- Performance testing

### 🎨 UX/UI

- Mejorar mensajes de error
- Optimizar CLI interface
- Crear dashboard web
- Mejorar reportes HTML

### 🔒 Seguridad

- Auditorías de seguridad
- Mejorar validación
- Hardening del sistema
- Documentar mejores prácticas

## Reconocimientos

Los contribuidores serán reconocidos en:
- README.md
- CONTRIBUTORS.md
- Release notes
- Commits y PRs

¡Gracias por contribuir a NVD Monitor! 🚀
