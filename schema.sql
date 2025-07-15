-- Schema de Base de Datos para NVD Monitor
-- Compatible con MySQL 8.0+

-- Crear base de datos
CREATE DATABASE IF NOT EXISTS nvd_monitor 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE nvd_monitor;

-- Tabla principal de vulnerabilidades
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    description TEXT,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    base_score DECIMAL(3,1) NOT NULL,
    vector_string TEXT,
    published_date DATETIME,
    last_modified DATETIME,
    references JSON,
    cwe_id VARCHAR(20),
    exploit_code BOOLEAN DEFAULT FALSE,
    zero_day BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Índices para optimizar consultas
    INDEX idx_severity (severity),
    INDEX idx_base_score (base_score),
    INDEX idx_published_date (published_date),
    INDEX idx_created_at (created_at),
    INDEX idx_exploit_code (exploit_code),
    INDEX idx_zero_day (zero_day),
    INDEX idx_severity_score (severity, base_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de configuración del sistema
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de logs de ejecución
CREATE TABLE IF NOT EXISTS execution_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    execution_start DATETIME NOT NULL,
    execution_end DATETIME,
    status ENUM('RUNNING', 'SUCCESS', 'ERROR') NOT NULL,
    vulnerabilities_found INT DEFAULT 0,
    vulnerabilities_processed INT DEFAULT 0,
    error_message TEXT,
    duration_seconds INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_execution_start (execution_start),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de notificaciones enviadas
CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    notification_type ENUM('EMAIL', 'WEBHOOK', 'SMS') NOT NULL,
    recipient VARCHAR(255) NOT NULL,
    subject VARCHAR(500),
    content TEXT,
    status ENUM('PENDING', 'SENT', 'FAILED') NOT NULL,
    sent_at DATETIME,
    error_message TEXT,
    vulnerability_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_status (status),
    INDEX idx_sent_at (sent_at),
    INDEX idx_notification_type (notification_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de análisis de tendencias
CREATE TABLE IF NOT EXISTS vulnerability_trends (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date_analyzed DATE NOT NULL,
    total_vulnerabilities INT DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    zero_day_count INT DEFAULT 0,
    exploit_available_count INT DEFAULT 0,
    avg_cvss_score DECIMAL(3,1),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_date (date_analyzed),
    INDEX idx_date_analyzed (date_analyzed)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de keywords para detección de zero-days
CREATE TABLE IF NOT EXISTS zero_day_keywords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    keyword VARCHAR(100) NOT NULL,
    category ENUM('EXPLOIT', 'ZERO_DAY', 'POC', 'WEAPONIZED') NOT NULL,
    weight INT DEFAULT 1,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_keyword (keyword),
    INDEX idx_category (category),
    INDEX idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabla de fuentes de exploits
CREATE TABLE IF NOT EXISTS exploit_sources (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    source_type ENUM('EXPLOIT_DB', 'GITHUB', 'METASPLOIT', 'PACKETSTORM', 'OTHER') NOT NULL,
    reliability_score INT DEFAULT 50,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_domain (domain),
    INDEX idx_source_type (source_type),
    INDEX idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insertar configuración inicial
INSERT INTO system_config (config_key, config_value, description) VALUES
('last_check_time', '', 'Timestamp de la última verificación exitosa'),
('api_rate_limit', '50', 'Límite de requests por minuto a la API de NVD'),
('max_vulnerabilities_per_check', '2000', 'Máximo número de vulnerabilidades a procesar por verificación'),
('email_notification_enabled', 'true', 'Habilitar notificaciones por email'),
('webhook_notification_enabled', 'false', 'Habilitar notificaciones por webhook'),
('minimum_cvss_score', '7.0', 'Score CVSS mínimo para considerar una vulnerabilidad'),
('zero_day_detection_enabled', 'true', 'Habilitar detección automática de zero-days')
ON DUPLICATE KEY UPDATE config_value = VALUES(config_value);

-- Insertar keywords para detección de zero-days
INSERT INTO zero_day_keywords (keyword, category, weight) VALUES
('zero-day', 'ZERO_DAY', 10),
('zero day', 'ZERO_DAY', 10),
('0-day', 'ZERO_DAY', 10),
('0day', 'ZERO_DAY', 10),
('exploit', 'EXPLOIT', 5),
('poc', 'POC', 3),
('proof of concept', 'POC', 3),
('proof-of-concept', 'POC', 3),
('weaponized', 'WEAPONIZED', 8),
('in the wild', 'EXPLOIT', 7),
('actively exploited', 'EXPLOIT', 9),
('exploit available', 'EXPLOIT', 6),
('metasploit', 'EXPLOIT', 4),
('exploit-db', 'EXPLOIT', 4)
ON DUPLICATE KEY UPDATE weight = VALUES(weight);

-- Insertar fuentes de exploits conocidas
INSERT INTO exploit_sources (domain, source_type, reliability_score) VALUES
('exploit-db.com', 'EXPLOIT_DB', 90),
('github.com', 'GITHUB', 70),
('metasploit.com', 'METASPLOIT', 95),
('packetstormsecurity.com', 'PACKETSTORM', 80),
('rapid7.com', 'METASPLOIT', 90),
('zerodayinitiative.com', 'OTHER', 95),
('googleprojectzero.blogspot.com', 'OTHER', 95)
ON DUPLICATE KEY UPDATE reliability_score = VALUES(reliability_score);

-- Crear vistas útiles para consultas frecuentes

-- Vista de vulnerabilidades críticas recientes
CREATE OR REPLACE VIEW critical_vulnerabilities AS
SELECT 
    v.*,
    CASE 
        WHEN v.exploit_code = TRUE THEN 'SÍ'
        ELSE 'NO'
    END as has_exploit,
    CASE 
        WHEN v.zero_day = TRUE THEN 'SÍ'
        ELSE 'NO'
    END as is_zero_day,
    DATEDIFF(NOW(), v.published_date) as days_since_published
FROM vulnerabilities v
WHERE v.severity IN ('CRITICAL', 'HIGH')
ORDER BY v.base_score DESC, v.published_date DESC;

-- Vista de estadísticas diarias
CREATE OR REPLACE VIEW daily_stats AS
SELECT 
    DATE(created_at) as date,
    COUNT(*) as total_vulnerabilities,
    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
    SUM(CASE WHEN exploit_code = TRUE THEN 1 ELSE 0 END) as exploit_count,
    SUM(CASE WHEN zero_day = TRUE THEN 1 ELSE 0 END) as zero_day_count,
    AVG(base_score) as avg_cvss_score
FROM vulnerabilities
GROUP BY DATE(created_at)
ORDER BY date DESC;

-- Vista de vulnerabilidades con exploits
CREATE OR REPLACE VIEW exploitable_vulnerabilities AS
SELECT 
    v.*,
    'Exploit disponible' as risk_level,
    DATEDIFF(NOW(), v.published_date) as days_since_published
FROM vulnerabilities v
WHERE v.exploit_code = TRUE
ORDER BY v.base_score DESC, v.published_date DESC;

-- Procedimientos almacenados útiles

DELIMITER //

-- Procedimiento para limpiar datos antiguos
CREATE PROCEDURE CleanOldData(IN days_to_keep INT)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;
    
    START TRANSACTION;
    
    -- Limpiar logs de ejecución antiguos
    DELETE FROM execution_logs 
    WHERE created_at < DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    
    -- Limpiar notificaciones antiguas
    DELETE FROM notifications 
    WHERE created_at < DATE_SUB(NOW(), INTERVAL days_to_keep DAY)
    AND status = 'SENT';
    
    -- Limpiar tendencias muy antiguas (mantener solo 1 año)
    DELETE FROM vulnerability_trends 
    WHERE date_analyzed < DATE_SUB(CURDATE(), INTERVAL 365 DAY);
    
    COMMIT;
    
    SELECT CONCAT('Limpieza completada: datos anteriores a ', days_to_keep, ' días eliminados') as result;
END //

-- Procedimiento para calcular estadísticas diarias
CREATE PROCEDURE CalculateDailyTrends(IN analysis_date DATE)
BEGIN
    INSERT INTO vulnerability_trends (
        date_analyzed, 
        total_vulnerabilities, 
        critical_count, 
        high_count, 
        medium_count, 
        low_count, 
        zero_day_count, 
        exploit_available_count, 
        avg_cvss_score
    )
    SELECT 
        analysis_date,
        COUNT(*),
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END),
        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END),
        SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END),
        SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END),
        SUM(CASE WHEN zero_day = TRUE THEN 1 ELSE 0 END),
        SUM(CASE WHEN exploit_code = TRUE THEN 1 ELSE 0 END),
        AVG(base_score)
    FROM vulnerabilities
    WHERE DATE(created_at) = analysis_date
    ON DUPLICATE KEY UPDATE
        total_vulnerabilities = VALUES(total_vulnerabilities),
        critical_count = VALUES(critical_count),
        high_count = VALUES(high_count),
        medium_count = VALUES(medium_count),
        low_count = VALUES(low_count),
        zero_day_count = VALUES(zero_day_count),
        exploit_available_count = VALUES(exploit_available_count),
        avg_cvss_score = VALUES(avg_cvss_score);
END //

-- Función para calcular score de riesgo
CREATE FUNCTION CalculateRiskScore(
    cvss_score DECIMAL(3,1),
    has_exploit BOOLEAN,
    is_zero_day BOOLEAN,
    days_since_published INT
) RETURNS INT
READS SQL DATA
DETERMINISTIC
BEGIN
    DECLARE risk_score INT DEFAULT 0;
    
    -- Score base según CVSS
    SET risk_score = ROUND(cvss_score * 10);
    
    -- Bonificación por exploit disponible
    IF has_exploit THEN
        SET risk_score = risk_score + 20;
    END IF;
    
    -- Bonificación por zero-day
    IF is_zero_day THEN
        SET risk_score = risk_score + 30;
    END IF;
    
    -- Penalización por antigüedad (reduce riesgo con el tiempo)
    IF days_since_published > 30 THEN
        SET risk_score = risk_score - (days_since_published - 30);
    END IF;
    
    -- Asegurar que esté en rango 0-100
    IF risk_score > 100 THEN
        SET risk_score = 100;
    ELSEIF risk_score < 0 THEN
        SET risk_score = 0;
    END IF;
    
    RETURN risk_score;
END //

DELIMITER ;

-- Crear triggers para auditoría

-- Trigger para actualizar estadísticas al insertar vulnerabilidad
DELIMITER //
CREATE TRIGGER after_vulnerability_insert
AFTER INSERT ON vulnerabilities
FOR EACH ROW
BEGIN
    -- Registrar en logs si es una vulnerabilidad crítica
    IF NEW.severity IN ('CRITICAL', 'HIGH') THEN
        INSERT INTO execution_logs (
            execution_start,
            execution_end,
            status,
            vulnerabilities_found,
            vulnerabilities_processed
        ) VALUES (
            NOW(),
            NOW(),
            'SUCCESS',
            1,
            1
        );
    END IF;
    
    -- Calcular tendencias para hoy
    CALL CalculateDailyTrends(CURDATE());
END //
DELIMITER ;

-- Crear usuario específico para la aplicación (ejecutar como root)
-- CREATE USER IF NOT EXISTS 'nvd_user'@'localhost' IDENTIFIED BY 'secure_password_here';
-- GRANT SELECT, INSERT, UPDATE, DELETE ON nvd_monitor.* TO 'nvd_user'@'localhost';
-- GRANT EXECUTE ON nvd_monitor.* TO 'nvd_user'@'localhost';
-- FLUSH PRIVILEGES;

-- Crear índices adicionales para optimización
CREATE INDEX idx_vulnerability_risk ON vulnerabilities (severity, base_score, exploit_code, zero_day);
CREATE INDEX idx_created_date ON vulnerabilities (DATE(created_at));
CREATE INDEX idx_cwe_id ON vulnerabilities (cwe_id);

-- Comentarios sobre el esquema
ALTER TABLE vulnerabilities COMMENT = 'Tabla principal que almacena todas las vulnerabilidades detectadas por NVD Monitor';
ALTER TABLE system_config COMMENT = 'Configuración del sistema almacenada en base de datos';
ALTER TABLE execution_logs COMMENT = 'Logs de cada ejecución del monitor para auditoría';
ALTER TABLE notifications COMMENT = 'Registro de todas las notificaciones enviadas';
ALTER TABLE vulnerability_trends COMMENT = 'Estadísticas diarias de vulnerabilidades para análisis de tendencias';
ALTER TABLE zero_day_keywords COMMENT = 'Keywords utilizadas para detectar automáticamente zero-days';
ALTER TABLE exploit_sources COMMENT = 'Dominios y fuentes conocidas que publican exploits';
