# Logger
#!/usr/bin/env python3
"""
Sistema de logging para el Assessment
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from config.settings import LOGS_DIR, LOG_LEVEL, LOG_FORMAT

class SecurityLogger:
    """Logger personalizado para el assessment de seguridad"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, LOG_LEVEL))
        
        # Evitar duplicación de handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Configurar handlers para archivo y consola"""
        # Handler para archivo
        log_file = LOGS_DIR / f"security_assessment_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(LOG_FORMAT)
        file_handler.setFormatter(file_formatter)
        
        # Handler para consola
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, LOG_LEVEL))
        console_formatter = logging.Formatter('%(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        
        # Agregar handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log_finding(self, severity: str, finding_id: str, message: str, details: dict = None):
        """Log específico para hallazgos de seguridad"""
        log_entry = {
            'finding_id': finding_id,
            'severity': severity,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        if details:
            log_entry['details'] = details
        
        if severity == 'CRITICAL':
            self.logger.critical(f"[{finding_id}] {message}", extra={'finding': log_entry})
        elif severity == 'HIGH':
            self.logger.error(f"[{finding_id}] {message}", extra={'finding': log_entry})
        elif severity == 'MEDIUM':
            self.logger.warning(f"[{finding_id}] {message}", extra={'finding': log_entry})
        else:
            self.logger.info(f"[{finding_id}] {message}", extra={'finding': log_entry})
    
    def debug(self, message: str):
        self.logger.debug(message)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def critical(self, message: str):
        self.logger.critical(message)

# Singleton para logger principal
main_logger = SecurityLogger('SecurityAssessment')