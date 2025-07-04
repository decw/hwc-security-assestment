# Crear una clase base para manejar credenciales multi-región
# utils/multi_region_client.py

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from config.settings import (
    HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY,
    REGION_PROJECT_MAPPING, REGION_DISPLAY_NAMES
)
from utils.logger import SecurityLogger

class MultiRegionClient:
    """Clase base para manejar clientes multi-región con diferentes project IDs"""
    
    def __init__(self):
        self.logger = SecurityLogger(self.__class__.__name__)
        self.credentials_cache = {}
        
    def get_credentials_for_region(self, region: str) -> BasicCredentials:
        """Obtener credenciales con el project_id correcto para la región"""
        if region not in self.credentials_cache:
            project_id = REGION_PROJECT_MAPPING.get(region)
            
            if not project_id:
                raise ValueError(f"No se encontró project_id para región {region}")
            
            self.credentials_cache[region] = BasicCredentials(
                HUAWEI_ACCESS_KEY,
                HUAWEI_SECRET_KEY,
                project_id
            )
            
            self.logger.debug(f"Credenciales creadas para {REGION_DISPLAY_NAMES.get(region, region)} "
                            f"con project_id: {project_id}")
        
        return self.credentials_cache[region]
    
    def get_region_display_name(self, region: str) -> str:
        """Obtener nombre descriptivo de la región"""
        return REGION_DISPLAY_NAMES.get(region, region)