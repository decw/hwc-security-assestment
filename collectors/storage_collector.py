#!/usr/bin/env python3
"""
Colector de configuraciones de almacenamiento para Huawei Cloud
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Any
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkevs.v2 import *
from utils.multi_region_client import MultiRegionClient

# Importar OBS con manejo de errores
try:
    # Opción 1: SDK oficial más nuevo
    from huaweicloudsdkobs import ObsClient, ListBucketsRequest
    OBS_SDK_TYPE = "official"
    print("✅ Usando OBS SDK oficial")
except ImportError:
    try:
        # Opción 2: SDK legacy obs
        import obs
        OBS_SDK_TYPE = "legacy"
        print("✅ Usando OBS SDK legacy")
    except ImportError:
        obs = None
        OBS_SDK_TYPE = None
        print("⚠️ OBS SDK no disponible")

# Importar otros servicios de backup y recuperación
try:
    from huaweicloudsdkcbr.v1 import *
    CBR_AVAILABLE = True
    print("✅ CBR SDK disponible")
except ImportError:
    CBR_AVAILABLE = False
    print("⚠️ CBR SDK no disponible")

try:
    from huaweicloudsdksfsturbo import *
    SFS_AVAILABLE = True
except ImportError:
    SFS_AVAILABLE = False
    print("WARNING: SFS SDK no disponible.")

from utils.logger import SecurityLogger
from config.settings import (
    HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY,
    HUAWEI_PROJECT_ID, REGIONS
)
from config.constants import DATA_CLASSIFICATION_TAGS

class StorageCollector(MultiRegionClient):
    """Colector de configuraciones de almacenamiento y backup"""
    
    def __init__(self):
        self.logger = SecurityLogger('StorageCollector')
        self.findings = []
        self.credentials = BasicCredentials(
            HUAWEI_ACCESS_KEY,
            HUAWEI_SECRET_KEY,
            HUAWEI_PROJECT_ID
        )
    
    def _get_evs_client(self, region: str):
        """Obtener cliente EVS para una región"""
        credentials = self.get_credentials_for_region(region)
        
        return EvsClient.new_builder() \
            .with_credentials(credentials) \
            .with_region(EvsRegion.value_of(region)) \
            .build()
    
    def _get_obs_client(self):
        """Obtener cliente OBS - CORREGIDO"""
        if OBS_SDK_TYPE == "official":
            try:
                return ObsClient.new_builder() \
                    .with_credentials(self.credentials) \
                    .with_region('la-south-2') \
                    .build()
            except Exception as e:
                self.logger.error(f"Error creando cliente OBS oficial: {str(e)}")
                return None
        elif OBS_SDK_TYPE == "legacy":
            try:
                return obs.ObsClient(
                    access_key_id=HUAWEI_ACCESS_KEY,
                    secret_access_key=HUAWEI_SECRET_KEY,
                    server='https://obs.la-south-2.myhuaweicloud.com'
                )
            except Exception as e:
                self.logger.error(f"Error creando cliente OBS legacy: {str(e)}")
                return None
        else:
            self.logger.warning("OBS Client no disponible")
            return None
    
    def _get_cbr_client(self, region: str):
        """Obtener cliente CBR (reemplaza CSBS)"""
        if not CBR_AVAILABLE:
            return None
        try:
            return CbrClient.new_builder() \
                .with_credentials(self.credentials) \
                .with_region(CbrRegion.value_of(region)) \
                .build()
        except Exception as e:
            self.logger.error(f"Error creando cliente CBR: {str(e)}")
            return None

    async def collect_all(self) -> Dict[str, Any]:
        """Recolectar todos los datos de almacenamiento"""
        self.logger.info("Iniciando recolección de datos de almacenamiento")
        
        results = {
            'evs_volumes': {},
            'obs_buckets': [],
            'backups': {},
            'sfs_shares': {},
            'encryption_status': {
                'evs': {'encrypted': 0, 'unencrypted': 0},
                'obs': {'encrypted': 0, 'unencrypted': 0}
            },
            'findings': self.findings,
            'statistics': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Recolectar EVS por región
        for region in REGIONS:
            self.logger.info(f"Analizando almacenamiento en región: {region}")
            try:
                results['evs_volumes'][region] = await self._collect_evs_volumes(region)
                results['backups'][region] = await self._collect_backups(region)
                results['sfs_shares'][region] = await self._collect_sfs_shares(region)
            except Exception as e:
                self.logger.error(f"Error en región {region}: {str(e)}")
        
        # Recolectar OBS (global)
        results['obs_buckets'] = await self._collect_obs_buckets()
        
        # Calcular estadísticas
        results['statistics'] = self._calculate_statistics(results)
        
        self.logger.info(f"Recolección de almacenamiento completada. Hallazgos: {len(self.findings)}")
        return results
    
    async def _collect_evs_volumes(self, region: str) -> List[Dict]:
        """Recolectar información de volúmenes EVS"""
        volumes = []
        try:
            client = self._get_evs_client(region)
            request = ListVolumesRequest()
            response = client.list_volumes(request)
            
            for volume in response.volumes:
                volume_info = {
                    'id': volume.id,
                    'name': volume.name,
                    'size': volume.size,
                    'status': volume.status,
                    'volume_type': volume.volume_type,
                    'bootable': volume.bootable,
                    'encrypted': getattr(volume, 'encrypted', False),
                    'multiattach': volume.multiattach,
                    'availability_zone': volume.availability_zone,
                    'created_at': volume.created_at,
                    'updated_at': volume.updated_at,
                    'attachments': volume.attachments,
                    'tags': getattr(volume, 'tags', {}),
                    'metadata': getattr(volume, 'metadata', {})
                }
                
                # Verificar cifrado
                if not volume_info['encrypted']:
                    self._add_finding(
                        'STO-001',
                        'MEDIUM',
                        f'Volumen EVS sin cifrar: {volume.name}',
                        {
                            'volume_id': volume.id,
                            'size_gb': volume.size,
                            'type': volume.volume_type,
                            'region': region
                        }
                    )
                    results['encryption_status']['evs']['unencrypted'] += 1
                else:
                    results['encryption_status']['evs']['encrypted'] += 1
                
                # Verificar clasificación de datos
                if not self._has_classification_tag(volume_info['tags']):
                    self._add_finding(
                        'STO-002',
                        'LOW',
                        f'Volumen sin clasificación de datos: {volume.name}',
                        {'volume_id': volume.id, 'region': region}
                    )
                
                # Verificar volúmenes sin uso
                if not volume.attachments:
                    self._add_finding(
                        'STO-003',
                        'LOW',
                        f'Volumen sin adjuntar: {volume.name}',
                        {
                            'volume_id': volume.id,
                            'size_gb': volume.size,
                            'cost_estimate': f'${volume.size * 0.1}/mes',
                            'region': region
                        }
                    )
                
                volumes.append(volume_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando volúmenes EVS en {region}: {str(e)}")
            
        return volumes
    
    async def _collect_obs_buckets(self) -> List[Dict]:
        """Recolectar información de buckets OBS - CORREGIDO"""
        buckets = []
        
        client = self._get_obs_client()
        if client is None:
            self.logger.warning("Saltando recolección OBS - Cliente no disponible")
            return buckets
            
        try:
            if OBS_SDK_TYPE == "official":
                # Usar SDK oficial
                request = ListBucketsRequest()
                response = client.list_buckets(request)
                bucket_list = response.buckets
            else:
                # Usar SDK legacy
                response = client.listBuckets()
                if response.status < 300:
                    bucket_list = response.body.buckets
                else:
                    self.logger.error(f"Error listando buckets: {response.status}")
                    return buckets
            
            for bucket in bucket_list:
                bucket_info = {
                    'name': getattr(bucket, 'name', 'unknown'),
                    'creation_date': getattr(bucket, 'creation_date', None) or getattr(bucket, 'create_date', None),
                    'location': getattr(bucket, 'location', 'unknown'),
                    'acl': None,
                    'encryption': {'enabled': False},
                    'versioning': 'Disabled',
                    'lifecycle': False,
                    'tags': {},
                    'public_access': False,
                    'size_bytes': 0,
                    'object_count': 0
                }
                
                # Obtener detalles adicionales
                try:
                    bucket_info.update(await self._get_bucket_details(client, bucket.name))
                except Exception as e:
                    self.logger.debug(f"Error obteniendo detalles de bucket {bucket.name}: {str(e)}")
                
                # Analizar seguridad
                self._analyze_bucket_security(bucket_info)
                buckets.append(bucket_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando buckets OBS: {str(e)}")
            
        return buckets
        
    
    async def _get_bucket_details(self, client: Any, bucket_name: str) -> Dict:
        """Obtener detalles de configuración de un bucket"""
        details = {}
        
        try:
            # Obtener ACL
            acl_resp = client.getBucketAcl(bucket_name)
            if acl_resp.status < 300:
                details['acl'] = {
                    'owner': acl_resp.body.owner.owner_id,
                    'grants': []
                }
                for grant in acl_resp.body.grants:
                    details['acl']['grants'].append({
                        'grantee': str(grant.grantee),
                        'permission': grant.permission
                    })
                    # Verificar acceso público
                    if 'AllUsers' in str(grant.grantee):
                        details['public_access'] = True
            
            # Obtener estado de cifrado
            enc_resp = client.getBucketEncryption(bucket_name)
            if enc_resp.status < 300:
                details['encryption'] = {
                    'enabled': True,
                    'algorithm': enc_resp.body.encryption_configuration.rule.encryption_algorithm,
                    'kms_key': getattr(enc_resp.body.encryption_configuration.rule, 'kms_master_key_id', None)
                }
            else:
                details['encryption'] = {'enabled': False}
            
            # Obtener versionado
            ver_resp = client.getBucketVersioning(bucket_name)
            if ver_resp.status < 300:
                details['versioning'] = ver_resp.body.versioning_configuration.status
            
            # Obtener lifecycle
            life_resp = client.getBucketLifecycle(bucket_name)
            if life_resp.status < 300:
                details['lifecycle'] = len(life_resp.body.lifecycle_rules) > 0
            
            # Obtener tags
            tags_resp = client.getBucketTagging(bucket_name)
            if tags_resp.status < 300:
                details['tags'] = {tag.key: tag.value for tag in tags_resp.body.tag_set.tags}
            
            # Obtener métricas de almacenamiento
            storage_resp = client.getBucketStorageInfo(bucket_name)
            if storage_resp.status < 300:
                details['size_bytes'] = storage_resp.body.size
                details['object_count'] = storage_resp.body.object_number
                
        except Exception as e:
            self.logger.debug(f"Error obteniendo detalles de bucket {bucket_name}: {str(e)}")
            
        return details
    
    async def _collect_backups(self, region: str) -> List[Dict]:
        """Recolectar información de backups"""
        backups = []
        
        try:
            # Intentar con Cloud Server Backup Service (CSBS)
            if CSBS_AVAILABLE:
                # Implementación para CSBS
                pass
            
            # Intentar con Volume Backup Service (VBS) 
            try:
                from huaweicloudsdkvbs.v2 import VbsClient, ListBackupsRequest
                from huaweicloudsdkvbs.v2.region.vbs_region import VbsRegion
                
                # Mapear región
                region_code = self._get_region_code(region)
                
                vbs_client = VbsClient.new_builder() \
                    .with_credentials(self.credentials) \
                    .with_region(VbsRegion.value_of(region_code)) \
                    .build()
                
                request = ListBackupsRequest()
                response = vbs_client.list_backups(request)
                
                for backup in response.backups:
                    backup_info = {
                        'id': backup.id,
                        'name': backup.name,
                        'status': backup.status,
                        'volume_id': backup.volume_id,
                        'size': backup.size,
                        'created_at': backup.created_at,
                        'description': backup.description
                    }
                    backups.append(backup_info)
                    
            except ImportError:
                self.logger.warning(f"VBS SDK no disponible para región {region}")
            except Exception as e:
                self.logger.error(f"Error recolectando VBS backups en {region}: {str(e)}")
            
            # Si no se encontraron backups, buscar en CSBS
            if not backups:
                try:
                    # Intentar con CSBS si está disponible
                    if hasattr(self, '_collect_csbs_backups'):
                        csbs_backups = await self._collect_csbs_backups(region)
                        backups.extend(csbs_backups)
                except Exception as e:
                    self.logger.warning(f"Error con CSBS en {region}: {str(e)}")
            
            # Verificar si hay recursos sin backup
            if len(backups) == 0:
                self._add_finding(
                    'STO-009',
                    'HIGH',
                    f'No se encontraron backups configurados en región {region}',
                    {'region': region, 'backup_count': 0}
                )
                    
        except Exception as e:
            self.logger.error(f"Error recolectando backups en {region}: {str(e)}")
            
        return backups

    def _get_region_code(self, region_name: str) -> str:
        """Convertir nombre de región del inventario a código API"""
        region_mapping = {
            'LA-Santiago': 'la-south-2',
            'LA-Buenos Aires1': 'sa-argentina-1', 
            'CN-Hong Kong': 'ap-southeast-1',
            'AP-Bangkok': 'ap-southeast-2',
            'AP-Singapore': 'ap-southeast-3'
        }
        return region_mapping.get(region_name, region_name)
    # Inicializar variables globales si no existen
    def init_storage_collector_globals():
        """Inicializar variables globales para storage collector"""
        global CSBS_AVAILABLE, SFS_AVAILABLE
        
        try:
            import huaweicloudsdkcsbs
            CSBS_AVAILABLE = True
        except ImportError:
            CSBS_AVAILABLE = False
        
        try:
            import huaweicloudsdksfs
            SFS_AVAILABLE = True
        except ImportError:
            SFS_AVAILABLE = False
        
        return CSBS_AVAILABLE, SFS_AVAILABLE
        
    async def _collect_sfs_shares(self, region: str) -> List[Dict]:
        """Recolectar información de SFS shares"""
        shares = []
        
        try:
            if SFS_AVAILABLE:
                # Implementación para SFS
                try:
                    from huaweicloudsdksfs.v2 import SfsClient, ListSharesRequest
                    from huaweicloudsdksfs.v2.region.sfs_region import SfsRegion
                    
                    region_code = self._get_region_code(region)
                    
                    sfs_client = SfsClient.new_builder() \
                        .with_credentials(self.credentials) \
                        .with_region(SfsRegion.value_of(region_code)) \
                        .build()
                    
                    request = ListSharesRequest()
                    response = sfs_client.list_shares(request)
                    
                    for share in response.shares:
                        share_info = {
                            'id': share.id,
                            'name': share.name,
                            'size': share.size,
                            'status': share.status,
                            'share_type': share.share_type,
                            'availability_zone': share.availability_zone,
                            'created_at': share.created_at
                        }
                        
                        # Verificar configuración de seguridad
                        if not share.is_public:
                            self._add_finding(
                                'STO-010',
                                'LOW',
                                f'SFS share sin acceso público configurado: {share.name}',
                                {'share_id': share.id, 'region': region}
                            )
                        
                        shares.append(share_info)
                        
                except ImportError:
                    self.logger.warning(f"SFS SDK específico no disponible para región {region}")
                except Exception as e:
                    self.logger.error(f"Error recolectando SFS shares en {region}: {str(e)}")
            else:
                self.logger.warning(f"Saltando recolección SFS en {region} - SFS SDK no disponible")
                
        except Exception as e:
            self.logger.error(f"Error general recolectando SFS shares en {region}: {str(e)}")
            
        return shares
    
    def _analyze_bucket_security(self, bucket: Dict):
        """Analizar seguridad de un bucket OBS"""
        # Verificar acceso público
        if bucket.get('public_access'):
            self._add_finding(
                'STO-004',
                'HIGH',
                f'Bucket OBS con acceso público: {bucket["name"]}',
                {
                    'bucket_name': bucket['name'],
                    'acl_grants': bucket.get('acl', {}).get('grants', [])
                }
            )
        
        # Verificar cifrado
        if not bucket.get('encryption', {}).get('enabled'):
            self._add_finding(
                'STO-005',
                'MEDIUM',
                f'Bucket OBS sin cifrado: {bucket["name"]}',
                {
                    'bucket_name': bucket['name'],
                    'size_bytes': bucket.get('size_bytes', 0),
                    'object_count': bucket.get('object_count', 0)
                }
            )
        
        # Verificar versionado para buckets importantes
        if self._is_critical_bucket(bucket) and bucket.get('versioning') != 'Enabled':
            self._add_finding(
                'STO-006',
                'MEDIUM',
                f'Bucket crítico sin versionado: {bucket["name"]}',
                {'bucket_name': bucket['name']}
            )
        
        # Verificar lifecycle
        if not bucket.get('lifecycle') and bucket.get('size_bytes', 0) > 100 * 1024 * 1024 * 1024:  # 100GB
            self._add_finding(
                'STO-007',
                'LOW',
                f'Bucket grande sin política de lifecycle: {bucket["name"]}',
                {
                    'bucket_name': bucket['name'],
                    'size_gb': round(bucket.get('size_bytes', 0) / (1024**3), 2)
                }
            )
        
        # Verificar clasificación
        if not self._has_classification_tag(bucket.get('tags', {})):
            self._add_finding(
                'STO-008',
                'LOW',
                f'Bucket sin clasificación de datos: {bucket["name"]}',
                {'bucket_name': bucket['name']}
            )
    
    def _has_classification_tag(self, tags: Dict) -> bool:
        """Verificar si el recurso tiene tag de clasificación"""
        if not tags:
            return False
        
        classification_keys = ['Classification', 'DataClassification', 'Clasificacion']
        return any(key in tags for key in classification_keys)
    
    def _is_critical_bucket(self, bucket: Dict) -> bool:
        """Determinar si un bucket es crítico"""
        critical_keywords = ['backup', 'prod', 'critical', 'database', 'logs']
        bucket_name = bucket['name'].lower()
        return any(keyword in bucket_name for keyword in critical_keywords)
    
    def _add_finding(self, finding_id: str, severity: str, message: str, details: dict):
        """Agregar un hallazgo de seguridad"""
        finding = {
            'id': finding_id,
            'severity': severity,
            'message': message,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.findings.append(finding)
        self.logger.log_finding(severity, finding_id, message, details)
    
    def _calculate_statistics(self, results: dict) -> dict:
        """Calcular estadísticas del análisis de almacenamiento"""
        stats = {
            'total_evs_volumes': sum(len(vols) for vols in results['evs_volumes'].values()),
            'total_obs_buckets': len(results['obs_buckets']),
            'total_backups': sum(len(backups) for backups in results['backups'].values()),
            'encryption_compliance': {
                'evs': 0,
                'obs': 0,
                'overall': 0
            },
            'unattached_volumes': 0,
            'public_buckets': 0,
            'buckets_without_versioning': 0,
            'resources_without_classification': 0,
            'total_storage_gb': 0,
            'findings_by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
        }
        
        # Calcular compliance de cifrado
        evs_enc = results['encryption_status']['evs']
        if evs_enc['encrypted'] + evs_enc['unencrypted'] > 0:
            stats['encryption_compliance']['evs'] = round(
                (evs_enc['encrypted'] / (evs_enc['encrypted'] + evs_enc['unencrypted'])) * 100, 2
            )
        
        obs_enc = results['encryption_status']['obs']
        if obs_enc['encrypted'] + obs_enc['unencrypted'] > 0:
            stats['encryption_compliance']['obs'] = round(
                (obs_enc['encrypted'] / (obs_enc['encrypted'] + obs_enc['unencrypted'])) * 100, 2
            )
        
        # Compliance general
        total_enc = evs_enc['encrypted'] + obs_enc['encrypted']
        total_unenc = evs_enc['unencrypted'] + obs_enc['unencrypted']
        if total_enc + total_unenc > 0:
            stats['encryption_compliance']['overall'] = round(
                (total_enc / (total_enc + total_unenc)) * 100, 2
            )
        
        # Contar volúmenes sin adjuntar
        for region_volumes in results['evs_volumes'].values():
            for volume in region_volumes:
                if not volume.get('attachments'):
                    stats['unattached_volumes'] += 1
                stats['total_storage_gb'] += volume.get('size', 0)
        
        # Analizar buckets
        for bucket in results['obs_buckets']:
            if bucket.get('public_access'):
                stats['public_buckets'] += 1
            if bucket.get('versioning') != 'Enabled':
                stats['buckets_without_versioning'] += 1
        
        # Contar hallazgos por severidad
        for finding in self.findings:
            stats['findings_by_severity'][finding['severity']] += 1
        
        return stats