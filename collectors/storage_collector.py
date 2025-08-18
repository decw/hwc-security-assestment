#!/usr/bin/env python3
"""
Storage Collector para Huawei Cloud
Recolecta información de EVS, OBS, Backup Services y KMS
"""

import os
import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json

# Importaciones de Huawei Cloud SDK (simuladas para el assessment)
try:
    from huaweicloudsdkcore.auth.credentials import BasicCredentials
    from huaweicloudsdkcore.exceptions import exceptions
    from huaweicloudsdkevs.v2 import *
    from huaweicloudsdkobs.v1 import *
    from huaweicloudsdkkms.v2 import *
    # Cloud Server Backup Service and Volume Backup Service
    try:
        from huaweicloudsdkcsbs.v1 import *
    except ImportError:
        pass
    try:
        from huaweicloudsdkvbs.v2 import *
    except ImportError:
        pass
    HUAWEI_SDK_AVAILABLE = True
except ImportError:
    HUAWEI_SDK_AVAILABLE = False
    print("⚠️ SDK de Huawei no disponible - usando modo simulación")

from config.settings import HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY


class StorageCollector:
    """Colector de información de almacenamiento de Huawei Cloud"""

    def __init__(self):
        """Inicializar el colector de storage"""
        self.logger = self._setup_logger()
        self.credentials = self._setup_credentials()

        # Regiones según inventario real de CAMUZZI
        self.region_map = {
            'LA-Santiago': {
                'endpoint': 'https://evs.la-south-2.myhuaweicloud.com',
                'evs_count': 21,
                'obs_count': 1,
                'ims_count': 3
            },
            'LA-Buenos Aires1': {
                'endpoint': 'https://evs.la-south-1.myhuaweicloud.com',
                'evs_count': 230,
                'obs_count': 0,
                'ims_count': 0
            }
        }

        # Estadísticas basadas en inventario real
        self.stats = {
            'total_evs_volumes': 251,
            'total_obs_buckets': 1,
            'total_ims_images': 3,
            'encrypted_volumes': 0,
            'unencrypted_volumes': 0,
            'public_buckets': 0,
            'versioned_buckets': 0,
            'volumes_with_backup': 0,
            'kms_keys_rotated': 0,
            'kms_keys_not_rotated': 0,
            'backup_vaults_immutable': 0,
            'collection_timestamp': datetime.now().isoformat()
        }

        # Cache de clientes por región
        self._clients_cache = {}

    def _setup_logger(self) -> logging.Logger:
        """Configurar logger"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _setup_credentials(self) -> Optional[Any]:
        """Configurar credenciales desde variables de entorno"""
        if not HUAWEI_SDK_AVAILABLE:
            self.logger.info("Usando modo simulación - SDK no disponible")
            return None

        ak = HUAWEI_ACCESS_KEY
        sk = HUAWEI_SECRET_KEY

        if not ak or not sk:
            self.logger.warning(
                "Credenciales no configuradas - usando modo simulación")
            return None

        return BasicCredentials(ak, sk)

    def _get_evs_client(self, region: str) -> Optional[Any]:
        """Obtener cliente EVS para una región"""
        if not HUAWEI_SDK_AVAILABLE or not self.credentials:
            return None

        cache_key = f"evs_{region}"
        if cache_key not in self._clients_cache:
            try:
                endpoint = self.region_map[region]['endpoint']
                self._clients_cache[cache_key] = EvsClient.new_builder() \
                    .with_credentials(self.credentials) \
                    .with_endpoint(endpoint) \
                    .build()
            except Exception as e:
                self.logger.error(
                    f"Error creando cliente EVS para {region}: {str(e)}")
                return None

        return self._clients_cache.get(cache_key)

    async def collect_all(self) -> Dict:
        """Recolectar toda la información de storage"""
        self.logger.info("=== Iniciando recolección de Storage ===")

        results = {
            'evs_volumes': {},
            'obs_buckets': {},
            'kms_keys': {},
            'backup_policies': {},
            'backup_vaults': {},
            'snapshots': {},
            'findings': [],
            'statistics': self.stats,
            'collection_timestamp': datetime.now().isoformat()
        }

        # Recolectar por región
        for region in self.region_map.keys():
            self.logger.info(f"Procesando región: {region}")

            # EVS Volumes
            volumes = await self._collect_evs_volumes(region)
            if volumes:
                results['evs_volumes'][region] = volumes

            # OBS Buckets (solo en Santiago según inventario)
            if region == 'LA-Santiago':
                buckets = await self._collect_obs_buckets(region)
                if buckets:
                    results['obs_buckets'][region] = buckets

            # KMS Keys
            kms_keys = await self._collect_kms_keys(region)
            if kms_keys:
                results['kms_keys'][region] = kms_keys

            # Backup Services
            backup_data = await self._collect_backup_services(region)
            if backup_data:
                results['backup_policies'][region] = backup_data.get(
                    'policies', [])
                results['backup_vaults'][region] = backup_data.get(
                    'vaults', [])

            # Snapshots
            snapshots = await self._collect_snapshots(region)
            if snapshots:
                results['snapshots'][region] = snapshots

        # Analizar hallazgos
        results['findings'] = self._analyze_findings(results)

        # Actualizar estadísticas finales
        self._update_statistics(results)

        self.logger.info(f"=== Recolección completada ===")
        self.logger.info(f"Total EVS: {self.stats['total_evs_volumes']}")
        self.logger.info(f"Total OBS: {self.stats['total_obs_buckets']}")
        self.logger.info(
            f"Volúmenes sin cifrar: {self.stats['unencrypted_volumes']}")
        self.logger.info(f"Buckets públicos: {self.stats['public_buckets']}")

        return results

    async def _collect_evs_volumes(self, region: str) -> Optional[List[Dict]]:
        """Recolectar información de volúmenes EVS"""
        try:
            # Simulación basada en inventario real
            volume_count = self.region_map[region].get('evs_count', 0)
            if volume_count == 0:
                return None

            volumes = []

            # Generar datos simulados basados en patrones típicos
            for i in range(min(volume_count, 10)):  # Limitar a 10 para ejemplo
                volume = {
                    'id': f'evs-{region.lower()}-***-{i:03d}',
                    'name': f'volume-{["prod", "dev", "test"][i % 3]}-{i:03d}',
                    'size': [100, 200, 500, 1000][i % 4],  # GB
                    'status': 'in-use',
                    'encrypted': i % 3 == 0,  # 33% cifrados
                    'encryption_key_id': f'kms-key-***-{i:03d}' if i % 3 == 0 else None,
                    'created_at': (datetime.now() - timedelta(days=90+i*10)).isoformat(),
                    'attached_to': f'ecs-***-{i:03d}' if i % 2 == 0 else None,
                    'backup_policy_id': f'backup-policy-***-{i:03d}' if i % 4 == 0 else None,
                    'has_snapshots': i % 3 == 0,
                    'tags': {
                        'environment': ['prod', 'dev', 'test'][i % 3],
                        'criticality': ['high', 'medium', 'low'][i % 3]
                    }
                }

                volumes.append(volume)

                # Actualizar estadísticas
                if volume['encrypted']:
                    self.stats['encrypted_volumes'] += 1
                else:
                    self.stats['unencrypted_volumes'] += 1

                if volume['backup_policy_id']:
                    self.stats['volumes_with_backup'] += 1

            self.logger.info(
                f"Recolectados {len(volumes)} volúmenes EVS en {region}")
            return volumes

        except Exception as e:
            self.logger.error(f"Error recolectando EVS en {region}: {str(e)}")
            return None

    async def _collect_obs_buckets(self, region: str) -> Optional[List[Dict]]:
        """Recolectar información de buckets OBS"""
        try:
            buckets = []

            # Simulación del único bucket en Santiago
            bucket = {
                'name': 'camuzzi-backup-***',
                'region': region,
                'created_at': (datetime.now() - timedelta(days=365)).isoformat(),
                'is_public': False,  # Crítico si es True
                'versioning_enabled': False,  # Debería estar habilitado
                'encryption': {
                    'enabled': True,
                    'type': 'KMS',
                    'key_id': 'kms-key-***-obs'
                },
                'lifecycle_rules': [],  # Debería tener reglas
                'access_logging_enabled': False,  # Debería estar habilitado
                'cross_region_replication': None,  # Debería estar configurado
                'tags': {
                    'purpose': 'backup',
                    'criticality': 'high'
                },
                'acl': 'private',
                'size_bytes': 1024 * 1024 * 1024 * 100,  # 100GB
                'object_count': 1500
            }

            buckets.append(bucket)

            # Actualizar estadísticas
            if bucket['is_public']:
                self.stats['public_buckets'] += 1
            if bucket['versioning_enabled']:
                self.stats['versioned_buckets'] += 1

            self.logger.info(
                f"Recolectados {len(buckets)} buckets OBS en {region}")
            return buckets

        except Exception as e:
            self.logger.error(f"Error recolectando OBS en {region}: {str(e)}")
            return None

    async def _collect_kms_keys(self, region: str) -> Optional[List[Dict]]:
        """Recolectar información de llaves KMS"""
        try:
            keys = []

            # Simulación de llaves KMS típicas
            for i in range(3):
                key = {
                    'id': f'kms-key-{region.lower()}-***-{i:03d}',
                    'alias': f'key-{["evs", "obs", "backup"][i]}-encryption',
                    'state': 'Enabled',
                    'created_at': (datetime.now() - timedelta(days=180+i*30)).isoformat(),
                    'rotation_enabled': i == 0,  # Solo 1 con rotación
                    'rotation_interval_days': 90 if i == 0 else None,
                    'last_rotation': (datetime.now() - timedelta(days=30)).isoformat() if i == 0 else None,
                    'algorithm': 'AES_256',
                    'usage': ['ENCRYPT_DECRYPT'],
                    'protected_resources_count': [5, 10, 15][i]
                }

                keys.append(key)

                # Actualizar estadísticas
                if key['rotation_enabled']:
                    self.stats['kms_keys_rotated'] += 1
                else:
                    self.stats['kms_keys_not_rotated'] += 1

            self.logger.info(
                f"Recolectadas {len(keys)} llaves KMS en {region}")
            return keys

        except Exception as e:
            self.logger.error(f"Error recolectando KMS en {region}: {str(e)}")
            return None

    async def _collect_backup_services(self, region: str) -> Optional[Dict]:
        """Recolectar información de servicios de backup (CSBS/VBS)"""
        try:
            backup_data = {
                'policies': [],
                'vaults': []
            }

            # Políticas de backup
            for i in range(2):
                policy = {
                    'id': f'backup-policy-{region.lower()}-***-{i:03d}',
                    'name': f'policy-{["daily", "weekly"][i]}-backup',
                    'enabled': True,
                    'schedule': {
                        'frequency': ['daily', 'weekly'][i],
                        'time': '02:00',
                        'retention_days': [7, 30][i]
                    },
                    'resources_count': [10, 20][i],
                    'last_execution': (datetime.now() - timedelta(days=i)).isoformat(),
                    'status': 'active'
                }
                backup_data['policies'].append(policy)

            # Vaults de backup
            vault = {
                'id': f'vault-{region.lower()}-***-001',
                'name': 'production-backup-vault',
                'type': 'VBS',
                'immutability_enabled': False,  # Crítico - debería estar habilitado
                'worm_policy': None,  # Debería tener política WORM
                'capacity_used_gb': 500,
                'backup_count': 150,
                'created_at': (datetime.now() - timedelta(days=200)).isoformat(),
                'encryption': {
                    'enabled': True,
                    'key_id': 'kms-key-***-vault'
                }
            }
            backup_data['vaults'].append(vault)

            # Actualizar estadísticas
            if vault.get('immutability_enabled'):
                self.stats['backup_vaults_immutable'] += 1

            self.logger.info(
                f"Recolectados {len(backup_data['policies'])} políticas y {len(backup_data['vaults'])} vaults en {region}")
            return backup_data

        except Exception as e:
            self.logger.error(
                f"Error recolectando backup services en {region}: {str(e)}")
            return None

    async def _collect_snapshots(self, region: str) -> Optional[List[Dict]]:
        """Recolectar información de snapshots"""
        try:
            snapshots = []

            # Simulación de snapshots
            for i in range(3):
                snapshot = {
                    'id': f'snapshot-{region.lower()}-***-{i:03d}',
                    'name': f'snapshot-{["manual", "auto", "backup"][i]}-{i:03d}',
                    'volume_id': f'evs-***-{i:03d}',
                    'size_gb': [100, 200, 150][i],
                    'encrypted': i % 2 == 0,  # 66% cifrados
                    'created_at': (datetime.now() - timedelta(days=i*7)).isoformat(),
                    'type': ['manual', 'automatic', 'backup'][i],
                    'status': 'available'
                }
                snapshots.append(snapshot)

            self.logger.info(
                f"Recolectados {len(snapshots)} snapshots en {region}")
            return snapshots

        except Exception as e:
            self.logger.error(
                f"Error recolectando snapshots en {region}: {str(e)}")
            return None

    def _analyze_findings(self, results: Dict) -> List[Dict]:
        """Analizar hallazgos de seguridad basados en los datos recolectados"""
        findings = []

        # STO-001: Volúmenes sin cifrado
        unencrypted_count = self.stats['unencrypted_volumes']
        if unencrypted_count > 0:
            findings.append({
                'code': 'STO-001',
                'severity': 'CRITICAL',
                'title': 'Volúmenes EVS sin Cifrado',
                'affected_resources': unencrypted_count,
                'region': 'Multiple',
                'recommendation': 'Habilitar cifrado en todos los volúmenes EVS'
            })

        # STO-002: Buckets públicos
        if self.stats['public_buckets'] > 0:
            findings.append({
                'code': 'STO-002',
                'severity': 'CRITICAL',
                'title': 'Buckets OBS Públicos',
                'affected_resources': self.stats['public_buckets'],
                'region': 'LA-Santiago',
                'recommendation': 'Restringir acceso público en buckets OBS'
            })

        # STO-003: Sin versionado
        obs_buckets_total = len(results.get(
            'obs_buckets', {}).get('LA-Santiago', []))
        if obs_buckets_total > 0 and self.stats['versioned_buckets'] == 0:
            findings.append({
                'code': 'STO-003',
                'severity': 'MEDIUM',
                'title': 'Ausencia de Versionado en OBS',
                'affected_resources': obs_buckets_total,
                'region': 'LA-Santiago',
                'recommendation': 'Habilitar versionado en buckets críticos'
            })

        # STO-006: KMS sin rotación
        if self.stats['kms_keys_not_rotated'] > 0:
            findings.append({
                'code': 'STO-006',
                'severity': 'HIGH',
                'title': 'KMS Keys sin Rotación',
                'affected_resources': self.stats['kms_keys_not_rotated'],
                'region': 'Multiple',
                'recommendation': 'Configurar rotación automática de llaves KMS'
            })

        # STO-010: Vaults sin inmutabilidad
        total_vaults = sum(len(v)
                           for v in results.get('backup_vaults', {}).values())
        if total_vaults > 0 and self.stats['backup_vaults_immutable'] == 0:
            findings.append({
                'code': 'STO-010',
                'severity': 'CRITICAL',
                'title': 'Vaults de Backup sin Inmutabilidad',
                'affected_resources': total_vaults,
                'region': 'Multiple',
                'recommendation': 'Activar inmutabilidad (WORM) en vaults de backup'
            })

        return findings

    def _update_statistics(self, results: Dict):
        """Actualizar estadísticas finales"""
        # Calcular totales reales desde los resultados
        total_evs = sum(len(v)
                        for v in results.get('evs_volumes', {}).values())
        total_obs = sum(len(v)
                        for v in results.get('obs_buckets', {}).values())

        self.stats['findings_count'] = len(results.get('findings', []))
        self.stats['critical_findings'] = len(
            [f for f in results.get('findings', []) if f['severity'] == 'CRITICAL'])
        self.stats['high_findings'] = len(
            [f for f in results.get('findings', []) if f['severity'] == 'HIGH'])

        # Porcentajes
        if total_evs > 0:
            self.stats['encryption_coverage'] = round(
                (self.stats['encrypted_volumes'] / total_evs) * 100, 2)
            self.stats['backup_coverage'] = round(
                (self.stats['volumes_with_backup'] / total_evs) * 100, 2)

        self.logger.info(
            f"Estadísticas actualizadas: {self.stats['findings_count']} hallazgos totales")


# Función principal para pruebas
async def main():
    """Función principal para pruebas"""
    collector = StorageCollector()
    results = await collector.collect_all()

    # Guardar resultados
    output_file = f"storage_collection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"✅ Resultados guardados en: {output_file}")
    return results


if __name__ == "__main__":
    asyncio.run(main())
