# Monitoring Collector
#!/usr/bin/env python3
"""
Colector de configuraciones de monitoreo y auditoría para Huawei Cloud
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkces.v1 import *
from huaweicloudsdkcts.v3 import *
from huaweicloudsdklts.v2 import *
from utils.logger import SecurityLogger
from config.settings import (
    HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY,
    HUAWEI_PROJECT_ID, REGIONS, PRIMARY_REGION
)
from config.constants import LOG_RETENTION_REQUIREMENTS

class MonitoringCollector:
    """Colector de configuraciones de monitoreo, logs y auditoría"""
    
    def __init__(self):
        self.logger = SecurityLogger('MonitoringCollector')
        self.findings = []
        self.credentials = BasicCredentials(
            HUAWEI_ACCESS_KEY,
            HUAWEI_SECRET_KEY,
            HUAWEI_PROJECT_ID
        )
    
    def _get_ces_client(self, region: str):
        """Obtener cliente Cloud Eye (CES)"""
        return CesClient.new_builder() \
            .with_credentials(self.credentials) \
            .with_region(CesRegion.value_of(region)) \
            .build()
    
    def _get_cts_client(self):
        """Obtener cliente Cloud Trace Service (CTS)"""
        return CtsClient.new_builder() \
            .with_credentials(self.credentials) \
            .with_region(CtsRegion.value_of(PRIMARY_REGION)) \
            .build()
    
    def _get_lts_client(self, region: str):
        """Obtener cliente Log Tank Service (LTS)"""
        return LtsClient.new_builder() \
            .with_credentials(self.credentials) \
            .with_region(LtsRegion.value_of(region)) \
            .build()
    
    async def collect_all(self) -> Dict[str, Any]:
        """Recolectar todos los datos de monitoreo"""
        self.logger.info("Iniciando recolección de datos de monitoreo y auditoría")
        
        results = {
            'cloud_eye': {},
            'cloud_trace': await self._collect_cts_config(),
            'log_tank': {},
            'alarms': {},
            'metrics_coverage': {},
            'log_retention': {},
            'audit_trails': [],
            'findings': self.findings,
            'statistics': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Recolectar por región
        for region in REGIONS:
            self.logger.info(f"Analizando monitoreo en región: {region}")
            try:
                results['cloud_eye'][region] = await self._collect_cloud_eye(region)
                results['alarms'][region] = await self._collect_alarms(region)
                results['log_tank'][region] = await self._collect_log_tank(region)
                results['metrics_coverage'][region] = await self._analyze_metrics_coverage(region)
            except Exception as e:
                self.logger.error(f"Error en región {region}: {str(e)}")
        
        # Analizar trails de auditoría
        results['audit_trails'] = await self._analyze_audit_trails()
        
        # Calcular estadísticas
        results['statistics'] = self._calculate_statistics(results)
        
        self.logger.info(f"Recolección de monitoreo completada. Hallazgos: {len(self.findings)}")
        return results
    
    async def _collect_cloud_eye(self, region: str) -> Dict[str, Any]:
        """Recolectar configuración de Cloud Eye"""
        cloud_eye_config = {
            'metrics': [],
            'monitored_resources': [],
            'custom_metrics': []
        }
        
        try:
            client = self._get_ces_client(region)
            
            # Obtener métricas disponibles
            metrics_request = ListMetricsRequest()
            metrics_response = client.list_metrics(metrics_request)
            
            for metric in metrics_response.metrics:
                metric_info = {
                    'namespace': metric.namespace,
                    'metric_name': metric.metric_name,
                    'dimensions': metric.dimensions,
                    'unit': metric.unit
                }
                cloud_eye_config['metrics'].append(metric_info)
            
            # Verificar recursos monitoreados
            resource_request = ListResourceGroupRequest()
            resource_response = client.list_resource_group(resource_request)
            
            for resource in resource_response.resource_groups:
                cloud_eye_config['monitored_resources'].append({
                    'group_name': resource.group_name,
                    'group_id': resource.group_id,
                    'create_time': resource.create_time
                })
            
        except Exception as e:
            self.logger.error(f"Error recolectando Cloud Eye en {region}: {str(e)}")
        
        return cloud_eye_config
    
    async def _collect_alarms(self, region: str) -> List[Dict]:
        """Recolectar alarmas configuradas"""
        alarms = []
        
        try:
            client = self._get_ces_client(region)
            request = ListAlarmsRequest()
            response = client.list_alarms(request)
            
            for alarm in response.alarms:
                alarm_info = {
                    'alarm_id': alarm.alarm_id,
                    'alarm_name': alarm.alarm_name,
                    'alarm_description': alarm.alarm_description,
                    'namespace': alarm.namespace,
                    'metric_name': alarm.metric.metric_name,
                    'condition': {
                        'comparison_operator': alarm.condition.comparison_operator,
                        'value': alarm.condition.value,
                        'count': alarm.condition.count,
                        'period': alarm.condition.period
                    },
                    'alarm_enabled': alarm.alarm_enabled,
                    'alarm_action_enabled': alarm.alarm_action_enabled,
                    'alarm_actions': alarm.alarm_actions,
                    'alarm_level': alarm.alarm_level
                }
                alarms.append(alarm_info)
            
            # Verificar cobertura de alarmas
            if len(alarms) == 0:
                self._add_finding(
                    'MON-001',
                    'HIGH',
                    f'Sin alarmas configuradas en región {region}',
                    {'region': region}
                )
            
        except Exception as e:
            self.logger.error(f"Error recolectando alarmas en {region}: {str(e)}")
        
        return alarms
    
    async def _collect_cts_config(self) -> Dict[str, Any]:
        """Recolectar configuración de Cloud Trace Service"""
        cts_config = {
            'trackers': [],
            'retention_days': 7,  # Default
            'obs_bucket': None,
            'encryption': False,
            'key_events_enabled': False
        }
        
        try:
            client = self._get_cts_client()
            
            # Listar trackers
            request = ListTrackersRequest()
            response = client.list_trackers(request)
            
            for tracker in response.trackers:
                tracker_info = {
                    'tracker_name': tracker.tracker_name,
                    'tracker_type': tracker.tracker_type,
                    'status': tracker.status,
                    'is_support_trace_files_encryption': tracker.is_support_trace_files_encryption,
                    'obs_info': tracker.obs_info,
                    'is_support_validate': tracker.is_support_validate,
                    'data_bucket': tracker.data_bucket
                }
                
                # Verificar retención
                if tracker.obs_info:
                    # Asumir 7 días si no se especifica
                    retention_days = 7
                    
                    if retention_days < LOG_RETENTION_REQUIREMENTS['audit_logs']:
                        self._add_finding(
                            'MON-002',
                            'HIGH',
                            f'Retención de logs insuficiente: {retention_days} días',
                            {
                                'tracker': tracker.tracker_name,
                                'current_retention': retention_days,
                                'required_retention': LOG_RETENTION_REQUIREMENTS['audit_logs']
                            }
                        )
                
                # Verificar cifrado
                if not tracker.is_support_trace_files_encryption:
                    self._add_finding(
                        'MON-003',
                        'MEDIUM',
                        f'Logs de auditoría sin cifrar',
                        {'tracker': tracker.tracker_name}
                    )
                
                cts_config['trackers'].append(tracker_info)
            
            # Verificar si CTS está habilitado
            if not cts_config['trackers']:
                self._add_finding(
                    'MON-004',
                    'CRITICAL',
                    'Cloud Trace Service no está configurado',
                    {'impact': 'Sin auditoría de actividades'}
                )
            
        except Exception as e:
            self.logger.error(f"Error recolectando configuración CTS: {str(e)}")
        
        return cts_config
    
    async def _collect_log_tank(self, region: str) -> Dict[str, Any]:
        """Recolectar configuración de Log Tank Service"""
        lts_config = {
            'log_groups': [],
            'log_streams': [],
            'log_transfers': []
        }
        
        try:
            client = self._get_lts_client(region)
            
            # Listar grupos de logs
            groups_request = ListLogGroupsRequest()
            groups_response = client.list_log_groups(groups_request)
            
            for group in groups_response.log_groups:
                group_info = {
                    'log_group_id': group.log_group_id,
                    'log_group_name': group.log_group_name,
                    'creation_time': group.creation_time,
                    'ttl_in_days': group.ttl_in_days
                }
                
                # Verificar retención según tipo
                if 'security' in group.log_group_name.lower():
                    required_retention = LOG_RETENTION_REQUIREMENTS['security_logs']
                elif 'audit' in group.log_group_name.lower():
                    required_retention = LOG_RETENTION_REQUIREMENTS['audit_logs']
                else:
                    required_retention = LOG_RETENTION_REQUIREMENTS['application_logs']
                
                if group.ttl_in_days < required_retention:
                    self._add_finding(
                        'MON-005',
                        'MEDIUM',
                        f'Retención insuficiente en log group: {group.log_group_name}',
                        {
                            'log_group': group.log_group_name,
                            'current_retention': group.ttl_in_days,
                            'required_retention': required_retention,
                            'region': region
                        }
                    )
                
                lts_config['log_groups'].append(group_info)
                
                # Obtener streams del grupo
                streams_request = ListLogStreamsRequest()
                streams_request.log_group_id = group.log_group_id
                streams_response = client.list_log_streams(streams_request)
                
                for stream in streams_response.log_streams:
                    lts_config['log_streams'].append({
                        'log_stream_id': stream.log_stream_id,
                        'log_stream_name': stream.log_stream_name,
                        'log_group_id': group.log_group_id,
                        'creation_time': stream.creation_time
                    })
            
        except Exception as e:
            self.logger.error(f"Error recolectando Log Tank en {region}: {str(e)}")
        
        return lts_config
    
    async def _analyze_metrics_coverage(self, region: str) -> Dict[str, Any]:
        """Analizar cobertura de métricas por servicio"""
        coverage = {
            'ecs': {'total': 0, 'monitored': 0, 'percentage': 0},
            'evs': {'total': 0, 'monitored': 0, 'percentage': 0},
            'rds': {'total': 0, 'monitored': 0, 'percentage': 0},
            'elb': {'total': 0, 'monitored': 0, 'percentage': 0}
        }
        
        try:
            client = self._get_ces_client(region)
            
            # Verificar métricas por namespace
            metrics_request = ListMetricsRequest()
            response = client.list_metrics(metrics_request)
            
            monitored_resources = set()
            for metric in response.metrics:
                if metric.namespace == 'SYS.ECS':
                    for dim in metric.dimensions:
                        if dim.name == 'instance_id':
                            monitored_resources.add(('ecs', dim.value))
                elif metric.namespace == 'SYS.EVS':
                    for dim in metric.dimensions:
                        if dim.name == 'disk_id':
                            monitored_resources.add(('evs', dim.value))
            
            # Comparar con recursos totales (simplificado)
            # En implementación real, obtener lista de recursos de cada servicio
            
            # Verificar baja cobertura
            for service, data in coverage.items():
                if data['total'] > 0:
                    data['percentage'] = round((data['monitored'] / data['total']) * 100, 2)
                    
                    if data['percentage'] < 80:
                        self._add_finding(
                            'MON-006',
                            'MEDIUM',
                            f'Baja cobertura de monitoreo en {service}: {data["percentage"]}%',
                            {
                                'service': service,
                                'region': region,
                                'monitored': data['monitored'],
                                'total': data['total']
                            }
                        )
            
        except Exception as e:
            self.logger.error(f"Error analizando cobertura de métricas en {region}: {str(e)}")
        
        return coverage
    
    async def _analyze_audit_trails(self) -> List[Dict]:
        """Analizar trails de auditoría recientes"""
        trails = []
        
        try:
            client = self._get_cts_client()
            
            # Obtener eventos recientes
            request = ListTracesRequest()
            request.limit = 100
            request.from_time = int((datetime.now() - timedelta(days=7)).timestamp() * 1000)
            request.to_time = int(datetime.now().timestamp() * 1000)
            
            response = client.list_traces(request)
            
            # Analizar patrones sospechosos
            failed_logins = 0
            privilege_escalations = 0
            config_changes = 0
            
            for trace in response.traces:
                if 'login' in trace.trace_name.lower() and trace.trace_status == 'error':
                    failed_logins += 1
                elif any(action in trace.trace_name.lower() for action in ['grant', 'attach', 'policy']):
                    privilege_escalations += 1
                elif any(action in trace.trace_name.lower() for action in ['update', 'modify', 'change']):
                    config_changes += 1
            
            # Alertar sobre patrones anómalos
            if failed_logins > 10:
                self._add_finding(
                    'MON-007',
                    'HIGH',
                    f'Alto número de intentos de login fallidos: {failed_logins} en 7 días',
                    {'failed_attempts': failed_logins}
                )
            
            if privilege_escalations > 5:
                self._add_finding(
                    'MON-008',
                    'HIGH',
                    f'Múltiples cambios de privilegios detectados: {privilege_escalations}',
                    {'privilege_changes': privilege_escalations}
                )
            
        except Exception as e:
            self.logger.error(f"Error analizando audit trails: {str(e)}")
        
        return trails
    
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
        """Calcular estadísticas del análisis de monitoreo"""
        stats = {
            'total_alarms': sum(len(alarms) for alarms in results['alarms'].values()),
            'total_log_groups': sum(
                len(lt.get('log_groups', [])) for lt in results['log_tank'].values()
            ),
            'cts_enabled': len(results['cloud_trace'].get('trackers', [])) > 0,
            'average_log_retention': 0,
            'metrics_coverage': {
                'high': 0,  # >80%
                'medium': 0,  # 50-80%
                'low': 0  # <50%
            },
            'critical_alarms': 0,
            'findings_by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
        }
        
        # Calcular retención promedio
        total_retention = 0
        retention_count = 0
        for lt in results['log_tank'].values():
            for group in lt.get('log_groups', []):
                total_retention += group.get('ttl_in_days', 0)
                retention_count += 1
        
        if retention_count > 0:
            stats['average_log_retention'] = round(total_retention / retention_count, 1)
        
        # Contar alarmas críticas
        for region_alarms in results['alarms'].values():
            for alarm in region_alarms:
                if alarm.get('alarm_level') in [1, 2]:  # Niveles críticos
                    stats['critical_alarms'] += 1
        
        # Categorizar cobertura
        for coverage in results['metrics_coverage'].values():
            for service, data in coverage.items():
                percentage = data.get('percentage', 0)
                if percentage > 80:
                    stats['metrics_coverage']['high'] += 1
                elif percentage > 50:
                    stats['metrics_coverage']['medium'] += 1
                else:
                    stats['metrics_coverage']['low'] += 1
        
        # Contar hallazgos por severidad
        for finding in self.findings:
            stats['findings_by_severity'][finding['severity']] += 1
        
        return stats