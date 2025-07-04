#!/usr/bin/env python3
"""
Colector de datos IAM para Huawei Cloud
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any
from huaweicloudsdkcore.auth.credentials import GlobalCredentials
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkcore.region.region import Region
from huaweicloudsdkiam.v3 import *
from huaweicloudsdkiam.v3.region.iam_region import IamRegion
from utils.logger import SecurityLogger
from config.settings import (
    HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY, 
    HUAWEI_DOMAIN_ID, API_TIMEOUT
)
from config.constants import PASSWORD_POLICY, MFA_REQUIREMENTS
import pytz
from dateutil import parser

class IAMCollector:
    """Colector de configuraciones y vulnerabilidades IAM"""
    
    def __init__(self):
        self.logger = SecurityLogger('IAMCollector')
        self.credentials = GlobalCredentials(
            HUAWEI_ACCESS_KEY,
            HUAWEI_SECRET_KEY,
            HUAWEI_DOMAIN_ID
        )
        self.client = self._init_client()
        self.findings = []

    def _convert_to_serializable(self, obj) -> Any:
        """Convertir objetos de Huawei Cloud a formato serializable"""
        if hasattr(obj, '__dict__'):
            # Convertir objeto a diccionario
            result = {}
            for key, value in obj.__dict__.items():
                if not key.startswith('_'):  # Ignorar atributos privados
                    result[key] = self._convert_to_serializable(value)
            return result
        elif isinstance(obj, list):
            return [self._convert_to_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: self._convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, datetime):
            return obj.isoformat()
        else:
            # Para tipos básicos (str, int, float, bool, None)
            return obj

    def _init_client(self):
        """Inicializar cliente IAM"""
        try:
            # IAM es un servicio global, pero necesita una región para el endpoint
            # Intentar con diferentes opciones de región
            try:
                # Opción 1: Usar IamRegion si está disponible
                region = IamRegion.value_of("ap-southeast-1")
            except:
                try:
                    # Opción 2: Crear región manualmente
                    region = Region("ap-southeast-1", "https://iam.ap-southeast-1.myhuaweicloud.com")
                except:
                    # Opción 3: Usar región genérica
                    region = None
            
            builder = IamClient.new_builder() \
                .with_credentials(self.credentials)
            
            if region:
                builder = builder.with_region(region)
            
            return builder.build()
            
        except Exception as e:
            self.logger.error(f"Error inicializando cliente IAM: {str(e)}")
            # Intentar configuración alternativa
            try:
                return IamClient.new_builder() \
                    .with_credentials(self.credentials) \
                    .with_endpoint("https://iam.myhuaweicloud.com") \
                    .build()
            except Exception as e2:
                self.logger.error(f"Error con configuración alternativa: {str(e2)}")
                raise
    
    def _parse_datetime_safe(self, date_str) -> datetime:
        """Parsear datetime de manera segura manejando timezone"""
        if not date_str:
            return datetime.now(timezone.utc)
        
        try:
            # Si ya es datetime, convertir a UTC si es necesario
            if isinstance(date_str, datetime):
                if date_str.tzinfo is None:
                    return date_str.replace(tzinfo=timezone.utc)
                return date_str
            
            # Si es string, intentar parsear
            if isinstance(date_str, str):
                # Remover milisegundos si están presentes
                if '.' in date_str:
                    date_str = date_str.split('.')[0] + 'Z'
                
                # Agregar timezone si no está presente
                if not date_str.endswith('Z') and '+' not in date_str:
                    date_str += 'Z'
                
                # Parsear con timezone UTC
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            
        except Exception as e:
            self.logger.debug(f"Error parsing datetime {date_str}: {str(e)}")
            return datetime.now(timezone.utc)
        
        return datetime.now(timezone.utc)            

    async def collect_all(self) -> Dict[str, Any]:
        """Recolectar todos los datos IAM"""
        self.logger.info("Iniciando recolección de datos IAM")
        
        results = {
            'users': await self._collect_users(),
            'groups': await self._collect_groups(),
            'roles': await self._collect_roles(),
            'policies': await self._collect_policies(),
            'access_keys': await self._collect_access_keys(),
            'mfa_status': await self._collect_mfa_status(),
            'password_policy': await self._collect_password_policy(),
            'findings': self.findings,
            'statistics': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Calcular estadísticas
        results['statistics'] = self._calculate_statistics(results)
        
        self.logger.info(f"Recolección IAM completada. Hallazgos: {len(self.findings)}")
        return results
    
    async def _collect_users(self) -> List[Dict]:
        """Recolectar información de usuarios"""
        users = []
        try:
            # Intentar diferentes métodos según la versión del SDK
            try:
                # Método v3
                request = KeystoneListUsersRequest()
                response = self.client.keystone_list_users(request)
                user_list = response.users
            except:
                try:
                    # Método alternativo
                    request = ListUsersRequest()
                    response = self.client.list_users(request)
                    user_list = response.users
                except Exception as e:
                    self.logger.error(f"No se pudo listar usuarios: {str(e)}")
                    return users
            
            for user in user_list:
                user_info = {
                    'id': getattr(user, 'id', 'unknown'),
                    'name': getattr(user, 'name', 'unknown'),
                    'enabled': getattr(user, 'enabled', True),
                    'domain_id': getattr(user, 'domain_id', ''),
                    'description': getattr(user, 'description', ''),
                    'password_expires_at': getattr(user, 'password_expires_at', None),
                    'last_login': getattr(user, 'last_login_time', None),
                    'created_at': getattr(user, 'create_time', None)
                }
                
                # Verificar privilegios excesivos
                if await self._check_admin_privileges(user_info['id']):
                    self._add_finding(
                        'IAM-001',
                        'CRITICAL',
                        f'Usuario con privilegios administrativos: {user_info["name"]}',
                        {'user_id': user_info['id'], 'user_name': user_info['name']}
                    )
                
                users.append(user_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando usuarios: {str(e)}")
            self.logger.debug(f"Tipo de error: {type(e).__name__}")
            
        return users
    
    async def _collect_groups(self) -> List[Dict]:
        """Recolectar información de grupos"""
        groups = []
        try:
            request = KeystoneListGroupsRequest()
            response = self.client.keystone_list_groups(request)
            
            for group in response.groups:
                group_info = {
                    'id': group.id,
                    'name': group.name,
                    'domain_id': group.domain_id,
                    'description': getattr(group, 'description', ''),
                    'create_time': getattr(group, 'create_time', None)
                }
                groups.append(group_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando grupos: {str(e)}")
            
        return groups
    
    async def _collect_roles(self) -> List[Dict]:
        """Recolectar información de roles - CORREGIDO nombres de clases"""
        roles = []
        try:
            # Corregir el nombre de la clase
            request = KeystoneListRolesRequest()
            response = self.client.keystone_list_roles(request)
            
            for role in response.roles:
                role_info = {
                    'id': getattr(role, 'id', 'unknown'),
                    'name': getattr(role, 'name', 'unknown'),
                    'domain_id': getattr(role, 'domain_id', ''),
                    'description': getattr(role, 'description', ''),
                    'type': getattr(role, 'type', 'unknown')
                }
                roles.append(role_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando roles: {str(e)}")
            # Intentar método alternativo
            try:
                # Si el método anterior falla, intentar con otro approach
                request = ListRolesRequest()
                response = self.client.list_roles(request)
                
                for role in response.roles:
                    role_info = self._convert_to_serializable(role)
                    roles.append(role_info)
                    
            except Exception as e2:
                self.logger.error(f"Error con método alternativo de roles: {str(e2)}")
            
        return roles
    
    async def _collect_policies(self) -> List[Dict]:
        """Recolectar políticas IAM - CORREGIDO"""
        policies = []
        try:
            # Obtener políticas custom
            request = ListCustomPoliciesRequest()
            response = self.client.list_custom_policies(request)
            
            for policy in response.roles:
                # Convertir a formato serializable
                policy_info = {
                    'id': getattr(policy, 'id', 'unknown'),
                    'name': getattr(policy, 'display_name', 'unknown'),
                    'type': getattr(policy, 'type', 'unknown'),
                    'description': getattr(policy, 'description', ''),
                    'policy': self._convert_to_serializable(getattr(policy, 'policy', {}))
                }
                
                # Analizar política para detectar permisos excesivos
                if self._check_excessive_permissions(policy_info['policy']):
                    self._add_finding(
                        'IAM-003',
                        'HIGH',
                        f'Política con permisos excesivos: {policy_info["name"]}',
                        {
                            'policy_id': policy_info['id'], 
                            'policy_name': policy_info['name']
                        }
                    )
                
                policies.append(policy_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando políticas: {str(e)}")
            
        return policies
    
    async def _collect_access_keys(self) -> List[Dict]:
        """Recolectar información de access keys - CORREGIDO"""
        access_keys = []
        users = await self._collect_users()
        
        for user in users:
            try:
                request = ListPermanentAccessKeysRequest()
                request.user_id = user['id']
                response = self.client.list_permanent_access_keys(request)
                
                for key in response.credentials:
                    # CORREGIDO: Manejo seguro de fechas
                    created_at = key.create_time
                    if created_at:
                        try:
                            # Intentar parsear la fecha de diferentes formas
                            if isinstance(created_at, str):
                                # Si es string, parsearlo
                                created_date = parser.parse(created_at)
                            else:
                                # Si ya es datetime, usarlo directamente
                                created_date = created_at
                            
                            # Asegurar que tiene timezone
                            if created_date.tzinfo is None:
                                created_date = created_date.replace(tzinfo=timezone.utc)
                            
                            # Calcular edad
                            now = datetime.now(timezone.utc)
                            key_age = (now - created_date).days
                        except Exception as date_error:
                            self.logger.warning(f"Error parseando fecha {created_at}: {date_error}")
                            key_age = 0
                    else:
                        key_age = 0
                    
                    key_info = {
                        'access_key_id': key.access,
                        'user_id': user['id'],
                        'user_name': user['name'],
                        'status': key.status,
                        'created_at': str(created_at) if created_at else None,
                        'age_days': key_age,
                        'last_used': getattr(key, 'last_use_time', None)
                    }
                    
                    # Verificar rotación de keys
                    if key_age > 90:
                        self._add_finding(
                            'IAM-004',
                            'HIGH',
                            f'Access Key sin rotación por {key_age} días',
                            {
                                'user_name': user['name'],
                                'access_key_id': key.access[:10] + '****',
                                'age_days': key_age
                            }
                        )
                    
                    access_keys.append(key_info)
                    
            except Exception as e:
                self.logger.error(f"Error recolectando access keys para usuario {user['id']}: {str(e)}")
                # CORREGIDO: Continuar con el siguiente usuario en lugar de fallar
                continue
                
        return access_keys
    
    # Función helper para manejo seguro de fechas
    def safe_date_parse(date_input):
        """Parsear fechas de manera segura"""
        if not date_input:
            return None
        
        try:
            if isinstance(date_input, str):
                # Intentar diferentes formatos
                try:
                    return datetime.fromisoformat(date_input.replace('Z', '+00:00'))
                except:
                    return parser.parse(date_input)
            elif isinstance(date_input, datetime):
                return date_input
            else:
                return datetime.fromtimestamp(float(date_input), tz=timezone.utc)
        except Exception as e:
            print(f"Error parseando fecha {date_input}: {e}")
            return None

    # Función para calcular edad de manera segura
    def calculate_age_days(created_date, reference_date=None):
        """Calcular edad en días de manera segura"""
        if not created_date:
            return 0
        
        if reference_date is None:
            reference_date = datetime.now(timezone.utc)
        
        try:
            if isinstance(created_date, str):
                created_date = safe_date_parse(created_date)
            
            if created_date and created_date.tzinfo is None:
                created_date = created_date.replace(tzinfo=timezone.utc)
            
            if created_date:
                return (reference_date - created_date).days
        except Exception as e:
            print(f"Error calculando edad: {e}")
        
        return 0

    async def _collect_mfa_status(self) -> Dict[str, Any]:
        """Verificar estado de MFA para todos los usuarios - MEJORADO"""
        mfa_status = {
            'total_users': 0,
            'mfa_enabled': 0,
            'mfa_disabled': 0,
            'users_without_mfa': [],
            'mfa_devices': []
        }
        
        users = await self._collect_users()
        mfa_status['total_users'] = len(users)
        
        for user in users:
            try:
                request = ShowUserMfaDeviceRequest()
                request.user_id = user['id']
                response = self.client.show_user_mfa_device(request)
                
                has_mfa = False
                if hasattr(response, 'virtual_mfa_device') and response.virtual_mfa_device:
                    has_mfa = True
                    mfa_status['mfa_enabled'] += 1
                    mfa_status['mfa_devices'].append({
                        'user_id': user['id'],
                        'user_name': user['name'],
                        'device_serial': getattr(response.virtual_mfa_device, 'serial_number', 'unknown')
                    })
                
                if not has_mfa:
                    mfa_status['mfa_disabled'] += 1
                    mfa_status['users_without_mfa'].append({
                        'user_id': user['id'],
                        'user_name': user['name']
                    })
                    
                    # Verificar si es usuario privilegiado
                    if await self._check_admin_privileges(user['id']):
                        self._add_finding(
                            'IAM-002',
                            'CRITICAL',
                            f'Usuario administrativo sin MFA: {user["name"]}',
                            {'user_id': user['id'], 'user_name': user['name']}
                        )
                    
            except Exception as e:
                self.logger.debug(f"No se pudo verificar MFA para usuario {user['id']}: {str(e)}")
                # Asumir que no tiene MFA si no se puede verificar
                mfa_status['mfa_disabled'] += 1
                mfa_status['users_without_mfa'].append({
                    'user_id': user['id'],
                    'user_name': user['name']
                })
                
        return mfa_status
    
    async def _collect_password_policy(self) -> Dict[str, Any]:
        """Recolectar política de contraseñas - CORREGIDO atributos"""
        policy = {}
        try:
            request = ShowDomainPasswordPolicyRequest()
            request.domain_id = HUAWEI_DOMAIN_ID
            response = self.client.show_domain_password_policy(request)
            
            # Acceder correctamente a los atributos
            pwd_policy = response.password_policy
            
            policy = {
                'minimum_length': getattr(pwd_policy, 'minimum_password_length', 8),
                'require_uppercase': getattr(pwd_policy, 'minimum_password_uppercase', 0) > 0,
                'require_lowercase': getattr(pwd_policy, 'minimum_password_lowercase', 0) > 0,
                'require_numbers': getattr(pwd_policy, 'minimum_password_number', 0) > 0,
                'require_special': getattr(pwd_policy, 'minimum_password_special_char', 0) > 0,
                'password_validity_period': getattr(pwd_policy, 'password_validity_period', 0),
                'password_char_combination': getattr(pwd_policy, 'password_char_combination', 0),
                'password_not_username_or_invert': getattr(pwd_policy, 'password_not_username_or_invert', False)
            }
            
            # Verificar cumplimiento con política mínima
            if policy['minimum_length'] < PASSWORD_POLICY['min_length']:
                self._add_finding(
                    'IAM-005',
                    'MEDIUM',
                    f'Política de contraseñas débil: longitud mínima {policy["minimum_length"]}',
                    {
                        'current_length': policy['minimum_length'], 
                        'required_length': PASSWORD_POLICY['min_length']
                    }
                )
                
        except Exception as e:
            self.logger.error(f"Error recolectando política de contraseñas: {str(e)}")
            self.logger.debug(f"Detalles del error: {type(e).__name__}")
            
        return policy
    
    async def _check_admin_privileges(self, user_id: str) -> bool:
        """Verificar si un usuario tiene privilegios administrativos"""
        try:
            # Verificar roles asignados
            request = ListProjectPermissionsForAgencyRequest()
            # Implementar lógica según API
            return False  # Placeholder
        except:
            return False
    
    # Método para verificar permisos excesivos - mejorado
    def _check_excessive_permissions(self, policy: dict) -> bool:
        """Verificar si una política tiene permisos excesivos"""
        if not policy:
            return False
            
        policy_str = str(policy).lower()
        
        # Patrones peligrosos
        dangerous_patterns = [
            '*:*:*',
            '"action": "*"',
            '"resource": "*"',
            'administratoraccess',
            '"effect": "allow"' and '"action": "*"'
        ]
        
        return any(pattern in policy_str for pattern in dangerous_patterns)
    
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
        """Calcular estadísticas del análisis IAM"""
        stats = {
            'total_users': len(results['users']),
            'total_groups': len(results['groups']),
            'total_policies': len(results['policies']),
            'total_access_keys': len(results['access_keys']),
            'users_without_mfa': results['mfa_status']['mfa_disabled'],
            'mfa_compliance_rate': 0,
            'old_access_keys': 0,
            'findings_by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
        }
        
        # Calcular tasa de cumplimiento MFA
        if stats['total_users'] > 0:
            stats['mfa_compliance_rate'] = round(
                (results['mfa_status']['mfa_enabled'] / stats['total_users']) * 100, 2
            )
        
        # Contar access keys antiguas
        stats['old_access_keys'] = sum(
            1 for key in results['access_keys'] if key['age_days'] > 90
        )
        
        # Contar hallazgos por severidad
        for finding in self.findings:
            stats['findings_by_severity'][finding['severity']] += 1
        
        return stats