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
        """Recolectar información de roles"""
        roles = []
        try:
            request = KeystoneListAllProjectsPermissionsForAgencyRequest()
            # Implementar lógica específica según la API de Huawei
            pass
        except Exception as e:
            self.logger.error(f"Error recolectando roles: {str(e)}")
            
        return roles
    
    async def _collect_policies(self) -> List[Dict]:
        """Recolectar políticas IAM"""
        policies = []
        try:
            # Obtener políticas custom
            request = ListCustomPoliciesRequest()
            response = self.client.list_custom_policies(request)
            
            for policy in response.roles:
                policy_info = {
                    'id': policy.id,
                    'name': policy.display_name,
                    'type': policy.type,
                    'description': policy.description,
                    'policy': policy.policy
                }
                
                # Analizar política para detectar permisos excesivos
                if self._check_excessive_permissions(policy.policy):
                    self._add_finding(
                        'IAM-003',
                        'HIGH',
                        f'Política con permisos excesivos: {policy.display_name}',
                        {'policy_id': policy.id, 'policy_name': policy.display_name}
                    )
                
                policies.append(policy_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando políticas: {str(e)}")
            
        return policies
    
    async def _collect_access_keys(self) -> List[Dict]:
        """Recolectar información de access keys"""
        access_keys = []
        users = await self._collect_users()
        
        for user in users:
            try:
                request = ListPermanentAccessKeysRequest()
                request.user_id = user['id']
                response = self.client.list_permanent_access_keys(request)
                
                for key in response.credentials:
                    key_age = (datetime.now() - datetime.fromisoformat(key.create_time)).days
                    
                    key_info = {
                        'access_key_id': key.access,
                        'user_id': user['id'],
                        'user_name': user['name'],
                        'status': key.status,
                        'created_at': key.create_time,
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
                
        return access_keys
    
    async def _collect_mfa_status(self) -> Dict[str, Any]:
        """Verificar estado de MFA para todos los usuarios"""
        mfa_status = {
            'total_users': 0,
            'mfa_enabled': 0,
            'mfa_disabled': 0,
            'users_without_mfa': []
        }
        
        users = await self._collect_users()
        mfa_status['total_users'] = len(users)
        
        for user in users:
            try:
                request = ShowUserMfaDeviceRequest()
                request.user_id = user['id']
                response = self.client.show_user_mfa_device(request)
                
                if not response.virtual_mfa_device:
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
                else:
                    mfa_status['mfa_enabled'] += 1
                    
            except Exception as e:
                self.logger.debug(f"No se pudo verificar MFA para usuario {user['id']}")
                
        return mfa_status
    
    async def _collect_password_policy(self) -> Dict[str, Any]:
        """Recolectar política de contraseñas"""
        policy = {}
        try:
            request = ShowDomainPasswordPolicyRequest()
            request.domain_id = HUAWEI_DOMAIN_ID
            response = self.client.show_domain_password_policy(request)
            
            policy = {
                'minimum_length': response.password_policy.minimum_length,
                'require_uppercase': response.password_policy.uppercase_requirements,
                'require_lowercase': response.password_policy.lowercase_requirements,
                'require_numbers': response.password_policy.number_requirements,
                'require_special': response.password_policy.special_character_requirements,
                'password_validity_period': response.password_policy.password_validity_period
            }
            
            # Verificar cumplimiento con política mínima
            if policy['minimum_length'] < PASSWORD_POLICY['min_length']:
                self._add_finding(
                    'IAM-005',
                    'MEDIUM',
                    f'Política de contraseñas débil: longitud mínima {policy["minimum_length"]}',
                    {'current_length': policy['minimum_length'], 
                     'required_length': PASSWORD_POLICY['min_length']}
                )
                
        except Exception as e:
            self.logger.error(f"Error recolectando política de contraseñas: {str(e)}")
            
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
    
    def _check_excessive_permissions(self, policy: dict) -> bool:
        """Verificar si una política tiene permisos excesivos"""
        if not policy:
            return False
            
        # Buscar patrones de permisos excesivos
        excessive_patterns = [
            '"Action": ["*"]',
            '"Resource": ["*"]',
            'AdministratorAccess',
            '"Effect": "Allow".*"Action": "\\*"'
        ]
        
        policy_str = str(policy)
        return any(pattern in policy_str for pattern in excessive_patterns)
    
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