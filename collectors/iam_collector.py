#!/usr/bin/env python3
"""
Colector de datos IAM para Huawei Cloud - Versión Completa
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
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
        self.processed_users = set()  # Para evitar duplicados
        self.user_cache = {}  # Cache para información de usuarios
        
    def _init_client(self):
        """Inicializar cliente IAM"""
        try:
            # IAM es un servicio global, usar región genérica
            try:
                region = IamRegion.value_of("ap-southeast-1")
            except:
                region = Region("ap-southeast-1", "https://iam.myhuaweicloud.com")
            
            return IamClient.new_builder() \
                .with_credentials(self.credentials) \
                .with_region(region) \
                .build()
            
        except Exception as e:
            self.logger.error(f"Error inicializando cliente IAM: {str(e)}")
            # Intentar sin región específica
            return IamClient.new_builder() \
                .with_credentials(self.credentials) \
                .with_endpoint("https://iam.myhuaweicloud.com") \
                .build()
    
    async def collect_all(self) -> Dict[str, Any]:
        """Recolectar todos los datos IAM"""
        self.logger.info("Iniciando recolección de datos IAM")
        
        results = {
            'users': [],
            'groups': [],
            'roles': [],
            'policies': [],
            'access_keys': [],
            'mfa_status': {
                'total_users': 0,
                'mfa_enabled': 0,
                'mfa_disabled': 0,
                'users_without_mfa': []
            },
            'password_policy': {},
            'login_policy': {},
            'protection_policy': {},
            'permissions_analysis': {},
            'user_group_mappings': {},
            'role_assignments': {},
            'service_accounts': [],
            'privileged_accounts': [],
            'inactive_users': [],
            'findings': self.findings,
            'statistics': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Recolectar usuarios primero
            results['users'] = await self._collect_users()
            self.logger.info(f"Usuarios recolectados: {len(results['users'])}")
            
            # Recolectar información de MFA para cada usuario
            results['mfa_status'] = await self._collect_mfa_status(results['users'])
            
            # Resto de recolecciones
            results['groups'] = await self._collect_groups()
            results['roles'] = await self._collect_roles()
            results['policies'] = await self._collect_policies()
            results['access_keys'] = await self._collect_access_keys(results['users'])
            results['password_policy'] = await self._collect_password_policy()
            results['login_policy'] = await self._collect_login_policy()
            results['protection_policy'] = await self._collect_protection_policy()
            
            # Análisis adicionales
            results['user_group_mappings'] = await self._collect_user_group_mappings(results['users'])
            results['role_assignments'] = await self._collect_role_assignments(results['users'])
            results['permissions_analysis'] = await self._analyze_effective_permissions(results)
            results['service_accounts'] = await self._identify_service_accounts(results['users'])
            results['privileged_accounts'] = await self._identify_privileged_accounts(results)
            results['inactive_users'] = await self._identify_inactive_users(results['users'])
            
            # Análisis de seguridad avanzados
            await self._analyze_password_age(results['users'])
            await self._analyze_permission_boundaries(results)
            await self._analyze_cross_account_access(results)
            await self._analyze_identity_providers()
            await self._check_root_account_usage()
            
            # Calcular estadísticas
            results['statistics'] = self._calculate_statistics(results)
            
        except Exception as e:
            self.logger.error(f"Error durante la recolección: {str(e)}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
        
        self.logger.info(f"Recolección IAM completada. Hallazgos: {len(self.findings)}")
        return results
    
    async def _collect_users(self) -> List[Dict]:
        """Recolectar información completa de usuarios"""
        users = []
        self.processed_users.clear()
        
        try:
            request = KeystoneListUsersRequest()
            response = self.client.keystone_list_users(request)
            
            self.logger.info(f"Total de usuarios encontrados: {len(response.users)}")
            
            for idx, user in enumerate(response.users):
                # Evitar duplicados
                if user.id in self.processed_users:
                    continue
                    
                self.processed_users.add(user.id)
                self.logger.info(f"Procesando usuario {idx+1}/{len(response.users)}: {user.name}")
                
                # Recolectar información básica
                user_info = {
                    'id': user.id,
                    'name': user.name,
                    'domain_id': user.domain_id,
                    'enabled': getattr(user, 'enabled', True),
                    'password_expires_at': getattr(user, 'password_expires_at', None),
                    'description': getattr(user, 'description', ''),
                    'email': getattr(user, 'email', ''),
                    'create_time': getattr(user, 'create_time', None),
                    'last_login_time': getattr(user, 'last_login_time', None),
                    'pwd_status': getattr(user, 'pwd_status', None),
                    'pwd_strength': getattr(user, 'pwd_strength', None),
                    'links': getattr(user, 'links', {}),
                    'phone': getattr(user, 'phone', ''),
                    'is_domain_owner': getattr(user, 'is_domain_owner', False),
                    'access_mode': getattr(user, 'access_mode', 'default')
                }
                
                # Obtener información adicional del usuario
                try:
                    detailed_info = await self._get_user_details(user.id)
                    user_info.update(detailed_info)
                except Exception as e:
                    self.logger.debug(f"No se pudo obtener detalles adicionales para {user.name}: {str(e)}")
                
                # Verificaciones de seguridad
                await self._check_user_security_issues(user_info)
                
                users.append(user_info)
                self.user_cache[user.id] = user_info
                
        except Exception as e:
            self.logger.error(f"Error recolectando usuarios: {str(e)}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            
        return users
    
    async def _get_user_details(self, user_id: str) -> Dict[str, Any]:
        """Obtener detalles adicionales de un usuario"""
        details = {}
        
        try:
            # Obtener información extendida del usuario
            request = KeystoneShowUserRequest()
            request.user_id = user_id
            response = self.client.keystone_show_user(request)
            
            user = response.user
            details.update({
                'xuser_id': getattr(user, 'xuser_id', None),
                'xuser_type': getattr(user, 'xuser_type', None),
                'areacode': getattr(user, 'areacode', None),
                'login_protect_status': getattr(user, 'login_protect_status', None),
                'xdomain_id': getattr(user, 'xdomain_id', None),
                'xdomain_type': getattr(user, 'xdomain_type', None)
            })
        except Exception as e:
            self.logger.debug(f"Error obteniendo detalles del usuario {user_id}: {str(e)}")
        
        return details
    
    async def _check_user_security_issues(self, user_info: Dict):
        """Verificar problemas de seguridad específicos del usuario"""
        # Contraseñas temporales no cambiadas
        if user_info.get('pwd_status') is False:
            self._add_finding(
                'IAM-006',
                'HIGH',
                f'Usuario con contraseña temporal no cambiada: {user_info["name"]}',
                {'user_id': user_info['id'], 'user_name': user_info['name']}
            )
        
        # Usuarios sin login reciente
        if user_info.get('last_login_time'):
            try:
                last_login = datetime.fromisoformat(user_info['last_login_time'].replace('Z', '+00:00'))
                days_since_login = (datetime.now() - last_login).days
                
                if days_since_login > 90:
                    self._add_finding(
                        'IAM-009',
                        'MEDIUM',
                        f'Usuario inactivo por {days_since_login} días: {user_info["name"]}',
                        {
                            'user_id': user_info['id'],
                            'user_name': user_info['name'],
                            'last_login': user_info['last_login_time'],
                            'days_inactive': days_since_login
                        }
                    )
            except:
                pass
        
        # Verificar si es cuenta de servicio sin rotación
        if self._is_service_account(user_info):
            # Las cuentas de servicio necesitan atención especial
            if not user_info.get('last_login_time'):
                self._add_finding(
                    'IAM-010',
                    'LOW',
                    f'Cuenta de servicio sin uso registrado: {user_info["name"]}',
                    {'user_id': user_info['id'], 'user_name': user_info['name']}
                )
    
    async def _collect_mfa_status(self, users: List[Dict]) -> Dict[str, Any]:
        """Verificar estado de MFA para todos los usuarios"""
        mfa_status = {
            'total_users': len(users),
            'mfa_enabled': 0,
            'mfa_disabled': 0,
            'users_without_mfa': [],
            'mfa_types': {
                'virtual': 0,
                'sms': 0,
                'email': 0,
                'hardware': 0
            }
        }
        
        for user in users:
            try:
                # Verificar dispositivos MFA virtuales
                mfa_info = await self._check_user_mfa_detailed(user['id'])
                
                if mfa_info['has_mfa']:
                    mfa_status['mfa_enabled'] += 1
                    # Contar tipos de MFA
                    for mfa_type in mfa_info['types']:
                        if mfa_type in mfa_status['mfa_types']:
                            mfa_status['mfa_types'][mfa_type] += 1
                else:
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
                # Asumir sin MFA si no se puede verificar
                mfa_status['mfa_disabled'] += 1
                mfa_status['users_without_mfa'].append({
                    'user_id': user['id'],
                    'user_name': user['name']
                })
        
        # Hallazgo general si hay muchos usuarios sin MFA
        mfa_percentage = (mfa_status['mfa_enabled'] / mfa_status['total_users'] * 100) if mfa_status['total_users'] > 0 else 0
        if mfa_percentage < 80:
            self._add_finding(
                'IAM-007',
                'HIGH',
                f'Bajo porcentaje de adopción de MFA: {mfa_percentage:.1f}%',
                {
                    'total_users': mfa_status['total_users'],
                    'mfa_enabled': mfa_status['mfa_enabled'],
                    'percentage': mfa_percentage
                }
            )
        
        return mfa_status
    
    async def _check_user_mfa_detailed(self, user_id: str) -> Dict[str, Any]:
        """Verificar MFA con detalles del tipo"""
        mfa_info = {
            'has_mfa': False,
            'types': [],
            'devices': []
        }
        
        try:
            # Verificar dispositivos MFA virtuales
            request = ListUserMfaDevicesRequest()
            request.user_id = user_id
            response = self.client.list_user_mfa_devices(request)
            
            if hasattr(response, 'virtual_mfa_devices') and response.virtual_mfa_devices:
                mfa_info['has_mfa'] = True
                mfa_info['types'].append('virtual')
                for device in response.virtual_mfa_devices:
                    mfa_info['devices'].append({
                        'type': 'virtual',
                        'serial_number': getattr(device, 'serial_number', 'N/A'),
                        'create_time': getattr(device, 'create_time', None)
                    })
            
        except Exception as e:
            self.logger.debug(f"Error verificando MFA virtual para {user_id}: {str(e)}")
        
        # Verificar métodos de protección de login
        try:
            request = ListUserLoginProtectsRequest()
            request.user_id = user_id
            response = self.client.list_user_login_protects(request)
            
            if hasattr(response, 'login_protects') and response.login_protects:
                for protect in response.login_protects:
                    if protect.enabled:
                        mfa_info['has_mfa'] = True
                        if protect.method == 'sms':
                            mfa_info['types'].append('sms')
                        elif protect.method == 'email':
                            mfa_info['types'].append('email')
                        
                        mfa_info['devices'].append({
                            'type': protect.method,
                            'verified': protect.verified,
                            'user_id': protect.user_id
                        })
        except Exception as e:
            self.logger.debug(f"Error verificando login protects para {user_id}: {str(e)}")
        
        return mfa_info
    
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
                    'create_time': getattr(group, 'create_time', None),
                    'links': getattr(group, 'links', {})
                }
                
                # Obtener miembros del grupo
                try:
                    members = await self._get_group_members(group.id)
                    group_info['member_count'] = len(members)
                    group_info['members'] = members
                except:
                    group_info['member_count'] = 0
                    group_info['members'] = []
                
                groups.append(group_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando grupos: {str(e)}")
            
        return groups
    
    async def _get_group_members(self, group_id: str) -> List[Dict]:
        """Obtener miembros de un grupo"""
        members = []
        try:
            request = KeystoneListUsersForGroupByAdminRequest()
            request.group_id = group_id
            response = self.client.keystone_list_users_for_group_by_admin(request)
            
            for user in response.users:
                members.append({
                    'user_id': user.id,
                    'user_name': user.name
                })
        except Exception as e:
            self.logger.debug(f"Error obteniendo miembros del grupo {group_id}: {str(e)}")
        
        return members
    
    async def _collect_roles(self) -> List[Dict]:
        """Recolectar información de roles"""
        roles = []
        
        try:
            # Listar roles del sistema
            request = ListRolesRequest()
            response = self.client.list_roles(request)
            
            for role in response.roles:
                role_info = {
                    'id': role.id,
                    'name': role.name,
                    'display_name': getattr(role, 'display_name', role.name),
                    'type': getattr(role, 'type', 'system'),
                    'description': getattr(role, 'description', ''),
                    'catalog': getattr(role, 'catalog', ''),
                    'policy': getattr(role, 'policy', {}),
                    'domain_id': getattr(role, 'domain_id', HUAWEI_DOMAIN_ID),
                    'references': getattr(role, 'references', 0)
                }
                
                # Analizar permisos del rol
                if role_info['policy']:
                    self._analyze_role_permissions(role_info)
                
                roles.append(role_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando roles del sistema: {str(e)}")
        
        # También obtener roles custom
        try:
            custom_roles = await self._collect_custom_roles()
            roles.extend(custom_roles)
        except:
            pass
        
        return roles
    
    async def _collect_custom_roles(self) -> List[Dict]:
        """Recolectar roles personalizados"""
        custom_roles = []
        
        try:
            request = ListCustomPoliciesRequest()
            response = self.client.list_custom_policies(request)
            
            for policy in response.roles:
                role_info = {
                    'id': policy.id,
                    'name': policy.name,
                    'display_name': policy.display_name,
                    'type': 'custom',
                    'description': policy.description,
                    'policy': policy.policy,
                    'created': getattr(policy, 'created', None),
                    'references': getattr(policy, 'references', 0)
                }
                
                # Verificar permisos excesivos
                if self._check_excessive_permissions(policy.policy):
                    self._add_finding(
                        'IAM-003',
                        'HIGH',
                        f'Rol personalizado con permisos excesivos: {policy.display_name}',
                        {
                            'role_id': policy.id,
                            'role_name': policy.display_name,
                            'type': 'custom'
                        }
                    )
                
                custom_roles.append(role_info)
                
        except Exception as e:
            self.logger.debug(f"Error recolectando roles personalizados: {str(e)}")
        
        return custom_roles
    
    async def _collect_policies(self) -> List[Dict]:
        """Recolectar políticas IAM"""
        policies = []
        
        # Recolectar políticas custom ya se hace en _collect_custom_roles
        # Aquí podemos agregar análisis adicional de políticas
        
        try:
            # Analizar políticas adjuntas a usuarios/grupos/roles
            # Esto requeriría iterar sobre las asignaciones
            pass
        except Exception as e:
            self.logger.debug(f"Error analizando políticas: {str(e)}")
        
        return policies
    
    async def _collect_access_keys(self, users: List[Dict]) -> List[Dict]:
        """Recolectar información de access keys"""
        access_keys = []
        
        for user in users:
            try:
                request = ListPermanentAccessKeysRequest()
                request.user_id = user['id']
                response = self.client.list_permanent_access_keys(request)
                
                for key in response.credentials:
                    created_at = getattr(key, 'create_time', None)
                    if created_at:
                        # Parsear fecha si es string
                        if isinstance(created_at, str):
                            try:
                                create_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                            except:
                                create_date = datetime.now()
                        else:
                            create_date = created_at
                        
                        key_age = (datetime.now() - create_date).days
                    else:
                        key_age = 0
                    
                    # Obtener último uso
                    last_used = await self._get_access_key_last_used(key.access)
                    
                    key_info = {
                        'access_key_id': key.access,
                        'user_id': user['id'],
                        'user_name': user['name'],
                        'status': key.status,
                        'created_at': created_at,
                        'age_days': key_age,
                        'description': getattr(key, 'description', ''),
                        'last_used': last_used,
                        'last_used_service': last_used.get('service') if last_used else None,
                        'last_used_region': last_used.get('region') if last_used else None
                    }
                    
                    # Verificaciones de seguridad
                    await self._check_access_key_security(key_info, user)
                    
                    access_keys.append(key_info)
                    
            except Exception as e:
                self.logger.debug(f"Error recolectando access keys para usuario {user['id']}: {str(e)}")
                
        return access_keys
    
    async def _get_access_key_last_used(self, access_key_id: str) -> Optional[Dict]:
        """Obtener información del último uso de una access key"""
        try:
            request = ShowPermanentAccessKeyRequest()
            request.access_key = access_key_id
            response = self.client.show_permanent_access_key(request)
            
            if hasattr(response.credential, 'last_use_time'):
                return {
                    'timestamp': response.credential.last_use_time,
                    'service': getattr(response.credential, 'service', 'unknown'),
                    'region': getattr(response.credential, 'region', 'unknown')
                }
        except:
            pass
        
        return None
    
    async def _check_access_key_security(self, key_info: Dict, user: Dict):
        """Verificar seguridad de access keys"""
        # Keys sin rotación
        if key_info['age_days'] > 90 and key_info['status'] == 'active':
            self._add_finding(
                'IAM-004',
                'HIGH',
                f'Access Key sin rotación por {key_info["age_days"]} días',
                {
                    'user_name': user['name'],
                    'access_key_id': key_info['access_key_id'][:10] + '****',
                    'age_days': key_info['age_days']
                }
            )
        
        # Keys sin uso
        if key_info['age_days'] > 30 and not key_info['last_used']:
            self._add_finding(
                'IAM-011',
                'MEDIUM',
                f'Access Key creada pero nunca usada',
                {
                    'user_name': user['name'],
                    'access_key_id': key_info['access_key_id'][:10] + '****',
                    'age_days': key_info['age_days']
                }
            )
        
        # Múltiples keys activas
        if key_info['status'] == 'active':
            active_keys_count = sum(1 for k in self.findings 
                                  if k.get('details', {}).get('user_name') == user['name'] 
                                  and 'active_key' in k.get('id', ''))
            if active_keys_count > 1:
                self._add_finding(
                    'IAM-012',
                    'LOW',
                    f'Usuario con múltiples access keys activas',
                    {
                        'user_name': user['name'],
                        'active_keys': active_keys_count + 1
                    }
                )
    
    async def _collect_password_policy(self) -> Dict[str, Any]:
        """Recolectar política de contraseñas del dominio"""
        policy = {}
        try:
            request = ShowDomainPasswordPolicyRequest()
            request.domain_id = HUAWEI_DOMAIN_ID
            response = self.client.show_domain_password_policy(request)
            
            pp = response.password_policy
            policy = {
                'minimum_password_length': pp.minimum_length,
                'maximum_password_length': pp.maximum_length,
                'maximum_consecutive_identical_chars': pp.maximum_consecutive_identical_chars,
                'number_of_recent_passwords_disallowed' = pp.number_of_recent_passwords_disallowed,
                'require_uppercase': pp.uppercase_requirements > 0,
                'require_lowercase': pp.lowercase_requirements > 0,
                'require_numbers': pp.number_requirements > 0,
                'require_special': pp.special_character_requirements > 0,
                'password_validity_period': pp.password_validity_period,
                'number_of_recent_passwords_disallowed': pp.number_of_recent_passwords_disallowed,
                'password_not_username_or_invert': pp.password_not_username_or_invert,
                'maximum_consecutive_identical_chars': getattr(pp, 'maximum_consecutive_identical_chars', 0),
                'minimum_password_age': getattr(pp, 'minimum_password_age', 0)
            }
            
            # Verificaciones de seguridad
            await self._check_password_policy_security(policy)
                
        except Exception as e:
            self.logger.error(f"Error recolectando política de contraseñas: {str(e)}")
            
        return policy
    
    async def _check_password_policy_security(self, policy: Dict):
        """Verificar seguridad de la política de contraseñas"""
        issues = []
        
        # Longitud mínima
        if policy['minimum_length'] < PASSWORD_POLICY['min_length']:
            issues.append(f"Longitud mínima insuficiente ({policy['minimum_length']} < {PASSWORD_POLICY['min_length']})")
            self._add_finding(
                'IAM-005',
                'MEDIUM',
                f'Política de contraseñas débil: longitud mínima {policy["minimum_length"]}',
                {
                    'current_length': policy['minimum_length'], 
                    'required_length': PASSWORD_POLICY['min_length']
                }
            )
        
        # Complejidad
        complexity_missing = []
        if not policy['require_uppercase']:
            complexity_missing.append('mayúsculas')
        if not policy['require_lowercase']:
            complexity_missing.append('minúsculas')
        if not policy['require_numbers']:
            complexity_missing.append('números')
        if not policy['require_special']:
            complexity_missing.append('caracteres especiales')
        
        if complexity_missing:
            self._add_finding(
                'IAM-008',
                'MEDIUM',
                'Política de contraseñas no requiere todos los tipos de caracteres',
                {
                    'missing_requirements': complexity_missing,
                    'current_policy': {
                        'uppercase': policy['require_uppercase'],
                        'lowercase': policy['require_lowercase'],
                        'numbers': policy['require_numbers'],
                        'special': policy['require_special']
                    }
                }
            )
        
        # Período de validez
        if policy['password_validity_period'] == 0:
            self._add_finding(
                'IAM-013',
                'MEDIUM',
                'Contraseñas sin expiración configurada',
                {'current_setting': 'Las contraseñas nunca expiran'}
            )
        elif policy['password_validity_period'] > PASSWORD_POLICY['max_age_days']:
            self._add_finding(
                'IAM-014',
                'LOW',
                f'Período de validez de contraseñas muy largo: {policy["password_validity_period"]} días',
                {
                    'current_days': policy['password_validity_period'],
                    'recommended_days': PASSWORD_POLICY['max_age_days']
                }
            )
        
        # Historial de contraseñas
        if policy['number_of_recent_passwords_disallowed'] < PASSWORD_POLICY['history_count']:
            self._add_finding(
                'IAM-015',
                'LOW',
                f'Historial de contraseñas insuficiente: {policy["number_of_recent_passwords_disallowed"]}',
                {
                    'current_history': policy['number_of_recent_passwords_disallowed'],
                    'recommended_history': PASSWORD_POLICY['history_count']
                }
            )
    
    async def _collect_login_policy(self) -> Dict[str, Any]:
        """Recolectar política de login del dominio"""
        policy = {}
        try:
            request = ShowDomainLoginPolicyRequest()
            request.domain_id = HUAWEI_DOMAIN_ID
            response = self.client.show_domain_login_policy(request)
            
            lp = response.login_policy
            policy = {
                'account_validity_period': lp.account_validity_period,
                'custom_info_for_login': lp.custom_info_for_login,
                'lockout_duration': lp.lockout_duration,
                'login_failed_times': lp.login_failed_times,
                'period_with_login_failures': lp.period_with_login_failures,
                'session_timeout': lp.session_timeout,
                'show_recent_login_info': lp.show_recent_login_info
            }
            
            # Verificar configuración de bloqueo
            if lp.login_failed_times == 0:
                self._add_finding(
                    'IAM-016',
                    'HIGH',
                    'Sin política de bloqueo por intentos fallidos',
                    {'current_setting': 'Intentos ilimitados permitidos'}
                )
            elif lp.login_failed_times > PASSWORD_POLICY['lockout_attempts']:
                self._add_finding(
                    'IAM-017',
                    'MEDIUM',
                    f'Umbral de bloqueo muy alto: {lp.login_failed_times} intentos',
                    {
                        'current_attempts': lp.login_failed_times,
                        'recommended_attempts': PASSWORD_POLICY['lockout_attempts']
                    }
                )
            
            # Verificar timeout de sesión
            if lp.session_timeout == 0:
                self._add_finding(
                    'IAM-018',
                    'MEDIUM',
                    'Sin timeout de sesión configurado',
                    {'risk': 'Las sesiones permanecen activas indefinidamente'}
                )
            
        except Exception as e:
            self.logger.error(f"Error recolectando política de login: {str(e)}")
        
        return policy
    
    async def _collect_protection_policy(self) -> Dict[str, Any]:
        """Recolectar política de protección del dominio"""
        policy = {}
        try:
            request = ShowDomainProtectPolicyRequest()
            request.domain_id = HUAWEI_DOMAIN_ID
            response = self.client.show_domain_protect_policy(request)
            
            pp = response.protect_policy
            policy = {
                'allow_user_to_manage_access_keys': pp.allow_user_to_manage_access_keys,
                'allow_user_to_manage_password': pp.allow_user_to_manage_password,
                'allow_user_to_manage_mfa_devices': pp.allow_user_to_manage_mfa_devices,
                'self_management': getattr(pp, 'self_management', {})
            }
            
            # Verificar autogestión
            if not pp.allow_user_to_manage_mfa_devices:
                self._add_finding(
                    'IAM-019',
                    'LOW',
                    'Usuarios no pueden gestionar sus propios dispositivos MFA',
                    {'impact': 'Puede reducir la adopción de MFA'}
                )
            
        except Exception as e:
            self.logger.debug(f"Error recolectando política de protección: {str(e)}")
        
        return policy
    
    async def _collect_user_group_mappings(self, users: List[Dict]) -> Dict[str, List]:
        """Recolectar mapeo de usuarios a grupos"""
        mappings = {}
        
        for user in users:
            try:
                request = KeystoneListGroupsForUserRequest()
                request.user_id = user['id']
                response = self.client.keystone_list_groups_for_user(request)
                
                user_groups = []
                for group in response.groups:
                    user_groups.append({
                        'group_id': group.id,
                        'group_name': group.name
                    })
                
                mappings[user['id']] = user_groups
                
                # Verificar usuarios sin grupos
                if not user_groups:
                    self._add_finding(
                        'IAM-020',
                        'LOW',
                        f'Usuario sin grupos asignados: {user["name"]}',
                        {'user_id': user['id'], 'user_name': user['name']}
                    )
                
            except Exception as e:
                self.logger.debug(f"Error obteniendo grupos para usuario {user['id']}: {str(e)}")
                mappings[user['id']] = []
        
        return mappings
    
    async def _collect_role_assignments(self, users: List[Dict]) -> Dict[str, Any]:
        """Recolectar asignaciones de roles"""
        assignments = {
            'user_roles': {},
            'group_roles': {},
            'total_assignments': 0
        }
        
        # Roles por usuario
        for user in users:
            try:
                user_roles = await self._get_user_roles(user['id'])
                assignments['user_roles'][user['id']] = user_roles
                assignments['total_assignments'] += len(user_roles)
            except:
                assignments['user_roles'][user['id']] = []
        
        return assignments
    
    async def _get_user_roles(self, user_id: str) -> List[Dict]:
        """Obtener roles asignados a un usuario"""
        roles = []
        try:
            # Obtener roles a nivel de proyecto
            request = ListProjectPermissionsForEnterpriseProjectRequest()
            # Configurar request según necesidad
            # Este es un ejemplo simplificado
        except:
            pass
        
        return roles
    
    async def _analyze_effective_permissions(self, results: Dict) -> Dict[str, Any]:
        """Analizar permisos efectivos de usuarios"""
        analysis = {
            'users_with_admin_access': [],
            'overprivileged_users': [],
            'permission_conflicts': [],
            'unused_permissions': []
        }
        
        # Analizar cada usuario
        for user in results['users']:
            user_perms = await self._calculate_user_effective_permissions(
                user, 
                results.get('user_group_mappings', {}).get(user['id'], []),
                results.get('role_assignments', {}).get('user_roles', {}).get(user['id'], [])
            )
            
            # Verificar acceso administrativo
            if self._has_admin_permissions(user_perms):
                analysis['users_with_admin_access'].append({
                    'user_id': user['id'],
                    'user_name': user['name'],
                    'source': user_perms.get('admin_source', 'unknown')
                })
                
                self._add_finding(
                    'IAM-001',
                    'CRITICAL',
                    f'Usuario con privilegios administrativos: {user["name"]}',
                    {
                        'user_id': user['id'],
                        'user_name': user['name'],
                        'permissions_source': user_perms.get('admin_source', 'unknown')
                    }
                )
        
        return analysis
    
    async def _calculate_user_effective_permissions(self, user: Dict, groups: List, roles: List) -> Dict:
        """Calcular permisos efectivos de un usuario"""
        permissions = {
            'direct_roles': roles,
            'group_inherited': [],
            'effective_actions': set(),
            'admin_source': None
        }
        
        # Agregar permisos de grupos
        for group in groups:
            if any(admin_keyword in group['group_name'].lower() 
                   for admin_keyword in ['admin', 'administrator', 'power']):
                permissions['admin_source'] = f"group:{group['group_name']}"
        
        return permissions
    
    def _has_admin_permissions(self, permissions: Dict) -> bool:
        """Verificar si los permisos incluyen acceso administrativo"""
        return permissions.get('admin_source') is not None
    
    async def _identify_service_accounts(self, users: List[Dict]) -> List[Dict]:
        """Identificar cuentas de servicio"""
        service_accounts = []
        
        for user in users:
            if self._is_service_account(user):
                service_accounts.append({
                    'user_id': user['id'],
                    'user_name': user['name'],
                    'indicators': self._get_service_account_indicators(user)
                })
        
        return service_accounts
    
    def _is_service_account(self, user: Dict) -> bool:
        """Determinar si es cuenta de servicio"""
        indicators = [
            'service' in user['name'].lower(),
            'svc' in user['name'].lower(),
            'app' in user['name'].lower(),
            'api' in user['name'].lower(),
            'system' in user['name'].lower(),
            not user.get('email'),  # Sin email
            user.get('description', '').lower() in ['service account', 'api user', 'system user']
        ]
        
        return sum(indicators) >= 2
    
    def _get_service_account_indicators(self, user: Dict) -> List[str]:
        """Obtener indicadores de cuenta de servicio"""
        indicators = []
        
        if 'service' in user['name'].lower():
            indicators.append('Nombre contiene "service"')
        if not user.get('email'):
            indicators.append('Sin email asociado')
        if not user.get('last_login_time'):
            indicators.append('Sin login interactivo')
        
        return indicators
    
    async def _identify_privileged_accounts(self, results: Dict) -> List[Dict]:
        """Identificar cuentas privilegiadas"""
        privileged = []
        
        # Basarse en el análisis de permisos efectivos
        admin_users = results.get('permissions_analysis', {}).get('users_with_admin_access', [])
        
        for admin in admin_users:
            # Buscar información adicional del usuario
            user_info = next((u for u in results['users'] if u['id'] == admin['user_id']), {})
            
            privileged.append({
                'user_id': admin['user_id'],
                'user_name': admin['user_name'],
                'privilege_source': admin['source'],
                'last_login': user_info.get('last_login_time'),
                'mfa_enabled': admin['user_id'] not in [u['user_id'] 
                    for u in results['mfa_status']['users_without_mfa']]
            })
        
        return privileged
    
    async def _identify_inactive_users(self, users: List[Dict]) -> List[Dict]:
        """Identificar usuarios inactivos"""
        inactive = []
        
        for user in users:
            if user.get('last_login_time'):
                try:
                    last_login = datetime.fromisoformat(user['last_login_time'].replace('Z', '+00:00'))
                    days_inactive = (datetime.now() - last_login).days
                    
                    if days_inactive > 90:
                        inactive.append({
                            'user_id': user['id'],
                            'user_name': user['name'],
                            'last_login': user['last_login_time'],
                            'days_inactive': days_inactive,
                            'enabled': user.get('enabled', True)
                        })
                except:
                    pass
            else:
                # Usuario sin login registrado
                if user.get('create_time'):
                    try:
                        created = datetime.fromisoformat(user['create_time'].replace('Z', '+00:00'))
                        days_since_creation = (datetime.now() - created).days
                        
                        if days_since_creation > 30:
                            inactive.append({
                                'user_id': user['id'],
                                'user_name': user['name'],
                                'last_login': 'Nunca',
                                'days_inactive': days_since_creation,
                                'enabled': user.get('enabled', True)
                            })
                    except:
                        pass
        
        return inactive
    
    async def _analyze_password_age(self, users: List[Dict]):
        """Analizar edad de contraseñas"""
        for user in users:
            if user.get('password_expires_at'):
                try:
                    expires = datetime.fromisoformat(user['password_expires_at'].replace('Z', '+00:00'))
                    
                    if expires < datetime.now():
                        self._add_finding(
                            'IAM-021',
                            'HIGH',
                            f'Usuario con contraseña expirada: {user["name"]}',
                            {
                                'user_id': user['id'],
                                'user_name': user['name'],
                                'expired_since': expires.isoformat()
                            }
                        )
                except:
                    pass
    
    async def _analyze_permission_boundaries(self, results: Dict):
        """Analizar límites de permisos"""
        # Verificar si hay políticas de límites de permisos configuradas
        users_without_boundaries = []
        
        for user in results['users']:
            # En Huawei Cloud, esto puede requerir verificación específica
            # Por ahora, verificamos si hay políticas restrictivas
            has_boundary = False  # Simplificado
            
            if not has_boundary and await self._check_admin_privileges(user['id']):
                users_without_boundaries.append(user)
        
        if users_without_boundaries:
            self._add_finding(
                'IAM-022',
                'MEDIUM',
                f'{len(users_without_boundaries)} usuarios administrativos sin límites de permisos',
                {
                    'users': [u['name'] for u in users_without_boundaries[:5]],
                    'total': len(users_without_boundaries)
                }
            )
    
    async def _analyze_cross_account_access(self, results: Dict):
        """Analizar acceso entre cuentas"""
        # En Huawei Cloud esto se relaciona con IAM Agency
        try:
            request = ListAgenciesRequest()
            response = self.client.list_agencies(request)
            
            for agency in response.agencies:
                # Verificar agencies con permisos amplios
                if agency.trust_domain_name != HUAWEI_DOMAIN_ID:
                    self._add_finding(
                        'IAM-023',
                        'MEDIUM',
                        f'Agency con acceso desde dominio externo: {agency.name}',
                        {
                            'agency_name': agency.name,
                            'trust_domain': agency.trust_domain_name,
                            'description': agency.description
                        }
                    )
        except Exception as e:
            self.logger.debug(f"Error analizando agencies: {str(e)}")
    
    async def _analyze_identity_providers(self):
        """Analizar proveedores de identidad federados"""
        try:
            request = KeystoneListIdentityProvidersRequest()
            response = self.client.keystone_list_identity_providers(request)
            
            for idp in response.identity_providers:
                # Verificar configuración de IdP
                if not idp.enabled:
                    self._add_finding(
                        'IAM-024',
                        'LOW',
                        f'Proveedor de identidad deshabilitado: {idp.id}',
                        {
                            'idp_id': idp.id,
                            'description': idp.description
                        }
                    )
        except Exception as e:
            self.logger.debug(f"Error analizando identity providers: {str(e)}")
    
    async def _check_root_account_usage(self):
        """Verificar uso de cuenta root"""
        # En Huawei Cloud, verificar el uso del usuario principal del dominio
        try:
            # Buscar eventos de login del usuario root/principal
            # Esto requeriría acceso a logs de auditoría (CTS)
            pass
        except:
            pass
    
    def _analyze_role_permissions(self, role: Dict):
        """Analizar permisos de un rol"""
        if role.get('policy'):
            # Verificar patrones peligrosos
            policy_str = str(role['policy'])
            
            dangerous_patterns = {
                'full_admin': ['*:*:*', '"Action": ["*"]'],
                'iam_admin': ['iam:*', 'iam:users:*', 'iam:groups:*'],
                'data_exfiltration': ['obs:*:get', 'obs:*:list', 'evs:*:get']
            }
            
            for risk_type, patterns in dangerous_patterns.items():
                if any(pattern in policy_str for pattern in patterns):
                    self._add_finding(
                        'IAM-025',
                        'HIGH' if risk_type == 'full_admin' else 'MEDIUM',
                        f'Rol con permisos de riesgo ({risk_type}): {role["name"]}',
                        {
                            'role_id': role['id'],
                            'role_name': role['name'],
                            'risk_type': risk_type
                        }
                    )
    
    async def _check_admin_privileges(self, user_id: str) -> bool:
        """Verificar si un usuario tiene privilegios administrativos"""
        try:
            # Verificar grupos administrativos
            request = KeystoneListGroupsForUserRequest()
            request.user_id = user_id
            response = self.client.keystone_list_groups_for_user(request)
            
            admin_groups = ['admin', 'administrator', 'power_user', 'be61248cddbf441e9446e8bc5a2bf26f']
            for group in response.groups:
                if any(admin in group.name.lower() for admin in admin_groups[:3]) or group.id in admin_groups:
                    return True
            
            # También verificar roles directos
            # Esto requeriría verificación adicional de roles asignados
            
        except Exception as e:
            self.logger.debug(f"Error verificando privilegios para usuario {user_id}: {str(e)}")
            
        return False
    
    def _check_excessive_permissions(self, policy: dict) -> bool:
        """Verificar si una política tiene permisos excesivos"""
        if not policy:
            return False
            
        # Buscar patrones de permisos excesivos
        excessive_patterns = [
            '"Action": ["*"]',
            '"Action": "*"',
            '"Resource": ["*"]',
            '"Resource": "*"',
            'AdministratorAccess',
            '"Effect": "Allow".*"Action": "\\*"',
            '*:*:*'
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
        """Calcular estadísticas completas del análisis IAM"""
        stats = {
            'total_users': len(results['users']),
            'total_groups': len(results['groups']),
            'total_roles': len(results['roles']),
            'total_policies': len(results['policies']),
            'total_access_keys': len(results['access_keys']),
            'users_without_mfa': results['mfa_status']['mfa_disabled'],
            'mfa_compliance_rate': 0,
            'old_access_keys': 0,
            'users_with_temp_passwords': 0,
            'inactive_users': len(results['inactive_users']),
            'service_accounts': len(results['service_accounts']),
            'privileged_accounts': len(results['privileged_accounts']),
            'unused_access_keys': 0,
            'findings_by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            },
            'top_risks': []
        }
        
        # Calcular tasa de cumplimiento MFA
        if stats['total_users'] > 0:
            stats['mfa_compliance_rate'] = round(
                (results['mfa_status']['mfa_enabled'] / stats['total_users']) * 100, 2
            )
        
        # Contar access keys antiguas y sin uso
        for key in results['access_keys']:
            if key['age_days'] > 90 and key.get('status') == 'active':
                stats['old_access_keys'] += 1
            if not key.get('last_used') and key['age_days'] > 30:
                stats['unused_access_keys'] += 1
        
        # Contar usuarios con contraseñas temporales
        stats['users_with_temp_passwords'] = sum(
            1 for user in results['users'] 
            if user.get('pwd_status') is False
        )
        
        # Contar hallazgos por severidad
        for finding in self.findings:
            stats['findings_by_severity'][finding['severity']] += 1
        
        # Identificar top riesgos
        critical_findings = [f for f in self.findings if f['severity'] == 'CRITICAL']
        stats['top_risks'] = [
            {
                'id': f['id'],
                'message': f['message'][:100] + '...' if len(f['message']) > 100 else f['message']
            } 
            for f in critical_findings[:5]
        ]
        
        # Estadísticas adicionales
        stats['users_without_groups'] = sum(
            1 for mapping in results['user_group_mappings'].values() 
            if not mapping
        )
        
        stats['password_policy_compliant'] = all([
            results['password_policy'].get('minimum_length', 0) >= PASSWORD_POLICY['min_length'],
            results['password_policy'].get('require_uppercase', False),
            results['password_policy'].get('require_lowercase', False),
            results['password_policy'].get('require_numbers', False),
            results['password_policy'].get('require_special', False)
        ])
        
        return stats