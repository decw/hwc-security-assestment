#!/usr/bin/env python3
"""
Colector de datos IAM para Huawei Cloud - Versión Completa
"""

import asyncio
from datetime import datetime, timedelta, timezone
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
import re


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
                region = Region("ap-southeast-1",
                                "https://iam.myhuaweicloud.com")

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
                'users_without_mfa': [],
                'service_accounts_without_mfa': [],  # Nuevo: cuentas de servicio sin MFA
                'regular_users_without_mfa': [],     # Nuevo: usuarios regulares sin MFA
                'mfa_types': {
                    'virtual': 0,
                    'sms': 0,
                    'email': 0,
                    'hardware': 0
                },
                'verification_methods': {'sms': 0, 'email': 0,
                                         'vmfa': 0, 'disabled': 0},
                'access_mode_counts': {},
                'verification_summary': {
                    'total_console_users': 0,
                    'total_programmatic_users': 0,
                    'total_users_without_mfa': 0,
                    'total_service_accounts_without_mfa': 0,
                    'total_regular_users_without_mfa': 0,
                    'total_mfa_types': 0,
                    'total_verification_methods': 0,
                    'total_access_mode_counts': 0
                }
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
            self.logger.info("Iniciando recolección de usuarios...")
            results['users'] = await self._collect_users()
            self.logger.info(f"Usuarios recolectados: {len(results['users'])}")

            if not results['users']:
                self.logger.warning(
                    "No se encontraron usuarios. Verificar credenciales y permisos.")
                return results

            # Recolectar información de MFA para cada usuario
            self.logger.info("Iniciando recolección de estado MFA...")
            results['mfa_status'] = await self._collect_mfa_status(results['users'])
            self.logger.info(
                f"Estado MFA recolectado: {results['mfa_status']['total_users']} usuarios")

            # Resto de recolecciones
            self.logger.info("Iniciando recolección de grupos...")
            results['groups'] = await self._collect_groups()
            self.logger.info(f"Grupos recolectados: {len(results['groups'])}")

            self.logger.info("Iniciando recolección de roles...")
            results['roles'] = await self._collect_roles(results['users'])
            self.logger.info(f"Roles recolectados: {len(results['roles'])}")

            self.logger.info("Iniciando recolección de políticas...")
            results['policies'] = await self._collect_policies()
            self.logger.info(
                f"Políticas recolectadas: {len(results['policies'])}")

            self.logger.info("Iniciando recolección de access keys...")
            results['access_keys'] = await self._collect_access_keys(results['users'])
            self.logger.info(
                f"Access keys recolectadas: {len(results['access_keys'])}")

            self.logger.info(
                "Iniciando recolección de políticas de contraseñas...")
            results['password_policy'] = await self._collect_password_policy()
            self.logger.info("Política de contraseñas recolectada")

            self.logger.info("Iniciando recolección de políticas de login...")
            results['login_policy'] = await self._collect_login_policy()
            self.logger.info("Política de login recolectada")

            self.logger.info(
                "Iniciando recolección de políticas de protección...")
            results['protection_policy'] = await self._collect_protection_policy()
            self.logger.info("Política de protección recolectada")

            # Análisis adicionales
            self.logger.info("Iniciando análisis de mapeos usuario-grupo...")
            results['user_group_mappings'] = await self._collect_user_group_mappings(results['users'])
            self.logger.info("Mapeos usuario-grupo recolectados")

            self.logger.info("Iniciando análisis de asignaciones de roles...")
            results['role_assignments'] = await self._collect_role_assignments(results['users'])
            self.logger.info("Asignaciones de roles recolectadas")

            self.logger.info("Iniciando análisis de permisos efectivos...")
            results['permissions_analysis'] = await self._analyze_effective_permissions(results)
            self.logger.info("Análisis de permisos efectivos completado")

            self.logger.info(
                "Iniciando identificación de cuentas de servicio...")
            results['service_accounts'] = await self._identify_service_accounts(results['users'])
            self.logger.info(
                f"Cuentas de servicio identificadas: {len(results['service_accounts'])}")

            self.logger.info(
                "Iniciando identificación de cuentas privilegiadas...")
            results['privileged_accounts'] = await self._identify_privileged_accounts(results)
            self.logger.info(
                f"Cuentas privilegiadas identificadas: {len(results['privileged_accounts'])}")

            self.logger.info(
                "Iniciando identificación de usuarios inactivos...")
            results['inactive_users'] = await self._identify_inactive_users(results['users'])
            self.logger.info(
                f"Usuarios inactivos identificados: {len(results['inactive_users'])}")

            # Análisis de seguridad avanzados
            self.logger.info("Iniciando análisis de edad de contraseñas...")
            await self._analyze_password_age(results['users'])

            self.logger.info("Iniciando análisis de límites de permisos...")
            await self._analyze_permission_boundaries(results)

            self.logger.info("Iniciando análisis de acceso entre cuentas...")
            await self._analyze_cross_account_access(results)

            self.logger.info(
                "Iniciando análisis de proveedores de identidad...")
            await self._analyze_identity_providers()

            self.logger.info("Iniciando verificación de uso de cuenta root...")
            await self._check_root_account_usage()

            # Calcular estadísticas
            self.logger.info("Calculando estadísticas...")
            results['statistics'] = self._calculate_statistics(results)
            self.logger.info("Estadísticas calculadas")

        except Exception as e:
            self.logger.error(f"Error durante la recolección: {str(e)}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")

        self.logger.info(
            f"Recolección IAM completada. Hallazgos: {len(self.findings)}")

        # Ejecutar checks adicionales
        await self._check_onboarding_offboarding_process(results)
        await self._check_privileged_access_logging(results)
        await self._check_inline_policies(results)
        await self._check_permission_review_process(results)
        await self._check_naming_convention(results)
        await self._check_policy_versions(results)
        await self._check_api_token_expiration(results)
        await self._check_environment_segregation(results)
        await self._check_zero_trust_principles(results)
        await self._check_iam_change_audit(results)
        await self._check_generic_shared_accounts(results)
        await self._check_privileged_identity_management(results)
        await self._check_inherited_permissions_documentation(results)
        await self._check_break_glass_procedure(results)
        await self._check_certificate_management(results)
        await self._check_iam_metrics(results)

        return results

    async def _collect_users(self) -> List[Dict]:
        """Recolectar información completa de usuarios"""
        users = []
        self.processed_users.clear()

        try:
            request = KeystoneListUsersRequest()
            response = self.client.keystone_list_users(request)

            self.logger.info(
                f"Total de usuarios encontrados: {len(response.users)}")

            for idx, user in enumerate(response.users):
                # Evitar duplicados
                if user.id in self.processed_users:
                    continue

                self.processed_users.add(user.id)
                self.logger.info(
                    f"Procesando usuario {idx+1}/{len(response.users)}: {user.name}")

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

                    # Verificar si hay información de access keys en los detalles
                    if detailed_info:
                        self.logger.debug(
                            f"Información detallada obtenida para {user.name}: {list(detailed_info.keys())}")

                except Exception as e:
                    self.logger.debug(
                        f"No se pudo obtener detalles adicionales para {user.name}: {str(e)}")

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
            self.logger.debug(
                f"Error obteniendo detalles del usuario {user_id}: {str(e)}")

        return details

    async def _check_user_security_issues(self, user_info: Dict):
        """Verificar problemas de seguridad específicos del usuario"""
        # Contraseñas temporales no cambiadas
        if user_info.get('pwd_status') is False:
            self._add_finding(
                'IAM-005',
                'HIGH',
                f'Usuario con contraseña temporal no cambiada: {user_info["name"]}',
                {'user_id': user_info['id'], 'user_name': user_info['name']}
            )

        # Usuarios sin login reciente
        if user_info.get('last_login_time'):
            try:
                last_login = datetime.fromisoformat(
                    user_info['last_login_time'].replace('Z', '+00:00'))
                days_since_login = (datetime.now() - last_login).days

                if days_since_login > 90:
                    self._add_finding(
                        'IAM-005',
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
                    {'user_id': user_info['id'],
                        'user_name': user_info['name']}
                )

    async def _collect_mfa_status(self, users: List[Dict]) -> Dict[str, Any]:
        """Verificar estado de MFA para todos los usuarios"""
        # ───────────────────────────── 1.  mapa user_id → verification_method
        from huaweicloudsdkiam.v3.model import ListUserLoginProtectsRequest
        login_protect_map = {}
        try:
            lp_req = ListUserLoginProtectsRequest()          # NO se pasa user_id
            lp_resp = self.client.list_user_login_protects(lp_req)
            for p in getattr(lp_resp, 'login_protects', []):
                if p.enabled:
                    login_protect_map[p.user_id] = p.verification_method.lower()
        except Exception as e:
            self.logger.debug(f'list_user_login_protects(): {e}')

        mfa_status = {
            'total_users': len(users),
            'mfa_enabled': 0,
            'mfa_disabled': 0,
            'users_without_mfa': [],
            'service_accounts_without_mfa': [],
            'regular_users_without_mfa': [],
            'verification_methods': {'sms': 0, 'email': 0, 'vmfa': 0, 'disabled': 0},
            'access_mode_counts': {'console': 0, 'programmatic': 0, 'default': 0},
            'verification_summary': {
                'total_console_users': 0,
                'total_programmatic_users': 0,
                'total_users_without_mfa': 0,
                'total_service_accounts_without_mfa': 0,
                'total_regular_users_without_mfa': 0
            }
        }

        users_with_mfa = set()

        for user in users:
            try:
                # Obtener método de verificación del mapa pre-construido
                login_verification_method = login_protect_map.get(
                    user['id'], 'disabled')

                # Verificar si tiene MFA activo (SOLO por login_verification_method)
                has_mfa = login_verification_method != 'disabled'

                if has_mfa:
                    users_with_mfa.add(user['id'])
                    mfa_status['mfa_enabled'] += 1
                    mfa_status['verification_methods'][login_verification_method] += 1
                else:
                    mfa_status['mfa_disabled'] += 1

                # Contar por tipo de access_mode
                access_mode = user.get('access_mode', 'default')

                # Mapear access_mode a categorías
                if access_mode == 'programmatic':
                    mfa_status['access_mode_counts']['programmatic'] += 1
                    mfa_status['verification_summary']['total_programmatic_users'] += 1
                elif access_mode == 'console':
                    mfa_status['access_mode_counts']['console'] += 1
                    mfa_status['verification_summary']['total_console_users'] += 1
                else:  # 'default' o sin access_mode
                    mfa_status['access_mode_counts']['default'] += 1

                # Verificar si es cuenta de servicio
                is_service_account = self._is_service_account(user)

                if not has_mfa:  # Solo si NO tiene MFA
                    if is_service_account:
                        mfa_status['service_accounts_without_mfa'].append({
                            'user_id': user['id'],
                            'user_name': user['name']
                        })
                    else:
                        mfa_status['regular_users_without_mfa'].append({
                            'user_id': user['id'],
                            'user_name': user['name']
                        })

                        # Verificar si es usuario privilegiado sin MFA
                        if await self._check_admin_privileges(user['id']):
                            self._add_finding(
                                'IAM-002',
                                'CRITICAL',
                                f'Usuario administrador sin MFA: {user["name"]}',
                                {'user_id': user['id'],
                                    'user_name': user['name']}
                            )

            except Exception as e:
                self.logger.debug(
                    f"No se pudo verificar MFA para usuario {user['id']}: {str(e)}")
                mfa_status['mfa_disabled'] += 1

        # Calcular totales finales
        mfa_status['verification_summary']['total_programmatic_users'] = mfa_status['access_mode_counts']['programmatic']
        mfa_status['verification_summary']['total_users_without_mfa'] = len(
            mfa_status['users_without_mfa'])
        mfa_status['verification_summary']['total_service_accounts_without_mfa'] = len(
            mfa_status['service_accounts_without_mfa'])
        mfa_status['verification_summary']['total_regular_users_without_mfa'] = len(
            mfa_status['regular_users_without_mfa'])

        return mfa_status

    async def _check_user_mfa_detailed(self, user_id: str) -> Dict[str, Any]:
        """Devuelve información de dispositivos VMFA y métodos sms/email"""
        mfa_info = {'has_mfa': False, 'types': [], 'devices': []}

        # VMFA ──────────────────────────────────────────────
        ...
        # Métodos sms / email ───────────────────────────────
        try:
            from huaweicloudsdkiam.v3.model import ListUserLoginProtectsRequest
            req = ListUserLoginProtectsRequest()
            req.user_id = user_id
            resp = self.client.list_user_login_protects(req)

            if getattr(resp, 'login_protects', None):
                for p in resp.login_protects:
                    if p.enabled:
                        m = getattr(p, 'verification_method', '')
                        mfa_info['has_mfa'] = True
                        if m and m not in mfa_info['types']:
                            mfa_info['types'].append(m)
                        mfa_info['devices'].append(
                            {'type': m, 'verified': p.verified})
        except Exception as e:
            self.logger.debug(f'LoginProtect check {user_id}: {e}')

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
            response = self.client.keystone_list_users_for_group_by_admin(
                request)

            for user in response.users:
                members.append({
                    'user_id': user.id,
                    'user_name': user.name
                })
        except Exception as e:
            self.logger.debug(
                f"Error obteniendo miembros del grupo {group_id}: {str(e)}")

        return members

    async def _collect_roles(self, users: List[Dict] = None) -> List[Dict]:
        """Recolectar información de permisos efectivos de usuarios a través de grupos"""
        user_permissions = []

        self.logger.info(
            "Recolectando permisos efectivos de usuarios a través de grupos...")

        try:
            # Usar usuarios ya recolectados si se proporcionan, sino recolectarlos
            if users is None:
                users = await self._collect_users()

            # Para cada usuario, obtener sus permisos efectivos
            for user in users:
                user_permissions_data = await self._get_user_effective_permissions(user['id'])

                if user_permissions_data:
                    # Crear un "rol efectivo" basado en los permisos del usuario
                    effective_role = {
                        'id': f"effective_{user['id']}",
                        'name': f"effective_permissions_{user['name']}",
                        'display_name': f"Permisos Efectivos - {user['name']}",
                        'type': 'effective',
                        'description': f'Permisos efectivos del usuario {user["name"]} a través de sus grupos',
                        'user_id': user['id'],
                        'user_name': user['name'],
                        'permissions': user_permissions_data,
                        'groups': user_permissions_data.get('groups', []),
                        'admin_access': user_permissions_data.get('admin_access', False),
                        'privileged_services': user_permissions_data.get('privileged_services', []),
                        'effective_actions': user_permissions_data.get('effective_actions', [])
                    }

                    # Analizar permisos del usuario
                    self._analyze_user_permissions(effective_role)

                    user_permissions.append(effective_role)

        except Exception as e:
            self.logger.error(
                f"Error recolectando permisos efectivos: {str(e)}")

        self.logger.info(
            f"Permisos efectivos recolectados: {len(user_permissions)}")
        return user_permissions

    async def _get_user_effective_permissions(self, user_id: str) -> Dict[str, Any]:
        """Obtener permisos efectivos de un usuario a través de sus grupos"""
        permissions = {
            'direct_permissions': [],
            'group_permissions': [],
            'effective_actions': set(),
            'admin_access': False,
            'privileged_services': set(),
            'permission_sources': [],
            'groups': []
        }

        try:
            # 1. Obtener grupos del usuario
            user_groups = await self._get_user_groups(user_id)
            permissions['groups'] = user_groups

            for group in user_groups:
                group_perms = await self._get_group_permissions(group['group_id'])
                if group_perms:
                    permissions['group_permissions'].extend(group_perms)
                    permissions['permission_sources'].append(
                        f"group:{group['group_name']}")

                    # Verificar si es grupo administrador
                    if self._is_admin_group(group['group_name']):
                        permissions['admin_access'] = True
                        permissions['privileged_services'].add('iam_admin')

            # 2. Obtener permisos directos del usuario (si están disponibles)
            direct_perms = await self._get_user_direct_permissions(user_id)
            if direct_perms:
                permissions['direct_permissions'] = direct_perms
                permissions['permission_sources'].append(
                    'direct_user_permissions')

            # 3. Consolidar permisos efectivos
            all_permissions = permissions['direct_permissions'] + \
                permissions['group_permissions']

            for perm in all_permissions:
                if isinstance(perm, dict) and 'action' in perm:
                    permissions['effective_actions'].add(perm['action'])

                    # Identificar servicios privilegiados
                    service = perm['action'].split(
                        ':')[0] if ':' in perm['action'] else perm['action']
                    if self._is_privileged_service(service):
                        permissions['privileged_services'].add(service)

            # Convertir sets a listas para serialización JSON
            permissions['effective_actions'] = list(
                permissions['effective_actions'])
            permissions['privileged_services'] = list(
                permissions['privileged_services'])

        except Exception as e:
            self.logger.error(
                f"Error obteniendo permisos efectivos para usuario {user_id}: {str(e)}")

        return permissions

    async def _get_user_groups(self, user_id: str) -> List[Dict]:
        """Obtener grupos de un usuario"""
        groups = []
        try:
            from huaweicloudsdkiam.v3.model import KeystoneListGroupsForUserRequest
            request = KeystoneListGroupsForUserRequest()
            request.user_id = user_id
            response = self.client.keystone_list_groups_for_user(request)

            for group in response.groups:
                groups.append({
                    'group_id': group.id,
                    'group_name': group.name,
                    'description': getattr(group, 'description', '')
                })
        except Exception as e:
            self.logger.debug(
                f"Error obteniendo grupos para usuario {user_id}: {str(e)}")

        return groups

    async def _get_group_permissions(self, group_id: str) -> List[Dict]:
        """Obtener permisos de un grupo basados en su nombre y configuración"""
        permissions = []

        try:
            # Obtener información del grupo
            from huaweicloudsdkiam.v3.model import KeystoneShowGroupRequest
            request = KeystoneShowGroupRequest()
            request.group_id = group_id
            response = self.client.keystone_show_group(request)

            # Verificar que el grupo y su nombre existan
            if response.group and response.group.name:
                group_name = response.group.name.lower()
            else:
                self.logger.debug(f"Grupo {group_id} sin nombre válido")
                return permissions

            # Mapeo de nombres de grupos a permisos típicos de Huawei Cloud
            group_permission_mapping = {
                'admin': [
                    {'action': '*:*:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'admin_group'},
                    {'action': 'iam:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'admin_group'},
                    {'action': 'ecs:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'admin_group'},
                    {'action': 'vpc:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'admin_group'}
                ],
                'administrator': [
                    {'action': '*:*:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'admin_group'},
                    {'action': 'iam:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'admin_group'}
                ],
                'power': [
                    {'action': 'ecs:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'power_group'},
                    {'action': 'vpc:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'power_group'},
                    {'action': 'obs:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'power_group'},
                    {'action': 'rds:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'power_group'}
                ],
                'developer': [
                    {'action': 'ecs:get', 'resource': '*',
                        'effect': 'Allow', 'source': 'developer_group'},
                    {'action': 'ecs:list', 'resource': '*',
                        'effect': 'Allow', 'source': 'developer_group'},
                    {'action': 'obs:get', 'resource': '*',
                        'effect': 'Allow', 'source': 'developer_group'},
                    {'action': 'obs:list', 'resource': '*',
                        'effect': 'Allow', 'source': 'developer_group'},
                    {'action': 'vpc:get', 'resource': '*',
                        'effect': 'Allow', 'source': 'developer_group'}
                ],
                'readonly': [
                    {'action': '*:get', 'resource': '*',
                        'effect': 'Allow', 'source': 'readonly_group'},
                    {'action': '*:list', 'resource': '*',
                        'effect': 'Allow', 'source': 'readonly_group'},
                    {'action': '*:describe', 'resource': '*',
                        'effect': 'Allow', 'source': 'readonly_group'}
                ],
                'security': [
                    {'action': 'cts:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'security_group'},
                    {'action': 'ces:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'security_group'},
                    {'action': 'config:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'security_group'},
                    {'action': 'kms:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'security_group'}
                ],
                'network': [
                    {'action': 'vpc:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'network_group'},
                    {'action': 'elb:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'network_group'},
                    {'action': 'nat:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'network_group'}
                ],
                'storage': [
                    {'action': 'obs:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'storage_group'},
                    {'action': 'evs:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'storage_group'},
                    {'action': 'sfs:*', 'resource': '*',
                        'effect': 'Allow', 'source': 'storage_group'}
                ]
            }

            # Buscar coincidencias en el nombre del grupo
            for group_type, perms in group_permission_mapping.items():
                if group_type in group_name:
                    permissions.extend(perms)
                    break

            # Si no hay coincidencias específicas, asignar permisos básicos
            if not permissions:
                permissions = [
                    {'action': 'iam:get', 'resource': '*',
                        'effect': 'Allow', 'source': 'basic_group'},
                    {'action': 'iam:list', 'resource': '*',
                        'effect': 'Allow', 'source': 'basic_group'}
                ]

        except Exception as e:
            self.logger.debug(
                f"Error obteniendo permisos por nombre para grupo {group_id}: {str(e)}")

        return permissions

    async def _get_user_direct_permissions(self, user_id: str) -> List[Dict]:
        """Obtener permisos directos de un usuario"""
        # En Huawei Cloud, los permisos directos de usuario son limitados
        # La mayoría de permisos vienen a través de grupos
        return []

    def _is_admin_group(self, group_name: str) -> bool:
        """Verificar si un grupo es administrador"""
        admin_indicators = ['admin', 'administrator',
                            'power', 'super', 'root', 'master']
        group_lower = group_name.lower()

        return any(indicator in group_lower for indicator in admin_indicators)

    def _is_privileged_service(self, service: str) -> bool:
        """Verificar si un servicio es privilegiado"""
        privileged_services = [
            'iam', 'admin', 'security', 'kms', 'obs', 'ecs', 'vpc',
            'rds', 'elb', 'cts', 'ces', 'config', 'nat', 'evs', 'sfs'
        ]

        return service.lower() in privileged_services

    def _analyze_user_permissions(self, user_permissions: Dict):
        """Analizar permisos efectivos de un usuario"""

        permissions = user_permissions.get('permissions', {})
        user_name = user_permissions.get('user_name', 'Unknown')
        user_id = user_permissions.get('user_id', 'Unknown')

        # Verificar acceso administrador
        if permissions.get('admin_access'):
            self._add_finding(
                'IAM-001',
                'CRITICAL',
                f'Usuario con acceso administrador: {user_name}',
                {
                    'user_id': user_id,
                    'user_name': user_name,
                    'permission_sources': permissions.get('permission_sources', []),
                    'groups': [g['group_name'] for g in permissions.get('groups', [])]
                }
            )

        # Verificar servicios privilegiados
        privileged_services = permissions.get('privileged_services', [])
        if len(privileged_services) > 3:
            self._add_finding(
                'IAM-001',
                'HIGH',
                f'Usuario con acceso a múltiples servicios privilegiados: {user_name}',
                {
                    'user_id': user_id,
                    'user_name': user_name,
                    'privileged_services': privileged_services,
                    'count': len(privileged_services),
                    'groups': [g['group_name'] for g in permissions.get('groups', [])]
                }
            )

        # Verificar permisos excesivos
        effective_actions = permissions.get('effective_actions', [])
        if '*' in effective_actions or any('*:*:*' in action for action in effective_actions):
            self._add_finding(
                'IAM-006',
                'HIGH',
                f'Usuario con permisos excesivos: {user_name}',
                {
                    'user_id': user_id,
                    'user_name': user_name,
                    'excessive_actions': [a for a in effective_actions if '*' in a],
                    'groups': [g['group_name'] for g in permissions.get('groups', [])]
                }
            )

        # Verificar usuarios sin grupos
        groups = permissions.get('groups', [])
        if not groups:
            self._add_finding(
                'IAM-008',
                'MEDIUM',
                f'Usuario sin grupos asignados: {user_name}',
                {
                    'user_id': user_id,
                    'user_name': user_name,
                    'risk': 'Usuario sin estructura de permisos organizada'
                }
            )

        # Verificar usuarios con muchos grupos
        if len(groups) > 5:
            self._add_finding(
                'IAM-007',
                'LOW',
                f'Usuario con muchos grupos asignados: {user_name}',
                {
                    'user_id': user_id,
                    'user_name': user_name,
                    'group_count': len(groups),
                    'groups': [g['group_name'] for g in groups],
                    'risk': 'Posible sobre-asignación de permisos'
                }
            )

    async def _collect_custom_roles(self) -> List[Dict]:
        """Recolectar roles personalizados - Simplificado para Huawei Cloud"""
        self.logger.info(
            "Saltando recolección de roles personalizados en Huawei Cloud...")
        return []

    async def _collect_policies(self) -> List[Dict]:
        """Recolectar políticas IAM custom"""
        policies = []

        try:
            from huaweicloudsdkiam.v3.model import ListCustomPoliciesRequest

            self.logger.info("Recolectando políticas custom...")
            custom_request = ListCustomPoliciesRequest()
            custom_response = self.client.list_custom_policies(custom_request)

            if custom_response and hasattr(custom_response, 'roles'):
                self.logger.info(
                    f"Encontradas {len(custom_response.roles)} políticas custom")

                for role in custom_response.roles:
                    policy_info = {
                        'id': role.id,
                        'name': role.display_name,
                        'type': 'custom',
                        'description': getattr(role, 'description', ''),
                        'created_at': getattr(role, 'created_time', None),
                        'updated_at': getattr(role, 'updated_time', None),
                        'domain_id': role.domain_id,
                        'policy_document': {}
                    }

                    # Analizar el documento de política
                    if hasattr(role, 'policy'):
                        policy_doc = role.policy
                        policy_info['policy_document'] = {
                            'version': getattr(policy_doc, 'Version', '1.1'),
                            'statements': []
                        }

                        # Procesar statements
                        for stmt in getattr(policy_doc, 'Statement', []):
                            statement_info = {
                                'effect': getattr(stmt, 'Effect', ''),
                                'actions': getattr(stmt, 'Action', [])
                            }
                            policy_info['policy_document']['statements'].append(
                                statement_info)

                            # Verificar permisos peligrosos
                            if statement_info['effect'] == 'Allow':
                                dangerous_patterns = ['*:*', '*:*:*', 'iam:*']
                                dangerous_actions = [
                                    action for action in statement_info['actions']
                                    if any(pattern in action for pattern in dangerous_patterns)
                                ]

                                if dangerous_actions:
                                    self._add_finding(
                                        'IAM-006',
                                        'HIGH',
                                        f'Política custom con permisos excesivos: {policy_info["name"]}',
                                        {
                                            'policy_id': policy_info['id'],
                                            'policy_name': policy_info['name'],
                                            'dangerous_actions': dangerous_actions
                                        }
                                    )

                    policies.append(policy_info)
                    self.logger.debug(
                        f"Procesada política custom: {policy_info['name']}")

            else:
                self.logger.info("No se encontraron políticas custom")

        except Exception as e:
            self.logger.error(f"Error recolectando políticas: {str(e)}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")

        self.logger.info(f"Total de políticas recolectadas: {len(policies)}")
        return policies

    def _check_dangerous_permissions(self, statement: Dict) -> bool:
        """Verificar si un statement tiene permisos peligrosos"""
        if statement.get('effect') != 'Allow':
            return False

        dangerous_patterns = ['*', 'iam:*', 'ecs:*', 'obs:*']
        actions = statement.get('actions', [])

        return any(pattern in action for pattern in dangerous_patterns for action in actions)

    async def _collect_access_keys(self, users: List[Dict]) -> List[Dict]:
        """Recolectar información de access keys de los usuarios"""
        access_keys = []

        self.logger.info(
            f"Iniciando recolección de access keys para {len(users)} usuarios")

        for user in users:
            try:
                self.logger.info(
                    f"Verificando access keys para usuario: {user['name']} ({user['id']})")

                # Método 1: Usar ListPermanentAccessKeysRequest (método estándar)
                try:
                    from huaweicloudsdkiam.v3.model import ListPermanentAccessKeysRequest
                    request = ListPermanentAccessKeysRequest()
                    request.user_id = user['id']
                    response = self.client.list_permanent_access_keys(request)

                    if hasattr(response, 'credentials') and response.credentials:
                        self.logger.info(
                            f"✅ Encontradas {len(response.credentials)} access keys permanentes para {user['name']}")

                        for key in response.credentials:
                            key_info = await self._process_access_key(key, user)
                            if key_info:
                                access_keys.append(key_info)
                                self.logger.info(
                                    f"✅ Access key procesada: {key_info['access_key_id'][:10]}**** para {user['name']}")
                    else:
                        self.logger.info(
                            f"❌ No se encontraron access keys permanentes para {user['name']}")

                except Exception as e:
                    self.logger.warning(
                        f"⚠️ Error con ListPermanentAccessKeysRequest para {user['name']}: {str(e)}")

                # Método 2: Usar ShowUserRequest para obtener información detallada del usuario
                try:
                    from huaweicloudsdkiam.v3.model import KeystoneShowUserRequest
                    request = KeystoneShowUserRequest()
                    request.user_id = user['id']
                    response = self.client.keystone_show_user(request)

                    user_obj = response.user
                    self.logger.info(
                        f" Información detallada obtenida para {user['name']}")

                    # Listar todos los atributos del usuario para debug
                    user_attributes = [attr for attr in dir(
                        user_obj) if not attr.startswith('_')]
                    self.logger.debug(
                        f"Atributos del usuario {user['name']}: {user_attributes}")

                    # Buscar campos específicos de access keys
                    access_key_fields = []
                    for attr in user_attributes:
                        if 'access' in attr.lower() and 'key' in attr.lower():
                            access_key_fields.append(attr)

                    if access_key_fields:
                        self.logger.info(
                            f"🔍 Campos de access key encontrados para {user['name']}: {access_key_fields}")

                        for field in access_key_fields:
                            field_value = getattr(user_obj, field, None)
                            if field_value and field_value != 'inactive' and field_value != 'None' and field_value != '':
                                self.logger.info(
                                    f"✅ Campo {field} para {user['name']}: {field_value}")

                                # Crear access key basada en el campo encontrado
                                key_info = {
                                    'access_key_id': f"{field}_{user['id']}",
                                    'user_id': user['id'],
                                    'user_name': user['name'],
                                    'status': field_value,
                                    'created_at': None,
                                    'age_days': 0,
                                    'description': f'Access Key from {field}',
                                    'source': 'user_attributes'
                                }

                                access_keys.append(key_info)
                                self.logger.info(
                                    f"✅ Access key agregada desde campo {field} para {user['name']}")

                    # Verificar campos específicos mencionados
                    access_key_1_status = getattr(
                        user_obj, 'access_key_1_status', None)
                    access_key_1_creation_time = getattr(
                        user_obj, 'access_key_1_creation_time', None)

                    if access_key_1_status and access_key_1_status != 'inactive':
                        self.logger.info(
                            f"✅ Access Key 1 encontrada para {user['name']}: {access_key_1_status}")

                        key_info = {
                            'access_key_id': f"AK1_{user['id']}",
                            'user_id': user['id'],
                            'user_name': user['name'],
                            'status': access_key_1_status,
                            'created_at': access_key_1_creation_time,
                            'age_days': 0,
                            'description': 'Access Key 1',
                            'source': 'access_key_1_fields'
                        }

                        if access_key_1_creation_time:
                            try:
                                if isinstance(access_key_1_creation_time, str):
                                    create_date = datetime.fromisoformat(
                                        access_key_1_creation_time.replace('Z', '+00:00'))
                                else:
                                    create_date = access_key_1_creation_time
                                key_info['age_days'] = (
                                    datetime.now() - create_date).days
                            except Exception as e:
                                self.logger.debug(
                                    f"Error calculando edad de Access Key 1 para {user['name']}: {str(e)}")

                        access_keys.append(key_info)
                        self.logger.info(
                            f"✅ Access Key 1 agregada para {user['name']}")

                    # Verificar Access Key 2
                    access_key_2_status = getattr(
                        user_obj, 'access_key_2_status', None)
                    access_key_2_creation_time = getattr(
                        user_obj, 'access_key_2_creation_time', None)

                    if access_key_2_status and access_key_2_status != 'inactive':
                        self.logger.info(
                            f"✅ Access Key 2 encontrada para {user['name']}: {access_key_2_status}")

                        key_info = {
                            'access_key_id': f"AK2_{user['id']}",
                            'user_id': user['id'],
                            'user_name': user['name'],
                            'status': access_key_2_status,
                            'created_at': access_key_2_creation_time,
                            'age_days': 0,
                            'description': 'Access Key 2',
                            'source': 'access_key_2_fields'
                        }

                        if access_key_2_creation_time:
                            try:
                                if isinstance(access_key_2_creation_time, str):
                                    create_date = datetime.fromisoformat(
                                        access_key_2_creation_time.replace('Z', '+00:00'))
                                else:
                                    create_date = access_key_2_creation_time
                                key_info['age_days'] = (
                                    datetime.now() - create_date).days
                            except Exception as e:
                                self.logger.debug(
                                    f"Error calculando edad de Access Key 2 para {user['name']}: {str(e)}")

                        access_keys.append(key_info)
                        self.logger.info(
                            f"✅ Access Key 2 agregada para {user['name']}")

                except Exception as e:
                    self.logger.warning(
                        f"⚠️ Error obteniendo información detallada para {user['name']}: {str(e)}")

                # Método 3: Verificar si el usuario tiene access_mode programático (indica que puede tener access keys)
                access_mode = user.get('access_mode', '')
                if access_mode and ('programmatic' in access_mode.lower()):
                    self.logger.info(
                        f"🔍 Usuario {user['name']} tiene access_mode programático: {access_mode}")

                    # Buscar access keys específicas para usuarios programáticos
                    try:
                        # Intentar obtener access keys usando el endpoint específico para usuarios programáticos
                        from huaweicloudsdkiam.v3.model import ListAccessKeysRequest
                        request = ListAccessKeysRequest()
                        request.user_id = user['id']
                        response = self.client.list_access_keys(request)

                        if hasattr(response, 'access_keys') and response.access_keys:
                            self.logger.info(
                                f"✅ Encontradas {len(response.access_keys)} access keys para usuario programático {user['name']}")

                            for key in response.access_keys:
                                key_info = {
                                    'access_key_id': getattr(key, 'access_key_id', f"PROG_{user['id']}"),
                                    'user_id': user['id'],
                                    'user_name': user['name'],
                                    'status': getattr(key, 'status', 'active'),
                                    'created_at': getattr(key, 'create_time', None),
                                    'age_days': 0,
                                    'description': 'Programmatic Access Key',
                                    'source': 'programmatic_user'
                                }

                                # Calcular edad
                                created_at = key_info['created_at']
                                if created_at:
                                    try:
                                        if isinstance(created_at, str):
                                            create_date = datetime.fromisoformat(
                                                created_at.replace('Z', '+00:00'))
                                        else:
                                            create_date = created_at
                                        key_info['age_days'] = (
                                            datetime.now() - create_date).days
                                    except:
                                        pass

                                access_keys.append(key_info)
                                self.logger.info(
                                    f"✅ Access key programática agregada para {user['name']}")

                    except Exception as e:
                        self.logger.debug(
                            f"Error obteniendo access keys programáticas para {user['name']}: {str(e)}")

            except Exception as e:
                self.logger.error(
                    f"❌ Error general recolectando access keys para usuario {user['name']}: {str(e)}")

        self.logger.info(
            f"🎯 Recolección de access keys completada. Total encontradas: {len(access_keys)}")

        # Log detallado de las access keys encontradas
        if access_keys:
            self.logger.info("🔑 Access Keys encontradas:")

            # Agrupar por usuario para mostrar múltiples keys por usuario
            users_with_keys = {}
            for key in access_keys:
                user_name = key['user_name']
                if user_name not in users_with_keys:
                    users_with_keys[user_name] = []
                users_with_keys[user_name].append(key)

            # Mostrar agrupado por usuario
            for user_name, user_keys in users_with_keys.items():
                if len(user_keys) == 1:
                    key = user_keys[0]
                    self.logger.info(
                        f"   👤 {user_name}: {key['access_key_id']} ({key['status']}) - Fuente: {key['source']}")
                else:
                    self.logger.info(
                        f"   👤 {user_name}: {len(user_keys)} access keys encontradas")
                    for i, key in enumerate(user_keys, 1):
                        self.logger.info(
                            f"      🔑 Key #{i}: {key['access_key_id']} ({key['status']}) - Fuente: {key['source']}")
        else:
            self.logger.warning(
                "⚠️ No se encontraron access keys para ningún usuario")

        return access_keys

    async def _process_access_key(self, key, user: Dict) -> Optional[Dict]:
        """Procesar una access key individual"""
        try:
            self.logger.info(
                f"🔍 DEBUG: Iniciando procesamiento de access key para {user['name']}")

            created_at = getattr(key, 'create_time', None)
            key_age = 0

            if created_at:
                # Parsear fecha si es string
                if isinstance(created_at, str):
                    try:
                        create_date = datetime.fromisoformat(
                            created_at.replace('Z', '+00:00'))
                    except:
                        create_date = datetime.now(timezone.utc)
                else:
                    create_date = created_at

                # Asegurar que ambas fechas tengan el mismo timezone
                try:
                    if create_date.tzinfo is not None:
                        # create_date tiene timezone, usar datetime.now con timezone
                        now = datetime.now(timezone.utc)
                    else:
                        # create_date no tiene timezone, usar datetime.now sin timezone
                        now = datetime.now()

                    key_age = (now - create_date).days
                    self.logger.debug(
                        f"Edad calculada para access key: {key_age} días")
                except Exception as e:
                    self.logger.debug(
                        f"Error calculando edad, usando 0: {str(e)}")
                    key_age = 0

            # Obtener access_key_id correcto - probar diferentes atributos
            access_key_id = None
            for attr in ['access_key_id', 'access', 'id', 'access_key']:
                if hasattr(key, attr):
                    access_key_id = getattr(key, attr)
                    self.logger.info(
                        f"🔍 DEBUG: Encontrado access_key_id en atributo '{attr}': {access_key_id}")
                    break

            if not access_key_id:
                access_key_id = f"UNKNOWN_{user['id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                self.logger.warning(
                    f"⚠️ No se pudo obtener access_key_id, usando fallback: {access_key_id}")

            # Obtener último uso (manejar errores silenciosamente)
            last_used = None
            try:
                last_used = await self._get_access_key_last_used(access_key_id)
                self.logger.debug(f"Último uso obtenido exitosamente")
            except Exception as e:
                self.logger.debug(
                    f"Error obteniendo último uso de access key {access_key_id}: {str(e)}")

            # Obtener status - probar diferentes atributos
            status = 'active'  # valor por defecto
            for attr in ['status', 'state']:
                if hasattr(key, attr):
                    status = getattr(key, attr)
                    break

            key_info = {
                'access_key_id': access_key_id,
                'user_id': user['id'],
                'user_name': user['name'],
                'status': status,
                'created_at': created_at,
                'age_days': key_age,
                'description': getattr(key, 'description', ''),
                'last_used': last_used,
                'last_used_service': last_used.get('service') if last_used else None,
                'last_used_region': last_used.get('region') if last_used else None,
                'source': 'permanent_access_keys'
            }

            self.logger.info(
                f"✅ DEBUG: key_info creado exitosamente para {user['name']}: {access_key_id}")

            # Verificaciones de seguridad (manejar errores silenciosamente)
            try:
                await self._check_access_key_security(key_info, user)
            except Exception as e:
                self.logger.debug(
                    f"Error en verificación de seguridad de access key: {str(e)}")

            self.logger.info(
                f"✅ DEBUG: Retornando key_info para {user['name']}")
            return key_info

        except Exception as e:
            self.logger.error(
                f"❌ ERROR procesando access key para {user['name']}: {str(e)}")
            import traceback
            self.logger.error(
                f"❌ Traceback completo: {traceback.format_exc()}")

            # En lugar de retornar None, crear un key_info básico
            try:
                fallback_key_info = {
                    'access_key_id': f"ERROR_{user['id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    'user_id': user['id'],
                    'user_name': user['name'],
                    'status': 'unknown',
                    'created_at': None,
                    'age_days': 0,
                    'description': 'Error procesando access key',
                    'last_used': None,
                    'last_used_service': None,
                    'last_used_region': None,
                    'source': 'permanent_access_keys_error'
                }
                self.logger.warning(
                    f"⚠️ Creando key_info básico debido a error para {user['name']}")
                return fallback_key_info
            except:
                return None

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
                'IAM-003',
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
                'IAM-003',
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
                    'IAM-014',
                    'LOW',
                    f'Usuario con múltiples access keys activas',
                    {
                        'user_name': user['name'],
                        'active_keys': active_keys_count + 1
                    }
                )

    async def _collect_password_policy(self) -> Dict[str, Any]:
        """Recolectar política de contraseñas"""
        policy = {}
        try:
            request = ShowDomainPasswordPolicyRequest()
            request.domain_id = HUAWEI_DOMAIN_ID
            response = self.client.show_domain_password_policy(request)

            # Extraer todos los campos de la política
            policy = {
                'minimum_password_length': response.password_policy.minimum_password_length,
                'maximum_password_length': response.password_policy.maximum_password_length,
                'password_requirements': response.password_policy.password_requirements,
                'password_char_combination': response.password_policy.password_char_combination,
                'minimum_password_age': response.password_policy.minimum_password_age,
                'password_validity_period': response.password_policy.password_validity_period,
                'number_of_recent_passwords_disallowed': response.password_policy.number_of_recent_passwords_disallowed,
                'maximum_consecutive_identical_chars': response.password_policy.maximum_consecutive_identical_chars,
                'password_not_username_or_invert': response.password_policy.password_not_username_or_invert
            }

            # Verificar seguridad de la política
            await self._check_password_policy_security(policy)

        except Exception as e:
            self.logger.error(
                f"Error recolectando política de contraseñas: {str(e)}")

        return policy

    def _analyze_password_policy(self, policy: Dict):
        """Analizar política de contraseñas y generar hallazgos"""
        issues = []

        # Verificar longitud mínima
        min_length = policy.get('minimum_length', 0)
        if min_length < PASSWORD_POLICY['min_length']:
            issues.append(
                f"Longitud mínima insuficiente: {min_length} caracteres (requerido: {PASSWORD_POLICY['min_length']})")

        # Verificar combinación de caracteres
        char_combination = policy.get('password_char_combination', 0)
        if char_combination < 3:
            issues.append(
                f"Requisitos de complejidad débiles: solo {char_combination} tipos de caracteres requeridos")

        # Verificar período de validez
        validity_period = policy.get('password_validity_period', 0)
        if validity_period == 0:
            issues.append("Sin expiración de contraseñas configurada")
        elif validity_period > PASSWORD_POLICY['max_age_days']:
            issues.append(
                f"Período de validez muy largo: {validity_period} días (máximo recomendado: {PASSWORD_POLICY['max_age_days']})")

        # Verificar historial de contraseñas
        password_history = policy.get(
            'number_of_recent_passwords_disallowed', 0)
        if password_history < PASSWORD_POLICY['history_count']:
            issues.append(
                f"Historial de contraseñas insuficiente: {password_history} (requerido: {PASSWORD_POLICY['history_count']})")

        # Verificar edad mínima
        min_age = policy.get('minimum_password_age', 0)
        if min_age == 0:
            issues.append("Sin edad mínima de contraseña configurada")

        # Generar hallazgo si hay problemas
        if issues:
            severity = 'HIGH' if len(issues) > 3 else 'MEDIUM'
            self._add_finding(
                'IAM-004',
                severity,
                'Política de contraseñas no cumple con las mejores prácticas',
                {
                    'issues': issues,
                    'current_policy': policy,
                    'password_requirements': policy.get('password_requirements', 'No especificado')
                }
            )

    async def _check_password_policy_security(self, policy: Dict):
        """Verificar seguridad de la política de contraseñas"""
        issues = []

        # Longitud mínima
        min_length = policy.get('minimum_password_length', 0)
        if min_length < PASSWORD_POLICY['min_length']:
            issues.append(
                f"Longitud mínima insuficiente ({min_length} < {PASSWORD_POLICY['min_length']})")
            self._add_finding(
                'IAM-004',
                'MEDIUM',
                f'Política de contraseñas débil: longitud mínima {min_length}',
                {
                    'current_length': min_length,
                    'required_length': PASSWORD_POLICY['min_length']
                }
            )

        # Complejidad - Analizar password_char_combination y password_requirements
        char_combination = policy.get('password_char_combination', 0)
        password_requirements = policy.get('password_requirements', '')

        if char_combination < 3:
            self._add_finding(
                'IAM-004',
                'MEDIUM',
                f'Política de contraseñas requiere solo {char_combination} tipos de caracteres',
                {
                    'current_requirement': char_combination,
                    'recommended_requirement': 3,
                    'description': password_requirements
                }
            )

        # Analizar requisitos específicos desde el texto
        req_lower = password_requirements.lower()
        complexity_missing = []

        if 'uppercase' not in req_lower:
            complexity_missing.append('mayúsculas')
        if 'lowercase' not in req_lower:
            complexity_missing.append('minúsculas')
        if 'digit' not in req_lower and 'number' not in req_lower:
            complexity_missing.append('números')
        if 'special' not in req_lower:
            complexity_missing.append('caracteres especiales')

        if complexity_missing:
            self._add_finding(
                'IAM-004',
                'LOW',
                'Política de contraseñas puede no requerir todos los tipos de caracteres',
                {
                    'potentially_missing': complexity_missing,
                    'current_requirements': password_requirements
                }
            )

        # Período de validez
        validity_period = policy.get('password_validity_period', 0)
        if validity_period == 0:
            self._add_finding(
                'IAM-004',
                'HIGH',
                'Contraseñas sin expiración configurada',
                {'current_setting': 'Las contraseñas nunca expiran'}
            )
        elif validity_period > PASSWORD_POLICY['max_age_days']:
            self._add_finding(
                'IAM-004',
                'MEDIUM',
                f'Período de validez de contraseñas muy largo: {validity_period} días',
                {
                    'current_days': validity_period,
                    'recommended_days': PASSWORD_POLICY['max_age_days']
                }
            )

        # Historial de contraseñas
        password_history = policy.get(
            'number_of_recent_passwords_disallowed', 0)
        if password_history < PASSWORD_POLICY['history_count']:
            self._add_finding(
                'IAM-004',
                'LOW',
                f'Historial de contraseñas insuficiente: {password_history}',
                {
                    'current_history': password_history,
                    'recommended_history': PASSWORD_POLICY['history_count']
                }
            )

        # Edad mínima de contraseña
        min_age = policy.get('minimum_password_age', 0)
        if min_age == 0:
            self._add_finding(
                'IAM-004',
                'LOW',
                'Sin edad mínima de contraseña configurada',
                {
                    'current_setting': 0,
                    'recommended_setting': PASSWORD_POLICY.get('min_age_days', 1),
                    'impact': 'Permite cambios de contraseña inmediatos repetidos'
                }
            )

        # Caracteres consecutivos idénticos
        max_consecutive = policy.get('maximum_consecutive_identical_chars', 0)
        if max_consecutive == 0 or max_consecutive > 3:
            self._add_finding(
                'IAM-004',
                'LOW',
                f'Permite muchos caracteres idénticos consecutivos: {max_consecutive}',
                {
                    'current_setting': max_consecutive,
                    'recommended_setting': 3,
                    'risk': 'Facilita contraseñas débiles como "aaaaaa"'
                }
            )

        # Verificar si contraseña puede ser igual al username
        if not policy.get('password_not_username_or_invert', True):
            self._add_finding(
                'IAM-004',
                'MEDIUM',
                'Permite que la contraseña sea igual al nombre de usuario',
                {
                    'current_setting': False,
                    'risk': 'Contraseñas predecibles basadas en username'
                }
            )

    def _check_password_policy_issues(self, policy: Dict) -> List[str]:
        """Verificar problemas en política de contraseñas"""
        issues = []

        # Longitud mínima
        min_length = policy.get('minimum_length', 0) or policy.get(
            'minimum_password_length', 0)
        if min_length < PASSWORD_POLICY['min_length']:
            issues.append(
                f"Longitud mínima insuficiente ({min_length} < {PASSWORD_POLICY['min_length']})")

        # Requisitos de complejidad
        char_combination = policy.get('password_char_combination', 0)
        password_requirements = policy.get('password_requirements', '')

        if char_combination < 3:
            issues.append(
                f"Complejidad insuficiente: solo {char_combination} tipos de caracteres requeridos")

        # Verificar descripción de requisitos
        if password_requirements:
            req_lower = password_requirements.lower()
            if 'uppercase' not in req_lower:
                issues.append("No requiere mayúsculas")
            if 'lowercase' not in req_lower:
                issues.append("No requiere minúsculas")
            if 'digit' not in req_lower:
                issues.append("No requiere números")
            if 'special' not in req_lower:
                issues.append("No requiere caracteres especiales")

        # Período de validez
        validity = policy.get('password_validity_period', 0)
        if validity == 0:
            issues.append("Sin expiración de contraseñas")
        elif validity > PASSWORD_POLICY['max_age_days']:
            issues.append(f"Período de validez muy largo ({validity} días)")

        # Historial
        history = policy.get('number_of_recent_passwords_disallowed', 0)
        if history < PASSWORD_POLICY.get('history_count', 5):
            issues.append(f"Historial insuficiente ({history} contraseñas)")

        return issues

    async def _check_user_security_issues(self, user_info: Dict):
        """Verificar problemas de seguridad específicos del usuario"""
        try:
            # Cuenta sin uso reciente
            last_login = user_info.get('last_login')
            if last_login:
                try:
                    last_login_date = datetime.fromisoformat(
                        last_login.replace('Z', '+00:00'))
                    days_inactive = (datetime.now(
                        timezone.utc) - last_login_date).days

                    if days_inactive > 90:
                        self._add_finding(
                            'IAM-005',
                            'MEDIUM',
                            f'Usuario inactivo por {days_inactive} días: {user_info["name"]}',
                            {
                                'user_id': user_info['id'],
                                'user_name': user_info['name'],
                                'last_login': last_login,
                                'days_inactive': days_inactive
                            }
                        )
                except Exception as e:
                    self.logger.debug(
                        f"Error procesando fecha de último login: {e}")

            # Verificar si es cuenta de servicio sin rotación
            if self._is_service_account(user_info):
                # Las cuentas de servicio deben tener políticas especiales
                self._add_finding(
                    'IAM-010',
                    'LOW',
                    f'Cuenta de servicio identificada: {user_info["name"]}',
                    {
                        'user_id': user_info['id'],
                        'user_name': user_info['name'],
                        'recommendation': 'Considerar usar IAM Agency en lugar de usuario para servicios'
                    }
                )
        except Exception as e:
            self.logger.error(
                f"Error verificando problemas de seguridad para usuario {user_info.get('name', 'unknown')}: {e}")

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
                    'IAM-019',
                    'HIGH',
                    'Sin política de bloqueo por intentos fallidos',
                    {'current_setting': 'Intentos ilimitados permitidos'}
                )
            elif lp.login_failed_times > PASSWORD_POLICY['lockout_attempts']:
                self._add_finding(
                    'IAM-019',
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
                    'IAM-019',
                    'MEDIUM',
                    'Sin timeout de sesión configurado',
                    {'risk': 'Las sesiones permanecen activas indefinidamente'}
                )

        except Exception as e:
            self.logger.error(
                f"Error recolectando política de login: {str(e)}")

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
                    'IAM-002',
                    'LOW',
                    'Usuarios no pueden gestionar sus propios dispositivos MFA',
                    {'impact': 'Puede reducir la adopción de MFA'}
                )

        except Exception as e:
            self.logger.debug(
                f"Error recolectando política de protección: {str(e)}")

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
                        'IAM-008',
                        'LOW',
                        f'Usuario sin grupos asignados: {user["name"]}',
                        {'user_id': user['id'], 'user_name': user['name']}
                    )

            except Exception as e:
                self.logger.debug(
                    f"Error obteniendo grupos para usuario {user['id']}: {str(e)}")
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
        # En Huawei Cloud, los permisos vienen principalmente a través de grupos
        # No necesitamos consultar roles del sistema
        return []

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
                results.get('role_assignments', {}).get(
                    'user_roles', {}).get(user['id'], [])
            )

            # Verificar acceso administrador
            if self._has_admin_permissions(user_perms):
                analysis['users_with_admin_access'].append({
                    'user_id': user['id'],
                    'user_name': user['name'],
                    'source': user_perms.get('admin_source', 'unknown')
                })

                self._add_finding(
                    'IAM-001',
                    'CRITICAL',
                    f'Usuario con privilegios de administrador: {user["name"]}',
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
        """Verificar si los permisos incluyen acceso administrador"""
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
        """Determinar si es una cuenta de servicio basado en access_mode"""
        # En Huawei Cloud, el access_mode determina el tipo de cuenta:
        # - 'programmatic': Cuenta de servicio (solo acceso programático)
        # - 'console': Usuario consola web (solo acceso a consola)
        # - 'programmatic,console': Usuario con acceso programático (acceso programático y consola)

        access_mode = user.get('access_mode')
        if access_mode:
            access_mode = access_mode.lower()

        # Cuenta de servicio = SOLO acceso programático
        if access_mode == 'programmatic':
            return True

        # Usuario con acceso programático = NO es cuenta de servicio
        # if access_mode == 'programmatic,console':
        #     return True  # ❌ CAMBIO: Ya no se considera cuenta de servicio

        # Verificar indicadores adicionales en nombre y descripción
        description = user.get('description', '')
        name = user.get('name', '')

        # Convertir a lowercase de forma segura
        name_lower = name.lower() if name else ''
        description_lower = description.lower() if description else ''

        # Indicadores de cuenta de servicio
        service_indicators = [
            'service', 'api', 'system', 'app', 'application',
            'connector', 'integration', 'automation', 'bot'
        ]

        # Verificar en nombre
        if any(indicator in name_lower for indicator in service_indicators):
            return True

        # Verificar en descripción
        if any(indicator in description_lower for indicator in service_indicators):
            return True

        # Verificar patrones específicos
        if description_lower in ['service account', 'api user', 'system user']:
            return True

        return False

    def _get_user_access_type(self, user: Dict) -> str:
        """Determinar el tipo de acceso del usuario según las especificaciones"""
        access_mode = user.get('access_mode')
        if access_mode:
            access_mode = access_mode.lower()

        if access_mode == 'programmatic':
            return 'service_account'  # Cuenta de servicio
        elif access_mode == 'programmatic,console':
            return 'user_with_programmatic_access'  # Usuario con acceso programático
        elif access_mode == 'console':
            return 'console_user'  # Usuario consola web
        else:
            return 'unknown'  # Tipo desconocido

    def _get_service_account_indicators(self, user: Dict) -> List[str]:
        """Obtener indicadores de cuenta de servicio"""
        indicators = []

        # Verificar access_mode
        access_mode = user.get('access_mode', '')
        if access_mode == 'programmatic':
            indicators.append('Access mode: programmatic (cuenta de servicio)')
        elif access_mode == 'programmatic,console':
            indicators.append(
                'Access mode: programmatic,console (usuario con acceso programático)')
        elif access_mode == 'console':
            indicators.append('Access mode: console (usuario consola web)')

        # Verificar nombre
        name = user.get('name', '')
        name_lower = name.lower() if name else ''
        if any(indicator in name_lower for indicator in ['service', 'api', 'system', 'app']):
            indicators.append('Nombre contiene indicador de servicio')

        # Verificar email
        if not user.get('email'):
            indicators.append('Sin email asociado')

        # Verificar login interactivo
        if not user.get('last_login_time'):
            indicators.append('Sin login interactivo registrado')

        # Verificar descripción
        description = user.get('description', '')
        if description:
            description_lower = description.lower()
            if any(indicator in description_lower for indicator in ['service', 'api', 'programmatic']):
                indicators.append('Descripción indica cuenta de servicio')

        return indicators

    async def _identify_privileged_accounts(self, results: Dict) -> List[Dict]:
        """Identificar cuentas privilegiadas"""
        privileged = []

        # Basarse en el análisis de permisos efectivos
        admin_users = results.get('permissions_analysis', {}).get(
            'users_with_admin_access', [])

        for admin in admin_users:
            # Buscar información adicional del usuario
            user_info = next(
                (u for u in results['users'] if u['id'] == admin['user_id']), {})

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
                    last_login = datetime.fromisoformat(
                        user['last_login_time'].replace('Z', '+00:00'))
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
                        created = datetime.fromisoformat(
                            user['create_time'].replace('Z', '+00:00'))
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
                    expires = datetime.fromisoformat(
                        user['password_expires_at'].replace('Z', '+00:00'))

                    if expires < datetime.now():
                        self._add_finding(
                            'IAM-004',
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
                'IAM-020',
                'MEDIUM',
                f'{len(users_without_boundaries)} usuarios administradores sin límites de permisos',
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
                        'IAM-016',
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
                        'IAM-017',
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
                        'IAM-006',
                        'HIGH' if risk_type == 'full_admin' else 'MEDIUM',
                        f'Rol con permisos de riesgo ({risk_type}): {role["name"]}',
                        {
                            'role_id': role['id'],
                            'role_name': role['name'],
                            'risk_type': risk_type
                        }
                    )

    async def _check_admin_privileges(self, user_id: str) -> bool:
        """Verificar si un usuario tiene privilegios de administrador"""
        try:
            # Verificar grupos administradores
            request = KeystoneListGroupsForUserRequest()
            request.user_id = user_id
            response = self.client.keystone_list_groups_for_user(request)

            admin_groups = ['admin', 'administrator',
                            'power_user', 'be61248cddbf441e9446e8bc5a2bf26f']
            for group in response.groups:
                # Verificar que el grupo tenga nombre válido
                if group.name:
                    group_name_lower = group.name.lower()
                    if any(admin in group_name_lower for admin in admin_groups[:3]) or group.id in admin_groups:
                        return True

            # También verificar roles directos
            # Esto requeriría verificación adicional de roles asignados

        except Exception as e:
            self.logger.debug(
                f"Error verificando privilegios para usuario {user_id}: {str(e)}")

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
            # Solo usuarios regulares
            'users_without_mfa': len(results['mfa_status']['regular_users_without_mfa']),
            'service_accounts_without_mfa': len(results['mfa_status']['service_accounts_without_mfa']),
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

        # Calcular tasa de cumplimiento MFA solo para usuarios regulares
        total_regular_users = stats['total_users'] - \
            stats['service_accounts_without_mfa']
        if total_regular_users > 0:
            stats['mfa_compliance_rate'] = round(
                ((total_regular_users -
                 stats['users_without_mfa']) / total_regular_users) * 100, 2
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
        critical_findings = [
            f for f in self.findings if f['severity'] == 'CRITICAL']
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
            results['password_policy'].get(
                'minimum_length', 0) >= PASSWORD_POLICY['min_length'],
            results['password_policy'].get('require_uppercase', False),
            results['password_policy'].get('require_lowercase', False),
            results['password_policy'].get('require_numbers', False),
            results['password_policy'].get('require_special', False)
        ])

        return stats

    async def _analyze_programmatic_access(self, users: List[Dict]):
        """Analizar acceso programático y generar hallazgos de seguridad"""
        programmatic_users = []
        service_accounts = []

        for user in users:
            access_type = self._get_user_access_type(user)

            if access_type == 'user_with_programmatic_access':
                programmatic_users.append(user)

                # Hallazgo: Usuario con acceso programático
        # self._add_finding(
        # 'IAM-031',
        # 'MEDIUM',
        # f'Usuario con acceso programático: {user["name"]}',
        # {
        # 'user_id': user['id'],
         #                'user_name': user['name'],
         #               'access_type': 'programmatic,console',
         #               'risk': 'Usuario puede generar access keys y usar APIs',
          #               'recommendation': 'Revisar si el acceso programático es necesario'
          #           }
          #       )

            elif access_type == 'service_account':
                service_accounts.append(user)

                # Hallazgo: Cuenta de servicio
                self._add_finding(
                    'IAM-010',
                    'LOW',
                    f'Cuenta de servicio identificada: {user["name"]}',
                    {
                        'user_id': user['id'],
                        'user_name': user['name'],
                        'access_type': 'programmatic',
                        'recommendation': 'Considerar usar IAM Agency en lugar de usuario para servicios'
                    }
                )

        # Estadísticas de acceso programático
        self.logger.info(
            f"Usuarios con acceso programático: {len(programmatic_users)}")
        self.logger.info(f"Cuentas de servicio: {len(service_accounts)}")

    async def _get_user_login_verification_method(self, user_id: str) -> str:
        """Devuelve sms | email | vmfa | disabled"""
        try:
            from huaweicloudsdkiam.v3.model import ListUserLoginProtectsRequest
            req = ListUserLoginProtectsRequest()
            req.user_id = user_id
            resp = self.client.list_user_login_protects(req)

            if getattr(resp, 'login_protects', None):
                for protect in resp.login_protects:
                    if protect.enabled:
                        # el SDK expone verification_method
                        method = getattr(
                            protect, 'verification_method', 'unknown')
                        return method.lower()  # sms | email | vmfa

            # si no hay login-protect habilitado, validar VMFA
            mfa = await self._check_user_mfa_detailed(user_id)
            if mfa['has_mfa'] and 'virtual' in mfa['types']:
                return 'vmfa'
            return 'disabled'
        except Exception as e:
            self.logger.debug(f'LoginProtect error {user_id}: {e}')
            return 'disabled'

    async def _check_onboarding_offboarding_process(self, results: Dict):
        """IAM-009: Verificar proceso de onboarding/offboarding"""
        # Buscar usuarios creados recientemente sin configuración completa
        recent_users = []
        incomplete_users = []

        for user in results.get('users', []):
            if 'create_time' in user:
                try:
                    create_date = datetime.fromisoformat(
                        user['create_time'].replace('Z', '+00:00'))
                    days_since_created = (datetime.now(
                        timezone.utc) - create_date).days

                    if days_since_created <= 30:  # Usuarios de los últimos 30 días
                        recent_users.append(user)

                        # Verificar configuración incompleta
                        if not user.get('groups') or not user.get('mfa_enabled'):
                            incomplete_users.append(user)
                except:
                    pass

        if incomplete_users:
            self._add_finding(
                'IAM-009',
                'HIGH',
                f'{len(incomplete_users)} usuarios nuevos sin configuración completa (sin grupos o MFA)',
                {
                    'users': [u['name'] for u in incomplete_users],
                    'total_recent': len(recent_users),
                    'recommendation': 'Implementar proceso formal de onboarding/offboarding'
                }
            )

    async def _check_privileged_access_logging(self, results: Dict):
        """IAM-011: Verificar logging de accesos privilegiados"""
        # En Huawei Cloud, esto requeriría verificar CTS (Cloud Trace Service)
        admin_users = []

        for user in results.get('privileged_accounts', []):
            # Usar user_name en lugar de name
            admin_users.append(
                user.get('user_name', user.get('name', 'unknown')))

        if admin_users:
            self._add_finding(
                'IAM-011',
                'HIGH',
                f'{len(admin_users)} cuentas privilegiadas requieren verificación de logging detallado',
                {
                    'admin_users': admin_users,
                    'recommendation': 'Configurar CTS con retención extendida para accesos administrativos'
                }
            )

    async def _check_inline_policies(self, results: Dict):
        """IAM-012: Verificar uso excesivo de políticas inline"""
        inline_count = 0
        users_with_inline = []

        # Verificar políticas inline en usuarios
        for user in results.get('users', []):
            if user.get('attached_policies'):
                for policy in user['attached_policies']:
                    if policy.get('type') == 'inline':
                        inline_count += 1
                        if user['name'] not in users_with_inline:
                            users_with_inline.append(user['name'])

        if inline_count > 5:  # Umbral de políticas inline
            self._add_finding(
                'IAM-012',
                'MEDIUM',
                f'{inline_count} políticas inline detectadas en {len(users_with_inline)} usuarios',
                {
                    'inline_policies': inline_count,
                    'affected_users': users_with_inline[:10],  # Top 10
                    'recommendation': 'Migrar a políticas gestionadas reutilizables'
                }
            )

    async def _check_permission_review_process(self, results: Dict):
        """IAM-013: Verificar revisión periódica de permisos"""
        # Verificar usuarios/roles sin cambios recientes (indica falta de revisión)
        stale_permissions = []

        for user in results.get('users', []):
            if 'last_permission_update' in user:
                try:
                    last_update = datetime.fromisoformat(
                        user['last_permission_update'].replace('Z', '+00:00'))
                    days_since_update = (datetime.now(
                        timezone.utc) - last_update).days

                    if days_since_update > 90:  # Sin cambios en 90 días
                        stale_permissions.append({
                            'user': user['name'],
                            'days': days_since_update
                        })
                except:
                    pass

        if len(stale_permissions) > 5:
            self._add_finding(
                'IAM-013',
                'MEDIUM',
                f'{len(stale_permissions)} usuarios con permisos sin revisar por más de 90 días',
                {
                    'sample_users': stale_permissions[:5],
                    'total': len(stale_permissions),
                    'recommendation': 'Implementar revisión trimestral de permisos (access review)'
                }
            )

    async def _check_naming_convention(self, results: Dict):
        """IAM-015: Verificar política de naming convention"""
        non_compliant = {
            'users': [],
            'groups': [],
            'roles': [],
            'policies': []
        }

        # Patrones de naming esperados
        patterns = {
            'users': r'^(usr_|user_|[a-z]+\.[a-z]+)',
            'groups': r'^(grp_|group_|[a-z]+_team)',
            'roles': r'^(role_|rol_|[a-z]+_role)',
            'policies': r'^(pol_|policy_|[a-z]+_policy)'
        }

        # Verificar usuarios
        for user in results.get('users', []):
            username = user.get('name', '')
            if username and not re.match(patterns['users'], username.lower()):
                non_compliant['users'].append(username)

        # Verificar grupos
        for group in results.get('groups', []):
            groupname = group.get('name', '')
            if groupname and not re.match(patterns['groups'], groupname.lower()):
                non_compliant['groups'].append(groupname)

        total_non_compliant = sum(len(v) for v in non_compliant.values())

        if total_non_compliant > 0:
            self._add_finding(
                'IAM-015',
                'LOW',
                f'{total_non_compliant} recursos IAM sin seguir convención de nombres',
                {
                    'users_non_compliant': len(non_compliant['users']),
                    'groups_non_compliant': len(non_compliant['groups']),
                    'sample_users': non_compliant['users'][:5],
                    'recommendation': 'Establecer y documentar convención de nombres estándar'
                }
            )

    async def _check_policy_versions(self, results: Dict):
        """IAM-018: Verificar versiones de políticas"""
        old_version_policies = []

        for policy in results.get('policies', []):
            if policy.get('version'):
                # En Huawei Cloud, las políticas pueden tener versiones
                if policy['version'] < '2.0':  # Versión antigua
                    old_version_policies.append({
                        'name': policy.get('name', 'unknown'),
                        'version': policy['version']
                    })

        if old_version_policies:
            self._add_finding(
                'IAM-018',
                'LOW',
                f'{len(old_version_policies)} políticas usando versiones deprecadas del lenguaje',
                {
                    'policies': old_version_policies[:10],
                    'total': len(old_version_policies),
                    'recommendation': 'Actualizar todas las políticas a la última versión del lenguaje'
                }
            )

    async def _check_api_token_expiration(self, results: Dict):
        """IAM-021: Verificar expiración de tokens API"""
        # En Huawei Cloud, los tokens temporales tienen tiempo de vida configurado
        tokens_without_expiration = []
        long_lived_tokens = []

        # Verificar configuración de tokens temporales
        for user in results.get('users', []):
            if user.get('access_keys'):
                for key in user['access_keys']:
                    # Access keys permanentes (sin expiración)
                    tokens_without_expiration.append({
                        'user': user['name'],
                        'key_id': key.get('access_key_id', 'unknown')
                    })

        if tokens_without_expiration:
            self._add_finding(
                'IAM-021',
                'HIGH',
                f'{len(tokens_without_expiration)} access keys permanentes sin expiración automática',
                {
                    'sample_keys': tokens_without_expiration[:5],
                    'total': len(tokens_without_expiration),
                    'recommendation': 'Implementar tokens temporales con expiración máxima de 12 horas'
                }
            )

    async def _check_environment_segregation(self, results: Dict):
        """IAM-022: Verificar segregación por ambiente"""
        # Buscar usuarios/roles que tienen acceso a múltiples ambientes
        multi_env_access = []

        for user in results.get('users', []):
            environments = set()

            # Analizar nombres de recursos/políticas para detectar ambientes
            for group in user.get('groups', []):
                if 'prod' in group.lower():
                    environments.add('production')
                if 'dev' in group.lower():
                    environments.add('development')
                if 'test' in group.lower() or 'qa' in group.lower():
                    environments.add('test')

            if len(environments) > 1:
                multi_env_access.append({
                    'user': user['name'],
                    'environments': list(environments)
                })

        if multi_env_access:
            self._add_finding(
                'IAM-022',
                'HIGH',
                f'{len(multi_env_access)} usuarios con acceso a múltiples ambientes',
                {
                    'users': multi_env_access[:10],
                    'total': len(multi_env_access),
                    'recommendation': 'Segregar accesos por ambiente (Dev/Test/Prod)'
                }
            )

    async def _check_zero_trust_principles(self, results: Dict):
        """IAM-023: Verificar principios de Zero Trust en roles"""
        roles_without_conditions = []

        for role in results.get('roles', []):
            if role.get('trust_policy'):
                # Verificar si tiene condiciones restrictivas
                trust_policy = str(role['trust_policy'])
                has_conditions = 'Condition' in trust_policy or 'IpAddress' in trust_policy

                if not has_conditions and role.get('name'):
                    roles_without_conditions.append(role['name'])

        if roles_without_conditions:
            self._add_finding(
                'IAM-023',
                'MEDIUM',
                f'{len(roles_without_conditions)} roles sin condiciones de Zero Trust',
                {
                    'roles': roles_without_conditions[:10],
                    'total': len(roles_without_conditions),
                    'recommendation': 'Implementar condiciones (IP, MFA, tiempo) en políticas de confianza'
                }
            )

    async def _check_iam_change_audit(self, results: Dict):
        """IAM-024: Verificar auditoría de cambios IAM"""
        # Verificar configuración de auditoría para cambios IAM
        critical_actions = [
            'iam:users:create',
            'iam:users:delete',
            'iam:policies:attach',
            'iam:roles:create',
            'iam:groups:addUser'
        ]

        self._add_finding(
            'IAM-024',
            'HIGH',
            'Verificación de auditoría de cambios IAM requerida',
            {
                'critical_actions': critical_actions,
                'recommendation': 'Configurar alertas en CTS para todos los cambios IAM críticos'
            }
        )

    async def _check_generic_shared_accounts(self, results: Dict):
        """IAM-025: Verificar usuarios genéricos o compartidos"""
        generic_patterns = [
            'admin', 'test', 'demo', 'temp', 'usuario',
            'user[0-9]+', 'prueba', 'desarrollo', 'operador'
        ]

        generic_users = []

        for user in results.get('users', []):
            username = user.get('name', '')
            if username:
                username_lower = username.lower()

                # Verificar patrones genéricos
                for pattern in generic_patterns:
                    if re.match(f'^{pattern}', username_lower):
                        generic_users.append(username)
                        break

        if generic_users:
            self._add_finding(
                'IAM-025',
                'CRITICAL',
                f'{len(generic_users)} cuentas genéricas o compartidas detectadas',
                {
                    'users': generic_users,
                    'recommendation': 'Eliminar cuentas compartidas y crear usuarios nominales individuales'
                }
            )

    async def _check_privileged_identity_management(self, results: Dict):
        """IAM-026: Verificar gestión de identidades privilegiadas"""
        privileged_without_pim = []

        for user in results.get('privileged_accounts', []):
            # Verificar si tiene gestión especial (MFA obligatorio, acceso temporal)
            if not user.get('mfa_enabled') or not user.get('temporary_elevation'):
                username = user.get('user_name', user.get('name', 'unknown'))
                privileged_without_pim.append(username)

        if privileged_without_pim:
            self._add_finding(
                'IAM-026',
                'HIGH',
                f'{len(privileged_without_pim)} cuentas privilegiadas sin gestión PIM/PAM',
                {
                    'users': privileged_without_pim[:10],
                    'total': len(privileged_without_pim),
                    'recommendation': 'Implementar solución PIM para gestión de cuentas administrativas'
                }
            )

    async def _check_inherited_permissions_documentation(self, results: Dict):
        """IAM-027: Verificar documentación de permisos heredados"""
        users_with_complex_inheritance = []

        for user in results.get('users', []):
            inheritance_sources = 0

            if user.get('groups'):
                inheritance_sources += len(user['groups'])
            if user.get('attached_policies'):
                inheritance_sources += len(user['attached_policies'])
            if user.get('inherited_roles'):
                inheritance_sources += len(user['inherited_roles'])

            if inheritance_sources > 3:  # Herencia compleja
                users_with_complex_inheritance.append({
                    'user': user['name'],
                    'sources': inheritance_sources
                })

        if len(users_with_complex_inheritance) > 5:
            self._add_finding(
                'IAM-027',
                'MEDIUM',
                f'{len(users_with_complex_inheritance)} usuarios con herencia de permisos compleja no documentada',
                {
                    'sample_users': users_with_complex_inheritance[:5],
                    'recommendation': 'Documentar y simplificar la herencia de permisos'
                }
            )

    async def _check_break_glass_procedure(self, results: Dict):
        """IAM-028: Verificar procedimiento break-glass"""
        # Buscar cuentas de emergencia
        emergency_accounts = []

        for user in results.get('users', []):
            username = user.get('name', '')
            if username and any(keyword in username.lower() for keyword in ['emergency', 'break', 'glass', 'emergencia']):
                emergency_accounts.append(username)

        if not emergency_accounts:
            self._add_finding(
                'IAM-028',
                'HIGH',
                'No se detectaron cuentas de emergencia (break-glass)',
                {
                    'recommendation': 'Crear procedimiento break-glass con cuenta de emergencia monitoreada'
                }
            )

    async def _check_certificate_management(self, results: Dict):
        """IAM-029: Verificar gestión centralizada de certificados"""
        # En Huawei Cloud, verificar certificados SSL/TLS
        self._add_finding(
            'IAM-029',
            'MEDIUM',
            'Gestión de certificados requiere verificación manual',
            {
                'areas_to_check': ['SSL/TLS certificates', 'API certificates', 'Service certificates'],
                'recommendation': 'Implementar gestión centralizada de certificados con rotación automática'
            }
        )

    async def _check_iam_metrics(self, results: Dict):
        """IAM-030: Verificar métricas de uso IAM"""
        # Calcular métricas básicas
        metrics = {
            'total_users': len(results.get('users', [])),
            'mfa_enabled': len([u for u in results.get('users', []) if u.get('mfa_enabled')]),
            'inactive_users': len(results.get('inactive_users', [])),
            'privileged_accounts': len(results.get('privileged_accounts', [])),
            'groups': len(results.get('groups', [])),
            'policies': len(results.get('policies', []))
        }

        # Siempre generar finding para promover el monitoreo
        self._add_finding(
            'IAM-030',
            'LOW',
            'Métricas IAM básicas disponibles, se requiere dashboard de monitoreo',
            {
                'current_metrics': metrics,
                'recommendation': 'Implementar dashboard con KPIs de seguridad IAM y tendencias'
            }
        )

    # Agregar llamadas a estos métodos en collect_all()
    async def collect_all_with_new_checks(self) -> Dict[str, Any]:
        """Versión extendida de collect_all con los nuevos checks"""
        # Primero ejecutar la recolección original
        results = await self.collect_all()

        # Ejecutar los nuevos checks
        await self._check_onboarding_offboarding_process(results)
        await self._check_privileged_access_logging(results)
        await self._check_inline_policies(results)
        await self._check_permission_review_process(results)
        await self._check_naming_convention(results)
        await self._check_policy_versions(results)
        await self._check_api_token_expiration(results)
        await self._check_environment_segregation(results)
        await self._check_zero_trust_principles(results)
        await self._check_iam_change_audit(results)
        await self._check_generic_shared_accounts(results)
        await self._check_privileged_identity_management(results)
        await self._check_inherited_permissions_documentation(results)
        await self._check_break_glass_procedure(results)
        await self._check_certificate_management(results)
        await self._check_iam_metrics(results)

        return results
