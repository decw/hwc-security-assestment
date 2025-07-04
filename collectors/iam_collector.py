#!/usr/bin/env python3
"""
Colector de datos IAM para Huawei Cloud
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
from huaweicloudsdkcore.auth.credentials import GlobalCredentials
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkcore.region.region import Region
from huaweicloudsdkiam.v3 import *
from huaweicloudsdkiam.v3.region.iam_region import IamRegion
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkiam.v3 import IamClient
from huaweicloudsdkiam.v3.model import KeystoneListUsersRequest
from utils.logger import SecurityLogger
from config.settings import (
    HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY, 
    HUAWEI_DOMAIN_ID, API_TIMEOUT
)
from config.constants import PASSWORD_POLICY, MFA_REQUIREMENTS
import pytz
from dateutil import parser
from datetime import datetime, timedelta, timezone

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
        self._cached_users = []  # Cache para evitar llamadas recursivas

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


    def _parse_date_safe(self, date_str) -> str:
        """Parsear fecha de forma segura"""
        if not date_str:
            return None
            
        try:
            # Si es timestamp en milliseconds
            if isinstance(date_str, (int, float)):
                if date_str > 1000000000000:  # Timestamp en milliseconds
                    date_str = date_str / 1000
                return datetime.fromtimestamp(date_str, tz=timezone.utc).isoformat()
            
            # Si es string, intentar parsearlo
            if isinstance(date_str, str):
                # Intentar diferentes formatos
                formats = [
                    '%Y-%m-%dT%H:%M:%S.%fZ',
                    '%Y-%m-%dT%H:%M:%SZ',
                    '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%d'
                ]
                
                for fmt in formats:
                    try:
                        dt = datetime.strptime(date_str, fmt)
                        if 'Z' in date_str:
                            dt = dt.replace(tzinfo=timezone.utc)
                        return dt.isoformat()
                    except ValueError:
                        continue
                        
                # Si no se puede parsear, devolver como string
                return str(date_str)
                
        except Exception as e:
            self.logger.warning(f"Error parseando fecha {date_str}: {e}")
            return str(date_str) if date_str else None
        
        return None
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

    def _generate_mfa_summary(self, users: List[Dict]) -> Dict:
        """Generar resumen de estado de MFA"""
        summary = {
            'total_users': len(users),
            'with_mfa': 0,
            'without_mfa': 0,
            'by_method': {
                'virtual_mfa': 0,
                'sms_mfa': 0,
                'email_mfa': 0,
                'hardware_token': 0
            },
            'users_without_mfa': []
        }
        
        for user in users:
            mfa_status = user.get('mfa_status', {})
            if mfa_status.get('enabled'):
                summary['with_mfa'] += 1
                
                # Contar por método
                for method, enabled in mfa_status.get('details', {}).items():
                    if enabled and method in summary['by_method']:
                        summary['by_method'][method] += 1
            else:
                summary['without_mfa'] += 1
                summary['users_without_mfa'].append({
                    'user_id': user['id'],
                    'user_name': user['name']
                })
        
        return summary


    async def collect_all(self) -> Dict[str, Any]:
        """Recolectar todos los datos IAM - SOLO UNA VEZ"""
        self.logger.info("Iniciando recolección de datos IAM")
        
        # Verificar si ya se ejecutó
        if hasattr(self, '_already_collected') and self._already_collected:
            self.logger.warning("IAM Collector ya fue ejecutado, retornando resultados previos")
            return self._cached_results
        
        results = {
            'users': [],
            'groups': [],
            'roles': [],
            'policies': [],
            'access_keys': [],
            'mfa_status': {},
            'password_policy': {},
            'findings': self.findings,
            'statistics': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Recolectar usuarios con toda la info de MFA
        users = await self._collect_users_with_mfa_debug()
        results['users'] = users
        
        # Generar resumen de MFA
        results['mfa_status'] = self._generate_mfa_summary(users)
        
        # Otros datos...
        results['groups'] = await self._collect_groups()
        results['policies'] = await self._collect_policies()
        results['password_policy'] = await self._collect_password_policy()
        
        # Calcular estadísticas
        results['statistics'] = self._calculate_statistics(results)
        
        # Marcar como completado y cachear
        self._already_collected = True
        self._cached_results = results
        
        self.logger.info(f"Recolección IAM completada. Hallazgos: {len(self.findings)}")
        return results


    async def _collect_users_with_mfa_debug(self) -> List[Dict]:
        """Recolectar usuarios con debugging mejorado para MFA"""
        users = []
        
        try:
            # Listar usuarios - SOLO UNA VEZ
            self.logger.info("Obteniendo lista de usuarios...")
            request = KeystoneListUsersRequest()
            response = self.client.keystone_list_users(request)
            
            total_users = len(response.users)
            self.logger.info(f"Total de usuarios encontrados: {total_users}")
            
            # Procesar cada usuario
            for idx, user in enumerate(response.users):
                self.logger.info(f"Procesando usuario {idx + 1}/{total_users}: {user.name}")
                
                user_info = {
                    'id': getattr(user, 'id', 'unknown'),
                    'name': getattr(user, 'name', 'unknown'),
                    'enabled': getattr(user, 'enabled', True),
                    'domain_id': getattr(user, 'domain_id', ''),
                    'description': getattr(user, 'description', ''),
                    'email': getattr(user, 'email', None),
                    'phone': getattr(user, 'phone', None)
                }
                
                # Verificar MFA completo
                mfa_status = await self._check_user_mfa(user.id)
                user_info['mfa_status'] = mfa_status
                user_info['mfa_enabled'] = mfa_status['enabled']
                
                # Access keys
                try:
                    access_keys = await self._get_user_access_keys(user.id)
                    user_info['access_keys'] = access_keys
                    user_info['has_programmatic_access'] = len(access_keys) > 0
                except:
                    user_info['access_keys'] = []
                    user_info['has_programmatic_access'] = False
                
                users.append(user_info)
                
                # Generar hallazgos
                if not mfa_status['enabled']:
                    self._add_finding(
                        'IAM-002',
                        'HIGH',
                        f'Usuario sin MFA habilitado: {user_info["name"]}',
                        {
                            'user_id': user_info['id'],
                            'user_name': user_info['name'],
                            'mfa_check_details': mfa_status
                        }
                    )
            
        except Exception as e:
            self.logger.error(f"Error recolectando usuarios: {str(e)}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
        
        return users


    def _inspect_user_object(self, user):
        """Método de debug para inspeccionar atributos del objeto usuario"""
        self.logger.debug("=== Inspeccionando objeto usuario ===")
        
        # Listar todos los atributos
        all_attributes = dir(user)
        
        # Filtrar métodos y atributos privados
        public_attributes = [attr for attr in all_attributes if not attr.startswith('_') and not callable(getattr(user, attr, None))]
        
        self.logger.debug(f"Atributos disponibles: {public_attributes}")
        
        # Intentar obtener valores
        for attr in public_attributes:
            try:
                value = getattr(user, attr)
                self.logger.debug(f"  {attr}: {value}")
            except:
                self.logger.debug(f"  {attr}: <no se pudo obtener>")

    def _calculate_age_in_days(self, date_string: str) -> int:
        """Calcular días desde una fecha"""
        if not date_string:
            return 0
        
        try:
            if isinstance(date_string, str):
                # Manejar diferentes formatos de fecha
                for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S']:
                    try:
                        date = datetime.strptime(date_string, fmt)
                        break
                    except:
                        continue
                else:
                    # Si es timestamp en milisegundos
                    if date_string.isdigit() and len(date_string) > 10:
                        date = datetime.fromtimestamp(int(date_string) / 1000)
                    else:
                        return 0
            else:
                date = datetime.fromtimestamp(date_string / 1000)
            
            return (datetime.now() - date).days
        except:
            return 0
            
    async def _check_user_mfa(self, user_id: str) -> Dict:
        """Verificar TODOS los métodos de MFA - Versión corregida para Huawei Cloud"""
        mfa_info = {
            'enabled': False,
            'device_count': 0,
            'methods': [],
            'details': {
                'virtual_mfa': False,
                'sms_mfa': False,
                'email_mfa': False,
                'hardware_token': False
            },
            'raw_responses': {}  # Para debugging
        }
        
        # 1. Virtual MFA Device (TOTP)
        try:
            self.logger.debug(f"Verificando Virtual MFA para usuario {user_id}")
            request = ShowUserMfaDeviceRequest()
            request.user_id = user_id
            response = self.client.show_user_mfa_device(request)
            
            # Guardar respuesta raw para debug
            mfa_info['raw_responses']['virtual_mfa'] = str(response)
            
            if hasattr(response, 'virtual_mfa_device') and response.virtual_mfa_device:
                mfa_info['details']['virtual_mfa'] = True
                mfa_info['methods'].append({
                    'type': 'VIRTUAL_MFA',
                    'enabled': True,
                    'serial_number': getattr(response.virtual_mfa_device, 'serial_number', 'N/A')
                })
        except Exception as e:
            self.logger.debug(f"Virtual MFA check error: {str(e)}")
        
        # 2. Login Protection Status (incluye SMS y Email)
        try:
            self.logger.debug(f"Verificando Login Protection Status para usuario {user_id}")
            request = ShowLoginProtectRequest()
            request.user_id = user_id
            response = self.client.show_login_protect(request)
            
            # Guardar respuesta raw
            mfa_info['raw_responses']['login_protect'] = str(response)
            
            if hasattr(response, 'login_protect'):
                protect = response.login_protect
                
                # Verificar si login protect está habilitado
                if getattr(protect, 'enabled', False):
                    # Verificar verificación por SMS
                    if getattr(protect, 'verification_method', '') == 'sms':
                        mfa_info['details']['sms_mfa'] = True
                        mfa_info['methods'].append({
                            'type': 'SMS',
                            'enabled': True,
                            'mobile': getattr(protect, 'mobile_bind', 'Configured')
                        })
                    
                    # Verificar verificación por email
                    elif getattr(protect, 'verification_method', '') == 'email':
                        mfa_info['details']['email_mfa'] = True
                        mfa_info['methods'].append({
                            'type': 'EMAIL',
                            'enabled': True,
                            'email': getattr(protect, 'email_bind', 'Configured')
                        })
                    
                    # Algunos usuarios pueden tener ambos
                    if getattr(protect, 'secondary_verification', False):
                        secondary_method = getattr(protect, 'secondary_method', '')
                        if secondary_method == 'sms' and not mfa_info['details']['sms_mfa']:
                            mfa_info['details']['sms_mfa'] = True
                            mfa_info['methods'].append({'type': 'SMS_SECONDARY', 'enabled': True})
                        elif secondary_method == 'email' and not mfa_info['details']['email_mfa']:
                            mfa_info['details']['email_mfa'] = True
                            mfa_info['methods'].append({'type': 'EMAIL_SECONDARY', 'enabled': True})
        except Exception as e:
            self.logger.debug(f"Login Protection check error: {str(e)}")
        
        # 3. Verificar MFA Rules (reglas de MFA configuradas)
        try:
            self.logger.debug(f"Verificando MFA Rules para usuario {user_id}")
            request = ListUserMfaRulesRequest()  # Si existe este endpoint
            request.user_id = user_id
            response = self.client.list_user_mfa_rules(request)
            
            mfa_info['raw_responses']['mfa_rules'] = str(response)
            
            if hasattr(response, 'rules'):
                for rule in response.rules:
                    rule_type = getattr(rule, 'mfa_type', '')
                    if getattr(rule, 'enabled', False):
                        if 'sms' in rule_type.lower():
                            mfa_info['details']['sms_mfa'] = True
                            mfa_info['methods'].append({'type': 'SMS_RULE', 'enabled': True})
                        elif 'email' in rule_type.lower():
                            mfa_info['details']['email_mfa'] = True
                            mfa_info['methods'].append({'type': 'EMAIL_RULE', 'enabled': True})
        except Exception as e:
            self.logger.debug(f"MFA Rules check error: {str(e)}")
        
        # 4. Método alternativo: Verificar en la información del usuario directamente
        try:
            self.logger.debug(f"Verificando info directa del usuario {user_id}")
            request = KeystoneShowUserRequest()
            request.user_id = user_id
            response = self.client.keystone_show_user(request)
            
            if hasattr(response, 'user'):
                user = response.user
                # Buscar indicadores de MFA en los metadatos del usuario
                extra = getattr(user, 'extra', {})
                if isinstance(extra, dict):
                    if extra.get('sms_mfa_enabled'):
                        mfa_info['details']['sms_mfa'] = True
                        mfa_info['methods'].append({'type': 'SMS_META', 'enabled': True})
                    if extra.get('email_mfa_enabled'):
                        mfa_info['details']['email_mfa'] = True
                        mfa_info['methods'].append({'type': 'EMAIL_META', 'enabled': True})
        except Exception as e:
            self.logger.debug(f"User info check error: {str(e)}")
        
        # Consolidar resultados
        mfa_info['device_count'] = len(set(m['type'].split('_')[0] for m in mfa_info['methods']))
        mfa_info['enabled'] = mfa_info['device_count'] > 0
        
        # Log detallado para debugging
        self.logger.info(f"MFA check completo para {user_id}:")
        self.logger.info(f"  Métodos encontrados: {[m['type'] for m in mfa_info['methods']]}")
        self.logger.info(f"  Virtual MFA: {mfa_info['details']['virtual_mfa']}")
        self.logger.info(f"  SMS MFA: {mfa_info['details']['sms_mfa']}")
        self.logger.info(f"  Email MFA: {mfa_info['details']['email_mfa']}")
        
        # Si tenemos respuestas raw, mostrarlas en debug
        if self.logger.logger.level <= 10:  # DEBUG level
            for api, response in mfa_info['raw_responses'].items():
                self.logger.debug(f"  Raw {api}: {response[:200]}...")  # Primeros 200 chars
        
        return mfa_info


    async def _collect_users_with_complete_mfa(self) -> List[Dict]:
        """Recolectar usuarios con verificación completa de MFA"""
        users = []
        mfa_stats = {
            'total_users': 0,
            'with_any_mfa': 0,
            'with_virtual_mfa': 0,
            'with_sms_mfa': 0,
            'with_email_mfa': 0,
            'with_hardware_token': 0,
            'with_multiple_methods': 0,
            'without_any_mfa': 0
        }
        
        try:
            # Listar usuarios
            request = KeystoneListUsersRequest()
            response = self.client.keystone_list_users(request)
            
            mfa_stats['total_users'] = len(response.users)
            self.logger.info(f"Analizando MFA para {mfa_stats['total_users']} usuarios")
            
            for idx, user in enumerate(response.users):
                self.logger.debug(f"Procesando usuario {idx + 1}/{mfa_stats['total_users']}: {user.name}")
                
                # Información básica del usuario
                user_info = {
                    'id': getattr(user, 'id', 'unknown'),
                    'name': getattr(user, 'name', 'unknown'),
                    'enabled': getattr(user, 'enabled', True),
                    'domain_id': getattr(user, 'domain_id', ''),
                    'description': getattr(user, 'description', ''),
                    'email': getattr(user, 'email', None),
                    'phone': getattr(user, 'phone', None)
                }
                
                # Verificación completa de MFA
                mfa_status = await self._check_user_mfa(user.id)
                user_info['mfa_status'] = mfa_status
                user_info['mfa_enabled'] = mfa_status['enabled']
                user_info['mfa_methods'] = mfa_status['methods']
                user_info['mfa_summary'] = mfa_status['summary']
                
                # Actualizar estadísticas
                if mfa_status['enabled']:
                    mfa_stats['with_any_mfa'] += 1
                    
                    # Contar por tipo
                    if mfa_status['details']['virtual_mfa']:
                        mfa_stats['with_virtual_mfa'] += 1
                    if mfa_status['details']['sms_mfa']:
                        mfa_stats['with_sms_mfa'] += 1
                    if mfa_status['details']['email_mfa']:
                        mfa_stats['with_email_mfa'] += 1
                    if mfa_status['details']['hardware_token']:
                        mfa_stats['with_hardware_token'] += 1
                    
                    # Verificar múltiples métodos
                    if mfa_status['device_count'] > 1:
                        mfa_stats['with_multiple_methods'] += 1
                else:
                    mfa_stats['without_any_mfa'] += 1
                
                # Obtener access keys
                try:
                    access_keys = await self._get_user_access_keys(user.id)
                    user_info['access_keys'] = access_keys
                    user_info['has_programmatic_access'] = len(access_keys) > 0
                except:
                    user_info['access_keys'] = []
                    user_info['has_programmatic_access'] = False
                
                # Análisis de seguridad
                user_info['security_risk'] = self._calculate_user_risk_score(user_info)
                
                users.append(user_info)
                
                # Generar hallazgos según el análisis
                self._generate_mfa_findings(user_info)
            
            # Log de estadísticas finales
            self.logger.info("=== Resumen de MFA ===")
            self.logger.info(f"Total usuarios: {mfa_stats['total_users']}")
            self.logger.info(f"Con algún MFA: {mfa_stats['with_any_mfa']} ({mfa_stats['with_any_mfa']/mfa_stats['total_users']*100:.1f}%)")
            self.logger.info(f"  - Virtual MFA (TOTP): {mfa_stats['with_virtual_mfa']}")
            self.logger.info(f"  - SMS MFA: {mfa_stats['with_sms_mfa']}")
            self.logger.info(f"  - Email MFA: {mfa_stats['with_email_mfa']}")
            self.logger.info(f"  - Hardware Token: {mfa_stats['with_hardware_token']}")
            self.logger.info(f"  - Múltiples métodos: {mfa_stats['with_multiple_methods']}")
            self.logger.info(f"Sin ningún MFA: {mfa_stats['without_any_mfa']} ({mfa_stats['without_any_mfa']/mfa_stats['total_users']*100:.1f}%)")
            
            # Guardar estadísticas para el reporte
            self.mfa_statistics = mfa_stats
            
        except Exception as e:
            self.logger.error(f"Error recolectando usuarios: {str(e)}")
        
        return users

    def _calculate_user_risk_score(self, user_info: Dict) -> Dict:
        """Calcular score de riesgo del usuario considerando MFA"""
        risk = {
            'score': 0,
            'level': 'LOW',
            'factors': [],
            'is_privileged': False
        }
        
        # Verificar si es privilegiado
        if any(ind in user_info.get('name', '').lower() for ind in ['admin', 'root', 'super']):
            risk['is_privileged'] = True
            risk['factors'].append('Usuario privilegiado')
        
        # Factor: Sin MFA
        if not user_info.get('mfa_enabled'):
            risk['score'] += 5
            risk['factors'].append('Sin MFA habilitado')
            
            if risk['is_privileged']:
                risk['score'] += 3  # Penalización extra para privilegiados
        
        # Factor: Solo un método de MFA
        elif user_info.get('mfa_status', {}).get('device_count', 0) == 1:
            risk['score'] += 2
            risk['factors'].append('Solo un método de MFA')
        
        # Factor: Access keys activas
        if user_info.get('has_programmatic_access'):
            risk['score'] += 2
            risk['factors'].append('Tiene access keys activas')
        
        # Determinar nivel
        if risk['score'] >= 8:
            risk['level'] = 'CRITICAL'
        elif risk['score'] >= 6:
            risk['level'] = 'HIGH'
        elif risk['score'] >= 3:
            risk['level'] = 'MEDIUM'
        else:
            risk['level'] = 'LOW'
        
        return risk

    def _generate_mfa_findings(self, user_info: Dict):
        """Generar hallazgos específicos según el estado de MFA"""
        mfa_status = user_info.get('mfa_status', {})
        
        # Sin ningún MFA
        if not mfa_status.get('enabled'):
            severity = 'CRITICAL' if user_info.get('security_risk', {}).get('is_privileged') else 'HIGH'
            
            self._add_finding(
                'IAM-002',
                severity,
                f'Usuario sin ningún método de MFA habilitado: {user_info["name"]}',
                {
                    'user_id': user_info['id'],
                    'user_name': user_info['name'],
                    'has_programmatic_access': user_info.get('has_programmatic_access', False),
                    'risk_score': user_info.get('security_risk', {}).get('score', 0),
                    'recommendation': 'Habilitar al menos un método de MFA inmediatamente'
                }
            )
        
        # Solo un método de MFA (se recomienda múltiple para usuarios críticos)
        elif mfa_status.get('device_count') == 1 and user_info.get('security_risk', {}).get('is_privileged'):
            self._add_finding(
                'IAM-010',
                'MEDIUM',
                f'Usuario privilegiado con solo un método de MFA: {user_info["name"]}',
                {
                    'user_id': user_info['id'],
                    'user_name': user_info['name'],
                    'current_method': mfa_status['methods'][0]['type'],
                    'recommendation': 'Configurar método de MFA adicional como respaldo'
                }
            )
        
        # MFA débil (solo email)
        elif mfa_status['details'].get('email_mfa') and not mfa_status['details'].get('virtual_mfa') and not mfa_status['details'].get('sms_mfa'):
            self._add_finding(
                'IAM-011',
                'MEDIUM',
                f'Usuario con MFA débil (solo email): {user_info["name"]}',
                {
                    'user_id': user_info['id'],
                    'user_name': user_info['name'],
                    'current_methods': 'Email MFA only',
                    'recommendation': 'Agregar Virtual MFA (TOTP) o SMS para mayor seguridad'
                }
            )


    async def _get_user_access_keys(self, user_id: str) -> List[Dict]:
        """Obtener access keys del usuario con análisis detallado"""
        access_keys = []
        
        try:
            request = ListPermanentAccessKeysRequest()
            request.user_id = user_id
            response = self.client.list_permanent_access_keys(request)
            
            for key in response.credentials:
                key_age = self._calculate_age_in_days(key.create_time)
                
                key_info = {
                    'access_key_id': key.access[:6] + '****',  # Ofuscado
                    'status': key.status,
                    'created_at': key.create_time,
                    'age_days': key_age,
                    'description': getattr(key, 'description', ''),
                    # Información de uso
                    'last_used': None,
                    'last_used_days_ago': None,
                    'last_used_service': None,
                    'ever_used': False
                }
                
                # Obtener información de último uso
                try:
                    usage_info = await self._get_access_key_usage(key.access)
                    if usage_info:
                        key_info.update({
                            'last_used': usage_info.get('last_used'),
                            'last_used_days_ago': self._calculate_age_in_days(usage_info.get('last_used')),
                            'last_used_service': usage_info.get('service_name'),
                            'ever_used': True
                        })
                except:
                    pass
                
                access_keys.append(key_info)
        
        except Exception as e:
            self.logger.debug(f"No se pudieron obtener access keys para usuario {user_id}")
        
        return access_keys

    def _analyze_user_security(self, user_info: Dict) -> Dict:
        """Analizar seguridad del usuario"""
        analysis = {
            'risk_score': 0,
            'issues': [],
            'recommendations': []
        }
        
        # Análisis de contraseña
        if user_info.get('password_expires_at'):
            pwd_age = self._calculate_age_in_days(user_info['password_expires_at'])
            if pwd_age > PASSWORD_POLICY['max_age_days']:
                analysis['risk_score'] += 3
                analysis['issues'].append(f"Contraseña sin cambiar por {pwd_age} días")
                analysis['recommendations'].append("Forzar cambio de contraseña")
        
        if user_info.get('pwd_status') == 'expired':
            analysis['risk_score'] += 5
            analysis['issues'].append("Contraseña expirada")
        
        # Análisis de último login
        if user_info.get('last_login_time'):
            last_login_days = self._calculate_age_in_days(user_info['last_login_time'])
            if last_login_days > 90:
                analysis['risk_score'] += 2
                analysis['issues'].append(f"Sin actividad por {last_login_days} días")
                analysis['recommendations'].append("Considerar desactivar cuenta inactiva")
        else:
            analysis['issues'].append("Usuario nunca ha iniciado sesión")
            if user_info.get('created_time'):
                account_age = self._calculate_age_in_days(user_info['created_time'])
                if account_age > 30:
                    analysis['risk_score'] += 1
                    analysis['recommendations'].append("Revisar necesidad de la cuenta")
        
        # Análisis de MFA
        if not user_info.get('mfa_enabled'):
            analysis['risk_score'] += 4
            analysis['issues'].append("Sin MFA habilitado")
            analysis['recommendations'].append("Habilitar MFA inmediatamente")
        
        # Análisis de access keys
        for key in user_info.get('access_keys', []):
            if key['age_days'] > 90:
                analysis['risk_score'] += 3
                analysis['issues'].append(f"Access key sin rotar por {key['age_days']} días")
            
            if not key['ever_used'] and key['age_days'] > 7:
                analysis['risk_score'] += 2
                analysis['issues'].append("Access key creada pero nunca utilizada")
                analysis['recommendations'].append("Eliminar access keys no utilizadas")
            
            if key['status'] != 'active' and key['age_days'] > 30:
                analysis['risk_score'] += 1
                analysis['issues'].append("Access key inactiva sin eliminar")
        
        # Determinar nivel de riesgo
        if analysis['risk_score'] >= 10:
            analysis['risk_level'] = 'CRITICAL'
        elif analysis['risk_score'] >= 7:
            analysis['risk_level'] = 'HIGH'
        elif analysis['risk_score'] >= 4:
            analysis['risk_level'] = 'MEDIUM'
        else:
            analysis['risk_level'] = 'LOW'
        
        return analysis

    def _generate_user_findings(self, user_info: Dict):
        """Generar hallazgos basados en el análisis del usuario"""
        analysis = user_info.get('security_analysis', {})
        
        # Hallazgo por falta de MFA
        if not user_info.get('mfa_enabled'):
            # Verificar si es usuario privilegiado
            is_privileged = self._is_privileged_user(user_info)
            
            self._add_finding(
                'IAM-002',
                'CRITICAL' if is_privileged else 'HIGH',
                f'Usuario sin MFA habilitado: {user_info["name"]}',
                {
                    'user_id': user_info['id'],
                    'user_name': user_info['name'],
                    'is_privileged': is_privileged,
                    'last_login': user_info.get('last_login_time'),
                    'has_programmatic_access': user_info.get('has_programmatic_access', False),
                    'risk_score': analysis.get('risk_score', 0)
                }
            )
        
        # Hallazgo por access keys antiguas
        for key in user_info.get('access_keys', []):
            if key['age_days'] > 90:
                self._add_finding(
                    'IAM-004',
                    'HIGH',
                    f'Access Key sin rotación por {key["age_days"]} días',
                    {
                        'user_name': user_info['name'],
                        'access_key_id': key['access_key_id'],
                        'age_days': key['age_days'],
                        'last_used': key.get('last_used'),
                        'ever_used': key.get('ever_used', False),
                        'recommendation': 'Rotar inmediatamente' if key['age_days'] > 180 else 'Planificar rotación'
                    }
                )
        
        # Hallazgo por cuentas inactivas
        if user_info.get('last_login_time'):
            last_login_days = self._calculate_age_in_days(user_info['last_login_time'])
            if last_login_days > 90:
                self._add_finding(
                    'IAM-006',
                    'MEDIUM',
                    f'Cuenta de usuario inactiva por {last_login_days} días',
                    {
                        'user_name': user_info['name'],
                        'last_login': user_info['last_login_time'],
                        'days_inactive': last_login_days,
                        'has_access_keys': len(user_info.get('access_keys', [])) > 0
                    }
                )


    async def _collect_users(self) -> List[Dict]:
        """Recolectar información detallada de usuarios"""
        users = []
        mfa_summary = {
            'total_users': 0,
            'with_mfa': 0,
            'without_mfa': 0,
            'check_failed': 0
        }
        
        try:
            # Listar usuarios
            request = KeystoneListUsersRequest()
            response = self.client.keystone_list_users(request)
            
            self.logger.info(f"Total de usuarios encontrados: {len(response.users)}")
            mfa_summary['total_users'] = len(response.users)
            
            for user in response.users:
                # Info básica
                user_info = {
                    'id': getattr(user, 'id', 'unknown'),
                    'name': getattr(user, 'name', 'unknown'),
                    'enabled': getattr(user, 'enabled', True),
                    'domain_id': getattr(user, 'domain_id', ''),
                    'description': getattr(user, 'description', ''),
                    # Verificar si el usuario tiene atributos de MFA directamente
                    'mfa_enabled': None,
                    'mfa_check_details': {}
                }
                
                # Verificar si hay información de MFA en el objeto usuario
                # Algunos APIs incluyen esta info directamente
                if hasattr(user, 'mfa_enabled'):
                    user_info['mfa_enabled'] = getattr(user, 'mfa_enabled', False)
                    user_info['mfa_check_details']['source'] = 'user_object'
                    self.logger.debug(f"MFA info directa en usuario {user_info['name']}: {user_info['mfa_enabled']}")
                
                # Si no está en el objeto, verificar con el método dedicado
                if user_info['mfa_enabled'] is None:
                    mfa_status = await self._check_user_mfa(user.id)
                    user_info['mfa_enabled'] = mfa_status.get('enabled', False)
                    user_info['mfa_check_details'] = mfa_status
                
                # Actualizar contadores
                if user_info['mfa_enabled'] is True:
                    mfa_summary['with_mfa'] += 1
                elif user_info['mfa_enabled'] is False:
                    mfa_summary['without_mfa'] += 1
                else:
                    mfa_summary['check_failed'] += 1
                
                # Obtener access keys
                try:
                    access_keys = await self._get_user_access_keys(user.id)
                    user_info['access_keys'] = access_keys
                    user_info['has_programmatic_access'] = len(access_keys) > 0
                except:
                    user_info['access_keys'] = []
                    user_info['has_programmatic_access'] = False
                
                users.append(user_info)
                
                # Solo generar hallazgo si realmente no tiene MFA
                # y no es un error de verificación
                if (user_info['mfa_enabled'] is False and 
                    user_info['mfa_check_details'].get('error') is None):
                    
                    self._add_finding(
                        'IAM-002',
                        'HIGH',
                        f'Usuario sin MFA habilitado: {user_info["name"]}',
                        {
                            'user_id': user_info['id'],
                            'user_name': user_info['name'],
                            'has_access_keys': user_info.get('has_programmatic_access', False),
                            'mfa_check_method': user_info['mfa_check_details'].get('check_method', 'unknown')
                        }
                    )
            
            # Log resumen de MFA
            self.logger.info(f"Resumen MFA: Total={mfa_summary['total_users']}, Con MFA={mfa_summary['with_mfa']}, Sin MFA={mfa_summary['without_mfa']}, Verificación fallida={mfa_summary['check_failed']}")
            
            # Si TODOS aparecen sin MFA, probablemente hay un problema
            if mfa_summary['without_mfa'] == mfa_summary['total_users'] and mfa_summary['total_users'] > 5:
                self.logger.warning("ADVERTENCIA: Todos los usuarios aparecen sin MFA. Posible problema con la verificación de MFA.")
                
                # Agregar nota al finding
                self._add_finding(
                    'IAM-009',
                    'INFO',
                    'Nota: La verificación de MFA puede requerir permisos adicionales',
                    {
                        'total_users': mfa_summary['total_users'],
                        'all_without_mfa': True,
                        'recommendation': 'Verificar permisos de API para consultar estado de MFA'
                    }
                )
                    
        except Exception as e:
            self.logger.error(f"Error recolectando usuarios: {str(e)}")
        
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


    async def _collect_role_assignments(self) -> List[Dict]:
        """Método alternativo para obtener información de roles a través de asignaciones"""
        assignments = []
        
        # Listar asignaciones de roles para usuarios
        for user in self.users:
            try:
                request = ListProjectPermissionsForAgencyRequest()
                request.project_id = HUAWEI_PROJECT_ID
                # Ajustar según la API real disponible
                
            except Exception as e:
                self.logger.debug(f"No se pudieron obtener roles para usuario {user['id']}")
        
        return assignments
        

    async def _collect_roles(self) -> List[Dict]:
        """Recolectar información de roles"""
        roles = []
        try:
            # Listar roles del sistema
            request = ListPermanentAccessKeysRequest()
            # En Huawei Cloud IAM v3, los roles se obtienen de forma diferente
            # Intentar obtener roles custom primero
            try:
                custom_request = ListCustomPoliciesRequest()
                response = self.client.list_custom_policies(custom_request)
                
                for role in response.roles:
                    role_info = {
                        'id': role.id,
                        'name': role.display_name,
                        'type': 'custom',
                        'description': role.description,
                        'created_at': getattr(role, 'create_time', None)
                    }
                    roles.append(role_info)
            except:
                self.logger.debug("No se pudieron obtener roles custom")
                
            # Nota: Los roles de sistema no siempre están disponibles via API
            self.logger.info(f"Roles recolectados: {len(roles)}")
            
        except Exception as e:
            self.logger.error(f"Error recolectando roles: {str(e)}")
            self.logger.debug("Los roles pueden requerir permisos adicionales")
            
        return roles

    async def _check_admin_privileges(self, user_id: str) -> bool:
        """Verificar si un usuario tiene privilegios administrativos"""
        try:
            # Método 1: Verificar grupos del usuario
            try:
                request = KeystoneListGroupsForUserRequest()
                request.user_id = user_id
                response = self.client.keystone_list_groups_for_user(request)
                
                # Buscar grupos administrativos
                admin_group_names = ['admin', 'administrators', 'power_user']
                for group in response.groups:
                    if any(admin_name in group.name.lower() for admin_name in admin_group_names):
                        return True
            except:
                self.logger.debug(f"No se pudo verificar grupos para usuario {user_id}")
            
            # Método 2: Verificar políticas directas (si está disponible)
            # Nota: La API exacta puede variar según la versión
            
            return False
        except Exception as e:
            self.logger.debug(f"Error verificando privilegios admin: {str(e)}")
            return False


    async def _collect_policies(self) -> List[Dict]:
        """Recolectar políticas IAM - CORREGIDO"""
        policies = []
        try:
            # Obtener políticas custom
            request = ListCustomPoliciesRequest()
            response = self.client.list_custom_policies(request)
            

            # La respuesta contiene políticas en el atributo 'policies'
            for policy in getattr(response, 'policies', []):
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
        """Verificar estado de MFA para todos los usuarios - Versión mejorada"""
        mfa_status = {
            'total_users': 0,
            'mfa_enabled': 0,
            'mfa_disabled': 0,
            'users_without_mfa': [],
            'mfa_methods_summary': {
                'virtual_mfa': 0,
                'sms_mfa': 0,
                'email_mfa': 0,
                'hardware_mfa': 0,
                'multiple_methods': 0
            },
            'users_mfa_details': []
        }
        
        try:
            users = await self._collect_users() if not hasattr(self, '_cached_users') else self._cached_users
            mfa_status['total_users'] = len(users)
            
            for user in users:
                user_mfa_info = {
                    'user_id': user['id'],
                    'user_name': user['name'],
                    'mfa_methods': [],
                    'has_mfa': False
                }
                
                try:
                    # Verificar login verification settings
                    request = ShowUserLoginProtectRequest()
                    request.user_id = user['id']
                    response = self.client.show_user_login_protect(request)
                    
                    login_protect = response.login_protect
                    
                    # Verificar cada método de MFA
                    mfa_methods = []
                    
                    # Virtual MFA (TOTP)
                    if getattr(login_protect, 'verification_method', None) == 'vmfa':
                        mfa_methods.append('VIRTUAL_MFA')
                        mfa_status['mfa_methods_summary']['virtual_mfa'] += 1
                    
                    # SMS MFA
                    if getattr(login_protect, 'verification_method', None) == 'sms':
                        mfa_methods.append('SMS_MFA')
                        mfa_status['mfa_methods_summary']['sms_mfa'] += 1
                    
                    # Email MFA
                    if getattr(login_protect, 'verification_method', None) == 'email':
                        mfa_methods.append('EMAIL_MFA')
                        mfa_status['mfa_methods_summary']['email_mfa'] += 1
                    
                    # También verificar el método antiguo para compatibilidad
                    if hasattr(self.client, 'show_user_mfa_device'):
                        mfa_request = ShowUserMfaDeviceRequest()
                        mfa_request.user_id = user['id']
                        mfa_response = self.client.show_user_mfa_device(mfa_request)
                        
                        if getattr(mfa_response, 'virtual_mfa_device', None):
                            if 'VIRTUAL_MFA' not in mfa_methods:
                                mfa_methods.append('VIRTUAL_MFA')
                                mfa_status['mfa_methods_summary']['virtual_mfa'] += 1
                    
                    # Actualizar información del usuario
                    user_mfa_info['mfa_methods'] = mfa_methods
                    user_mfa_info['has_mfa'] = len(mfa_methods) > 0
                    
                    if len(mfa_methods) > 0:
                        mfa_status['mfa_enabled'] += 1
                        if len(mfa_methods) > 1:
                            mfa_status['mfa_methods_summary']['multiple_methods'] += 1
                    else:
                        mfa_status['mfa_disabled'] += 1
                        mfa_status['users_without_mfa'].append({
                            'user_id': user['id'],
                            'user_name': user['name']
                        })
                        
                        # Verificar si es usuario privilegiado sin MFA
                        if await self._check_admin_privileges(user['id']):
                            self._add_finding(
                                'IAM-002',
                                'CRITICAL',
                                f'Usuario administrativo sin MFA: {user["name"]}',
                                {
                                    'user_id': user['id'],
                                    'user_name': user['name'],
                                    'recommendation': 'Habilitar al menos un método de MFA inmediatamente'
                                }
                            )
                    
                    mfa_status['users_mfa_details'].append(user_mfa_info)
                    self.logger.info(f"Usuario {user['name']}: MFA métodos = {mfa_methods}")
                    
                except Exception as e:
                    self.logger.debug(f"No se pudo verificar MFA completo para usuario {user['id']}: {str(e)}")
                    # Intentar método alternativo o asumir sin MFA
                    mfa_status['mfa_disabled'] += 1
                    mfa_status['users_without_mfa'].append({
                        'user_id': user['id'],
                        'user_name': user['name'],
                        'error': str(e)
                    })
                    
        except Exception as e:
            self.logger.error(f"Error crítico recolectando estado MFA: {str(e)}")
        
        # Agregar análisis de métodos de MFA
        if mfa_status['mfa_methods_summary']['sms_mfa'] > 0:
            self._add_finding(
                'IAM-006',
                'MEDIUM',
                f"{mfa_status['mfa_methods_summary']['sms_mfa']} usuarios usando SMS como MFA",
                {
                    'count': mfa_status['mfa_methods_summary']['sms_mfa'],
                    'recommendation': 'SMS MFA es vulnerable a SIM swapping. Considerar migrar a Virtual MFA o hardware tokens'
                }
            )
        
        self.logger.info(f"MFA Status Summary: {mfa_status['mfa_methods_summary']}")
        
        return mfa_status
    
    def _calculate_iam_compliance_score(self, stats: dict) -> float:
        """Calcular score de cumplimiento IAM (0-100)"""
        score = 100.0
        penalties = []
        
        # Penalizaciones por incumplimientos
        if stats['mfa_compliance_rate'] < 100:
            penalty = (100 - stats['mfa_compliance_rate']) * 0.3
            penalties.append(('MFA incompleto', penalty))
            score -= penalty
        
        if stats['access_key_security']['keys_older_90_days'] > 0:
            penalty = min(stats['access_key_security']['keys_older_90_days'] * 5, 20)
            penalties.append(('Keys sin rotar', penalty))
            score -= penalty
        
        if stats['user_activity']['inactive_90_days'] > 0:
            penalty = min(stats['user_activity']['inactive_90_days'] * 3, 15)
            penalties.append(('Usuarios inactivos', penalty))
            score -= penalty
        
        if stats['password_security']['no_password_expiry'] > 0:
            penalty = min(stats['password_security']['no_password_expiry'] * 2, 10)
            penalties.append(('Sin expiración de contraseña', penalty))
            score -= penalty
        
        if stats['privileged_users']['admins_without_mfa'] > 0:
            penalty = stats['privileged_users']['admins_without_mfa'] * 10
            penalties.append(('Admins sin MFA', penalty))
            score -= penalty
        
        # Log de penalizaciones para transparencia
        if penalties:
            self.logger.debug(f"Penalizaciones de compliance IAM: {penalties}")
        
        return max(round(score, 2), 0.0)  # No permitir scores negativos


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
        # Primero, obtener mfa_status de manera segura
        mfa_status = results.get('mfa_status', {})
        
        stats = {
            'total_users': len(results.get('users', [])),
            'total_groups': len(results.get('groups', [])),
            'total_policies': len(results.get('policies', [])),
            'total_access_keys': len(results.get('access_keys', [])),
            'users_without_mfa': mfa_status.get('mfa_disabled', 0),  # Corregido aquí
            'mfa_compliance_rate': 0,
            'old_access_keys': 0,
            'findings_by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            },
            # Nuevas estadísticas
            'user_access_summary': {
                'console_only': 0,
                'programmatic_only': 0,
                'both_access': 0,
                'no_access': 0
            },
            'user_activity': {
                'never_logged_in': 0,
                'inactive_90_days': 0,
                'inactive_30_days': 0,
                'active_users': 0
            },
            'password_security': {
                'passwords_older_90_days': 0,
                'passwords_older_180_days': 0,
                'no_password_expiry': 0
            },
            'access_key_security': {
                'active_keys': 0,
                'inactive_keys': 0,
                'never_used_keys': 0,
                'keys_unused_90_days': 0,
                'keys_older_90_days': 0,
                'keys_older_180_days': 0
            },
            'privileged_users': {
                'total_admins': 0,
                'admins_without_mfa': mfa_status.get('admin_users_without_mfa', 0),
                'admins_inactive': 0
            }
        }
        
        # Calcular tasa de cumplimiento MFA de manera segura
        total_users = mfa_status.get('total_users', stats['total_users'])
        mfa_enabled = mfa_status.get('mfa_enabled', 0)
        
        if total_users > 0:
            stats['mfa_compliance_rate'] = round((mfa_enabled / total_users) * 100, 2)
        
        # Analizar usuarios
        for user in results.get('users', []):
            # Tipo de acceso
            has_console = user.get('has_console_access', False)
            has_programmatic = user.get('has_programmatic_access', False)
            
            if has_console and has_programmatic:
                stats['user_access_summary']['both_access'] += 1
            elif has_console:
                stats['user_access_summary']['console_only'] += 1
            elif has_programmatic:
                stats['user_access_summary']['programmatic_only'] += 1
            else:
                stats['user_access_summary']['no_access'] += 1
            
            # Actividad del usuario
            if user.get('never_logged_in'):
                stats['user_activity']['never_logged_in'] += 1
            elif user.get('days_since_last_login'):
                days_inactive = user['days_since_last_login']
                if days_inactive > 90:
                    stats['user_activity']['inactive_90_days'] += 1
                elif days_inactive > 30:
                    stats['user_activity']['inactive_30_days'] += 1
                else:
                    stats['user_activity']['active_users'] += 1
            else:
                stats['user_activity']['active_users'] += 1
            
            # Seguridad de contraseñas
            if user.get('password_age_days'):
                password_age = user['password_age_days']
                if password_age > 180:
                    stats['password_security']['passwords_older_180_days'] += 1
                elif password_age > 90:
                    stats['password_security']['passwords_older_90_days'] += 1
            
            if not user.get('password_expires_at'):
                stats['password_security']['no_password_expiry'] += 1
        
        # Analizar access keys
        for key in results.get('access_keys', []):
            if key.get('status') == 'active':
                stats['access_key_security']['active_keys'] += 1
                
                # Keys antiguas
                age_days = key.get('age_days', 0)
                if age_days > 180:
                    stats['access_key_security']['keys_older_180_days'] += 1
                elif age_days > 90:
                    stats['access_key_security']['keys_older_90_days'] += 1
                
                # Keys sin uso
                if key.get('never_used'):
                    stats['access_key_security']['never_used_keys'] += 1
                elif key.get('last_used_days_ago', 0) > 90:
                    stats['access_key_security']['keys_unused_90_days'] += 1
            else:
                stats['access_key_security']['inactive_keys'] += 1
        
        # Contar access keys antiguas (para compatibilidad)
        stats['old_access_keys'] = stats['access_key_security']['keys_older_90_days']
        
        # Analizar usuarios privilegiados
        admin_user_ids = set()
        for finding in self.findings:
            if finding.get('id') == 'IAM-001':
                user_id = finding.get('details', {}).get('user_id')
                if user_id:
                    admin_user_ids.add(user_id)
        
        for user in results.get('users', []):
            if user.get('id') in admin_user_ids:
                stats['privileged_users']['total_admins'] += 1
                
                # Admin inactivo
                days_inactive = user.get('days_since_last_login', 0)
                if days_inactive > 30:
                    stats['privileged_users']['admins_inactive'] += 1
        
        # Contar hallazgos por severidad
        for finding in self.findings:
            severity = finding.get('severity', 'LOW')
            if severity in stats['findings_by_severity']:
                stats['findings_by_severity'][severity] += 1
        
        # Agregar resumen de riesgos
        stats['risk_summary'] = {
            'critical_risks': stats['findings_by_severity']['CRITICAL'],
            'high_priority_issues': (
                stats['privileged_users']['admins_without_mfa'] +
                stats['user_activity']['never_logged_in'] +
                stats['access_key_security']['keys_older_180_days']
            ),
            'compliance_score': self._calculate_iam_compliance_score(stats)
        }
        
        return stats



    def safe_dict_access(func):
        """Decorador para manejar acceso seguro a diccionarios"""
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except KeyError as e:
                logger.error(f"KeyError en {func.__name__}: {e}")
                return {}
        return wrapper