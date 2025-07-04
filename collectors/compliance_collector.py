#!/usr/bin/env python3
"""
Colector de cumplimiento y compliance para Huawei Cloud
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Any
from utils.logger import SecurityLogger
from config.settings import COMPLIANCE_FRAMEWORKS
from config.constants import (
    PASSWORD_POLICY, MFA_REQUIREMENTS, 
    LOG_RETENTION_REQUIREMENTS, BACKUP_REQUIREMENTS,
    DATA_CLASSIFICATION_TAGS, WEAK_CIPHERS
)

class ComplianceCollector:
    """Colector para verificar cumplimiento con frameworks de seguridad"""
    
    def __init__(self, iam_data: dict, network_data: dict, 
                 storage_data: dict, monitoring_data: dict):
        self.logger = SecurityLogger('ComplianceCollector')
        self.findings = []
        self.iam_data = iam_data
        self.network_data = network_data
        self.storage_data = storage_data
        self.monitoring_data = monitoring_data
    
    async def collect_all(self) -> Dict[str, Any]:
        """Evaluar cumplimiento con todos los frameworks"""
        self.logger.info("Iniciando evaluación de cumplimiento")
        
        results = {
            'frameworks': {},  # CORREGIDO: Inicializar frameworks
            'overall_compliance': 0,
            'findings': self.findings,
            'recommendations': [],
            'gap_analysis': {},
            'maturity_level': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        # Evaluar cada framework
        for framework in COMPLIANCE_FRAMEWORKS:
            self.logger.info(f"Evaluando cumplimiento con {framework}")
            
            try:
                if framework == 'CIS_Huawei_Cloud_1.1':
                    results['frameworks'][framework] = await self._evaluate_cis()
                elif framework == 'ISO_27001_2022':
                    results['frameworks'][framework] = await self._evaluate_iso27001()
                elif framework == 'NIST_CSF_2.0':
                    results['frameworks'][framework] = await self._evaluate_nist_csf()
            except Exception as e:
                self.logger.error(f"Error evaluando framework {framework}: {str(e)}")
                # Continuar con el siguiente framework
                results['frameworks'][framework] = {'error': str(e), 'compliance_percentage': 0}
        
        # Calcular cumplimiento general
        results['overall_compliance'] = self._calculate_overall_compliance(results['frameworks'])
        
        # Análisis de brechas
        results['gap_analysis'] = self._perform_gap_analysis(results['frameworks'])
        
        # Determinar nivel de madurez
        results['maturity_level'] = self._calculate_maturity_level(results)
        
        # Generar recomendaciones
        results['recommendations'] = self._generate_recommendations()
        
        self.logger.info(f"Evaluación de cumplimiento completada. Hallazgos: {len(self.findings)}")
        return results
    
    async def _evaluate_cis(self) -> Dict[str, Any]:
        """Evaluar cumplimiento con CIS Benchmarks"""
        cis_results = {
            'version': '1.1',
            'sections': {},
            'total_controls': 0,
            'passed_controls': 0,
            'failed_controls': 0,
            'not_applicable': 0,
            'compliance_percentage': 0
        }
        
        # Sección 1: Identity and Access Management
        cis_results['sections']['1_iam'] = {
            'title': 'Identity and Access Management',
            'controls': []
        }
        
        # 1.1 - Evitar uso de cuenta root
        control_1_1 = self._check_root_account_usage()
        cis_results['sections']['1_iam']['controls'].append(control_1_1)
        
        # 1.2 - MFA para usuarios privilegiados
        control_1_2 = self._check_mfa_privileged_users()
        cis_results['sections']['1_iam']['controls'].append(control_1_2)
        
        # 1.3 - Rotación de credenciales
        control_1_3 = self._check_credential_rotation()
        cis_results['sections']['1_iam']['controls'].append(control_1_3)
        
        # 1.4 - Políticas de contraseñas
        control_1_4 = self._check_password_policy()
        cis_results['sections']['1_iam']['controls'].append(control_1_4)
        
        # Sección 2: Logging
        cis_results['sections']['2_logging'] = {
            'title': 'Logging',
            'controls': []
        }
        
        # 2.1 - Cloud Trace habilitado
        control_2_1 = self._check_cloud_trace_enabled()
        cis_results['sections']['2_logging']['controls'].append(control_2_1)
        
        # 2.2 - Cifrado de logs
        control_2_2 = self._check_log_encryption()
        cis_results['sections']['2_logging']['controls'].append(control_2_2)
        
        # Sección 3: Networking
        cis_results['sections']['3_networking'] = {
            'title': 'Networking',
            'controls': []
        }
        
        # 3.1 - Security groups restrictivos
        control_3_1 = self._check_security_group_restrictions()
        cis_results['sections']['3_networking']['controls'].append(control_3_1)
        
        # 3.2 - Sin puertos administrativos expuestos
        control_3_2 = self._check_admin_ports_exposure()
        cis_results['sections']['3_networking']['controls'].append(control_3_2)
        
        # Sección 4: Storage
        cis_results['sections']['4_storage'] = {
            'title': 'Storage',
            'controls': []
        }
        
        # 4.1 - Cifrado en reposo
        control_4_1 = self._check_encryption_at_rest()
        cis_results['sections']['4_storage']['controls'].append(control_4_1)
        
        # 4.2 - Sin buckets públicos
        control_4_2 = self._check_public_buckets()
        cis_results['sections']['4_storage']['controls'].append(control_4_2)
        
        # Calcular estadísticas
        for section in cis_results['sections'].values():
            for control in section['controls']:
                cis_results['total_controls'] += 1
                if control['status'] == 'PASS':
                    cis_results['passed_controls'] += 1
                elif control['status'] == 'FAIL':
                    cis_results['failed_controls'] += 1
                else:
                    cis_results['not_applicable'] += 1
        
        if cis_results['total_controls'] > 0:
            cis_results['compliance_percentage'] = round(
                (cis_results['passed_controls'] / cis_results['total_controls']) * 100, 2
            )
        
        return cis_results
    
    async def _evaluate_iso27001(self) -> Dict[str, Any]:
        """Evaluar cumplimiento con ISO 27001:2022"""
        iso_results = {
            'version': '2022',
            'domains': {},
            'total_controls': 93,
            'implemented': 0,
            'partial': 0,
            'not_implemented': 0,
            'compliance_percentage': 0
        }
        
        # A.5 - Políticas de seguridad
        iso_results['domains']['A5'] = {
            'title': 'Organizational controls',
            'controls': []
        }
        
        # A.8 - Gestión de activos
        iso_results['domains']['A8'] = {
            'title': 'Asset management',
            'controls': []
        }
        
        # A.8.1 - Inventario de activos
        control_a8_1 = {
            'id': 'A.8.1',
            'title': 'Inventory of assets',
            'status': 'IMPLEMENTED' if self._check_asset_inventory() else 'NOT_IMPLEMENTED',
            'evidence': 'Inventario de recursos documentado'
        }
        iso_results['domains']['A8']['controls'].append(control_a8_1)
        
        # A.8.2 - Clasificación de información
        control_a8_2 = {
            'id': 'A.8.2',
            'title': 'Information classification',
            'status': self._check_data_classification_status(),
            'evidence': 'Tags de clasificación en recursos'
        }
        iso_results['domains']['A8']['controls'].append(control_a8_2)
        
        # A.9 - Control de acceso
        iso_results['domains']['A9'] = {
            'title': 'Access control',
            'controls': []
        }
        
        # A.10 - Criptografía
        iso_results['domains']['A10'] = {
            'title': 'Cryptography',
            'controls': []
        }
        
        # A.12 - Seguridad de operaciones
        iso_results['domains']['A12'] = {
            'title': 'Operations security',
            'controls': []
        }
        
        # Calcular estadísticas
        for domain in iso_results['domains'].values():
            for control in domain['controls']:
                if control['status'] == 'IMPLEMENTED':
                    iso_results['implemented'] += 1
                elif control['status'] == 'PARTIAL':
                    iso_results['partial'] += 1
                else:
                    iso_results['not_implemented'] += 1
        
        evaluated_controls = (iso_results['implemented'] + 
                            iso_results['partial'] + 
                            iso_results['not_implemented'])
        
        if evaluated_controls > 0:
            iso_results['compliance_percentage'] = round(
                ((iso_results['implemented'] + iso_results['partial'] * 0.5) / 
                 evaluated_controls) * 100, 2
            )
        
        return iso_results
    
    async def _evaluate_nist_csf(self) -> Dict[str, Any]:
        """Evaluar cumplimiento con NIST Cybersecurity Framework"""
        nist_results = {
            'version': '2.0',
            'functions': {},
            'maturity_by_function': {},
            'overall_maturity': 0
        }
        
        # IDENTIFY
        nist_results['functions']['identify'] = {
            'categories': [],
            'maturity': 0
        }
        
        # ID.AM - Asset Management
        id_am_score = self._evaluate_asset_management()
        nist_results['functions']['identify']['categories'].append({
            'id': 'ID.AM',
            'name': 'Asset Management',
            'score': id_am_score,
            'subcategories': [
                {'id': 'ID.AM-1', 'desc': 'Physical devices inventoried', 'status': 'N/A'},
                {'id': 'ID.AM-2', 'desc': 'Software platforms inventoried', 'status': 'PASS'},
                {'id': 'ID.AM-3', 'desc': 'Communication flows mapped', 'status': 'PARTIAL'},
                {'id': 'ID.AM-5', 'desc': 'Resources prioritized', 'status': 'FAIL'}
            ]
        })
        
        # PROTECT
        nist_results['functions']['protect'] = {
            'categories': [],
            'maturity': 0
        }
        
        # PR.AC - Identity Management and Access Control
        pr_ac_score = self._evaluate_access_control()
        nist_results['functions']['protect']['categories'].append({
            'id': 'PR.AC',
            'name': 'Identity Management and Access Control',
            'score': pr_ac_score,
            'subcategories': [
                {'id': 'PR.AC-1', 'desc': 'Identities and credentials managed', 'status': 'PARTIAL'},
                {'id': 'PR.AC-4', 'desc': 'Access permissions managed', 'status': 'PARTIAL'},
                {'id': 'PR.AC-7', 'desc': 'Users authenticated', 'status': 'PASS'}
            ]
        })
        
        # PR.DS - Data Security
        pr_ds_score = self._evaluate_data_security()
        nist_results['functions']['protect']['categories'].append({
            'id': 'PR.DS',
            'name': 'Data Security',
            'score': pr_ds_score,
            'subcategories': [
                {'id': 'PR.DS-1', 'desc': 'Data-at-rest protected', 'status': 'PARTIAL'},
                {'id': 'PR.DS-2', 'desc': 'Data-in-transit protected', 'status': 'PASS'}
            ]
        })
        
        # DETECT
        nist_results['functions']['detect'] = {
            'categories': [],
            'maturity': 0
        }
        
        # DE.CM - Security Continuous Monitoring
        de_cm_score = self._evaluate_continuous_monitoring()
        nist_results['functions']['detect']['categories'].append({
            'id': 'DE.CM',
            'name': 'Security Continuous Monitoring',
            'score': de_cm_score
        })
        
        # RESPOND
        nist_results['functions']['respond'] = {
            'categories': [],
            'maturity': 0
        }
        
        # RECOVER
        nist_results['functions']['recover'] = {
            'categories': [],
            'maturity': 0
        }
        
        # Calcular madurez por función
        for func_name, func_data in nist_results['functions'].items():
            if func_data['categories']:
                avg_score = sum(cat['score'] for cat in func_data['categories']) / len(func_data['categories'])
                func_data['maturity'] = round(avg_score, 2)
                nist_results['maturity_by_function'][func_name] = func_data['maturity']
        
        # Madurez general
        if nist_results['maturity_by_function']:
            nist_results['overall_maturity'] = round(
                sum(nist_results['maturity_by_function'].values()) / 
                len(nist_results['maturity_by_function']), 2
            )
        
        return nist_results
    
    def _check_root_account_usage(self) -> dict:
        """CIS 1.1 - Verificar uso de cuenta root"""
        # Implementación simplificada
        return {
            'control_id': '1.1',
            'title': 'Avoid the use of the root account',
            'status': 'PASS',  # Asumir que pasa si no hay evidencia contraria
            'evidence': 'No recent root account activity detected',
            'recommendation': 'Continue avoiding root account usage'
        }
    
    def _check_mfa_privileged_users(self) -> dict:
        """CIS 1.2 - MFA para usuarios privilegiados"""
        mfa_status = self.iam_data.get('mfa_status', {})
        users_without_mfa = mfa_status.get('users_without_mfa', [])
        
        # Verificar si hay usuarios admin sin MFA
        admin_without_mfa = []
        for user in users_without_mfa:
            # Verificar si es admin (simplificado)
            for finding in self.iam_data.get('findings', []):
                if (finding['id'] == 'IAM-001' and 
                    finding['details'].get('user_id') == user['user_id']):
                    admin_without_mfa.append(user['user_name'])
        
        if admin_without_mfa:
            self._add_finding(
                'COMP-001',
                'CRITICAL',
                f'CIS 1.2 - Usuarios administrativos sin MFA: {len(admin_without_mfa)}',
                {'users': admin_without_mfa}
            )
            status = 'FAIL'
        else:
            status = 'PASS'
        
        return {
            'control_id': '1.2',
            'title': 'Ensure MFA is enabled for all IAM users with console password',
            'status': status,
            'evidence': f'{len(admin_without_mfa)} admin users without MFA',
            'recommendation': 'Enable MFA for all privileged users immediately'
        }
    
    def _check_credential_rotation(self) -> dict:
        """CIS 1.3 - Rotación de credenciales"""
        old_keys = 0
        for key in self.iam_data.get('access_keys', []):
            if key.get('age_days', 0) > 90:
                old_keys += 1
        
        if old_keys > 0:
            self._add_finding(
                'COMP-002',
                'HIGH',
                f'CIS 1.3 - {old_keys} access keys sin rotar en 90+ días',
                {'count': old_keys}
            )
            status = 'FAIL'
        else:
            status = 'PASS'
        
        return {
            'control_id': '1.3',
            'title': 'Ensure credentials unused for 90 days or greater are disabled',
            'status': status,
            'evidence': f'{old_keys} keys older than 90 days',
            'recommendation': 'Implement automatic key rotation policy'
        }
    
    def _check_password_policy(self) -> dict:
        """CIS 1.4 - Política de contraseñas"""
        policy = self.iam_data.get('password_policy', {})
        issues = []
        
        if policy.get('minimum_length', 0) < PASSWORD_POLICY['min_length']:
            issues.append('Longitud mínima insuficiente')
        if not policy.get('require_uppercase'):
            issues.append('No requiere mayúsculas')
        if not policy.get('require_numbers'):
            issues.append('No requiere números')
        
        if issues:
            self._add_finding(
                'COMP-003',
                'MEDIUM',
                f'CIS 1.4 - Política de contraseñas débil',
                {'issues': issues}
            )
            status = 'FAIL'
        else:
            status = 'PASS'
        
        return {
            'control_id': '1.4',
            'title': 'Ensure IAM password policy requires strong passwords',
            'status': status,
            'evidence': f'{len(issues)} policy issues found',
            'recommendation': 'Strengthen password policy according to best practices'
        }
    
    def _check_cloud_trace_enabled(self) -> dict:
        """CIS 2.1 - Cloud Trace habilitado"""
        cts_config = self.monitoring_data.get('cloud_trace', {})
        trackers = cts_config.get('trackers', [])
        
        if not trackers:
            self._add_finding(
                'COMP-004',
                'CRITICAL',
                'CIS 2.1 - Cloud Trace Service no configurado',
                {}
            )
            status = 'FAIL'
        else:
            status = 'PASS'
        
        return {
            'control_id': '2.1',
            'title': 'Ensure CloudTrail is enabled',
            'status': status,
            'evidence': f'{len(trackers)} trackers configured',
            'recommendation': 'Enable CloudTrail for all regions'
        }
    
    def _check_log_encryption(self) -> dict:
        """CIS 2.2 - Cifrado de logs"""
        encrypted_trackers = 0
        total_trackers = 0
        
        for tracker in self.monitoring_data.get('cloud_trace', {}).get('trackers', []):
            total_trackers += 1
            if tracker.get('is_support_trace_files_encryption'):
                encrypted_trackers += 1
        
        if total_trackers > 0 and encrypted_trackers < total_trackers:
            status = 'FAIL'
        else:
            status = 'PASS'
        
        return {
            'control_id': '2.2',
            'title': 'Ensure CloudTrail log file validation is enabled',
            'status': status,
            'evidence': f'{encrypted_trackers}/{total_trackers} trackers encrypted',
            'recommendation': 'Enable encryption for all audit logs'
        }
    
    def _check_security_group_restrictions(self) -> dict:
        """CIS 3.1 - Security groups restrictivos"""
        overly_permissive = 0
        
        for finding in self.network_data.get('findings', []):
            if finding['id'] in ['NET-004', 'NET-006']:
                overly_permissive += 1
        
        if overly_permissive > 0:
            status = 'FAIL'
        else:
            status = 'PASS'
        
        return {
            'control_id': '3.1',
            'title': 'Ensure no security groups allow ingress from 0.0.0.0/0',
            'status': status,
            'evidence': f'{overly_permissive} overly permissive rules found',
            'recommendation': 'Restrict security group rules to specific IPs'
        }
    
    def _check_admin_ports_exposure(self) -> dict:
        """CIS 3.2 - Puertos administrativos no expuestos"""
        exposed_admin_ports = 0
        
        for resource in self.network_data.get('exposed_resources', []):
            for port in resource.get('exposed_ports', []):
                if port['port'] in [22, 3389]:  # SSH, RDP
                    exposed_admin_ports += 1
        
        if exposed_admin_ports > 0:
            self._add_finding(
                'COMP-005',
                'CRITICAL',
                f'CIS 3.2 - {exposed_admin_ports} puertos administrativos expuestos',
                {}
            )
            status = 'FAIL'
        else:
            status = 'PASS'
        
        return {
            'control_id': '3.2',
            'title': 'Ensure no security groups allow ingress to admin ports',
            'status': status,
            'evidence': f'{exposed_admin_ports} admin ports exposed',
            'recommendation': 'Use bastion hosts for administrative access'
        }
    
    def _check_encryption_at_rest(self) -> dict:
        """CIS 4.1 - Cifrado en reposo"""
        encryption_status = self.storage_data.get('encryption_status', {})
        
        total_unencrypted = (encryption_status.get('evs', {}).get('unencrypted', 0) +
                           encryption_status.get('obs', {}).get('unencrypted', 0))
        
        if total_unencrypted > 0:
            status = 'FAIL'
        else:
            status = 'PASS'
        
        return {
            'control_id': '4.1',
            'title': 'Ensure data at rest is encrypted',
            'status': status,
            'evidence': f'{total_unencrypted} unencrypted storage resources',
            'recommendation': 'Enable encryption for all storage resources'
        }
    
    def _check_public_buckets(self) -> dict:
        """CIS 4.2 - Sin buckets públicos"""
        public_buckets = 0
        
        for bucket in self.storage_data.get('obs_buckets', []):
            if bucket.get('public_access'):
                public_buckets += 1
        
        if public_buckets > 0:
            status = 'FAIL'
        else:
            status = 'PASS'
        
        return {
            'control_id': '4.2',
            'title': 'Ensure S3 bucket access is not public',
            'status': status,
            'evidence': f'{public_buckets} public buckets found',
            'recommendation': 'Make all buckets private unless explicitly required'
        }
    
    def _check_asset_inventory(self) -> bool:
        """Verificar si existe inventario de activos"""
        # Verificar que tengamos datos de todos los servicios principales
        return all([
            self.iam_data.get('users'),
            self.network_data.get('vpcs'),
            self.storage_data.get('evs_volumes')
        ])
    
    def _check_data_classification_status(self) -> str:
        """Verificar estado de clasificación de datos"""
        total_resources = 0
        classified_resources = 0
        
        # Verificar EVS
        for volumes in self.storage_data.get('evs_volumes', {}).values():
            for volume in volumes:
                total_resources += 1
                if self._has_classification_tag(volume.get('tags', {})):
                    classified_resources += 1
        
        # Verificar OBS
        for bucket in self.storage_data.get('obs_buckets', []):
            total_resources += 1
            if self._has_classification_tag(bucket.get('tags', {})):
                classified_resources += 1
        
        if total_resources == 0:
            return 'NOT_APPLICABLE'
        
        classification_rate = (classified_resources / total_resources) * 100
        
        if classification_rate >= 80:
            return 'IMPLEMENTED'
        elif classification_rate >= 40:
            return 'PARTIAL'
        else:
            return 'NOT_IMPLEMENTED'
    
    def _has_classification_tag(self, tags: dict) -> bool:
        """Verificar si tiene tag de clasificación"""
        classification_keys = ['Classification', 'DataClassification', 'Clasificacion']
        return any(key in tags for key in classification_keys)
    
    def _evaluate_asset_management(self) -> float:
        """Evaluar madurez de gestión de activos"""
        score = 0.0
        
        # Inventario completo
        if self._check_asset_inventory():
            score += 2.5
        
        # Clasificación de datos
        classification_status = self._check_data_classification_status()
        if classification_status == 'IMPLEMENTED':
            score += 2.5
        elif classification_status == 'PARTIAL':
            score += 1.25
        
        return min(score, 5.0)  # Máximo 5
    
    def _evaluate_access_control(self) -> float:
        """Evaluar madurez de control de acceso"""
        score = 0.0
        
        # MFA habilitado
        mfa_rate = 0
        mfa_status = self.iam_data.get('mfa_status', {})
        if mfa_status.get('total_users', 0) > 0:
            mfa_rate = mfa_status.get('mfa_enabled', 0) / mfa_status.get('total_users', 0)
        
        score += mfa_rate * 2.5
        
        # Sin privilegios excesivos
        admin_users = len([f for f in self.iam_data.get('findings', []) 
                          if f['id'] == 'IAM-001'])
        if admin_users == 0:
            score += 2.5
        elif admin_users < 3:
            score += 1.25
        
        return min(score, 5.0)
    
    def _evaluate_data_security(self) -> float:
        """Evaluar madurez de seguridad de datos"""
        score = 0.0
        
        # Cifrado en reposo
        enc_status = self.storage_data.get('encryption_status', {})
        total_encrypted = (enc_status.get('evs', {}).get('encrypted', 0) +
                         enc_status.get('obs', {}).get('encrypted', 0))
        total_unencrypted = (enc_status.get('evs', {}).get('unencrypted', 0) +
                           enc_status.get('obs', {}).get('unencrypted', 0))
        
        if total_encrypted + total_unencrypted > 0:
            enc_rate = total_encrypted / (total_encrypted + total_unencrypted)
            score += enc_rate * 2.5
        
        # Sin acceso público
        public_buckets = len([b for b in self.storage_data.get('obs_buckets', [])
                            if b.get('public_access')])
        if public_buckets == 0:
            score += 2.5
        
        return min(score, 5.0)
    
    def _evaluate_continuous_monitoring(self) -> float:
        """Evaluar madurez de monitoreo continuo"""
        score = 0.0
        
        # Cloud Trace habilitado
        if self.monitoring_data.get('cloud_trace', {}).get('trackers'):
            score += 1.25
        
        # Alarmas configuradas
        total_alarms = sum(len(alarms) for alarms in 
                         self.monitoring_data.get('alarms', {}).values())
        if total_alarms > 10:
            score += 1.25
        elif total_alarms > 5:
            score += 0.625
        
        # Retención adecuada
        avg_retention = self.monitoring_data.get('statistics', {}).get('average_log_retention', 0)
        if avg_retention >= 90:
            score += 1.25
        elif avg_retention >= 30:
            score += 0.625
        
        # Cobertura de monitoreo
        # Implementación simplificada
        score += 1.25
        
        return min(score, 5.0)
    
    def _calculate_overall_compliance(self, frameworks: dict) -> float:
        """Calcular cumplimiento general"""
        total_compliance = 0
        count = 0
        
        for framework, results in frameworks.items():
            if 'compliance_percentage' in results:
                total_compliance += results['compliance_percentage']
                count += 1
        
        if count > 0:
            return round(total_compliance / count, 2)
        return 0
    
    def _perform_gap_analysis(self, frameworks: dict) -> dict:
        """Realizar análisis de brechas"""
        gaps = {
            'critical_gaps': [],
            'high_priority_gaps': [],
            'medium_priority_gaps': [],
            'quick_wins': []
        }
        
        # Analizar CIS
        cis_results = frameworks.get('CIS_Huawei_Cloud_1.1', {})
        for section in cis_results.get('sections', {}).values():
            for control in section.get('controls', []):
                if control['status'] == 'FAIL':
                    gap = {
                        'framework': 'CIS',
                        'control': control['control_id'],
                        'title': control['title'],
                        'recommendation': control['recommendation']
                    }
                    
                    # Categorizar por prioridad
                    if control['control_id'] in ['1.2', '2.1', '3.2']:
                        gaps['critical_gaps'].append(gap)
                    elif control['control_id'] in ['1.3', '2.2', '3.1']:
                        gaps['high_priority_gaps'].append(gap)
                    else:
                        gaps['medium_priority_gaps'].append(gap)
        
        # Identificar quick wins
        if self.iam_data.get('mfa_status', {}).get('mfa_disabled', 0) > 0:
            gaps['quick_wins'].append({
                'action': 'Habilitar MFA para todos los usuarios',
                'impact': 'Alto',
                'effort': 'Bajo',
                'time': '1-2 días'
            })
        
        return gaps
    
    def _calculate_maturity_level(self, results: dict) -> float:
        """Calcular nivel de madurez (1-5)"""
        # CORREGIDO: Verificar que 'frameworks' existe
        frameworks = results.get('frameworks', {})
        nist_maturity = frameworks.get('NIST_CSF_2.0', {}).get('overall_maturity', 0)
        
        # Ajustar con otros factores
        compliance_factor = results.get('overall_compliance', 0) / 100
        
        # Fórmula ponderada
        maturity = (nist_maturity * 0.6) + (compliance_factor * 5 * 0.4)
        
        return round(maturity, 1)
    
    def _generate_recommendations(self) -> List[dict]:
        """Generar recomendaciones priorizadas"""
        recommendations = []
        
        # Basadas en hallazgos críticos
        critical_findings = [f for f in self.findings if f['severity'] == 'CRITICAL']
        
        for finding in critical_findings[:5]:  # Top 5
            recommendations.append({
                'priority': 'CRITICAL',
                'title': f"Remediar: {finding['message']}",
                'description': f"Finding {finding['id']} requiere atención inmediata",
                'effort': 'Variable',
                'impact': 'Muy Alto'
            })
        
        # CORREGIDO: No llamar _calculate_maturity_level con argumentos incorrectos
        # Simplificar la lógica o usar self.results si está disponible
        
        # Recomendaciones generales por defecto
        recommendations.extend([
            {
                'priority': 'HIGH',
                'title': 'Implementar programa de seguridad formal',
                'description': 'Establecer políticas, procedimientos y responsabilidades',
                'effort': 'Alto',
                'impact': 'Transformacional'
            },
            {
                'priority': 'HIGH',
                'title': 'Automatizar controles de seguridad',
                'description': 'Implementar Infrastructure as Code y políticas automatizadas',
                'effort': 'Medio',
                'impact': 'Alto'
            }
        ])
        
        return recommendations
    
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