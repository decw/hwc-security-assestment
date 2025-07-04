#!/usr/bin/env python3
"""
Analizador de riesgos para el Assessment de Seguridad
Calcula scores de riesgo, prioriza hallazgos y genera matrices de riesgo
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import numpy as np

from utils.logger import SecurityLogger
from config.constants import SEVERITY_MAPPING, CRITICAL_PORTS

class RiskLevel(Enum):
    """Niveles de riesgo"""
    CRITICAL = "CRÍTICO"
    HIGH = "ALTO"
    MEDIUM = "MEDIO"
    LOW = "BAJO"
    MINIMAL = "MÍNIMO"

class Impact(Enum):
    """Niveles de impacto"""
    CATASTROPHIC = 5
    MAJOR = 4
    MODERATE = 3
    MINOR = 2
    NEGLIGIBLE = 1

class Likelihood(Enum):
    """Niveles de probabilidad"""
    ALMOST_CERTAIN = 5
    LIKELY = 4
    POSSIBLE = 3
    UNLIKELY = 2
    RARE = 1

@dataclass
class Risk:
    """Clase para representar un riesgo"""
    id: str
    title: str
    description: str
    category: str
    impact: Impact
    likelihood: Likelihood
    severity: str
    affected_resources: List[str]
    mitigation: str
    residual_risk: float = 0.0
    
    @property
    def inherent_risk_score(self) -> int:
        """Calcular score de riesgo inherente"""
        return self.impact.value * self.likelihood.value
    
    @property
    def risk_level(self) -> RiskLevel:
        """Determinar nivel de riesgo basado en score"""
        score = self.inherent_risk_score
        if score >= 20:
            return RiskLevel.CRITICAL
        elif score >= 15:
            return RiskLevel.HIGH
        elif score >= 10:
            return RiskLevel.MEDIUM
        elif score >= 5:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

class RiskAnalyzer:
    """Analizador principal de riesgos"""
    
    def __init__(self):
        self.logger = SecurityLogger('RiskAnalyzer')
        self.risks = []
        self.risk_matrix = np.zeros((5, 5))  # 5x5 risk matrix
        
    def analyze_all_findings(self, assessment_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analizar todos los hallazgos y calcular riesgos"""
        self.logger.info("Iniciando análisis de riesgos")
        
        # Extraer hallazgos consolidados
        findings = assessment_results.get('consolidated_findings', [])
        
        # Convertir hallazgos a riesgos
        for finding in findings:
            risk = self._finding_to_risk(finding, assessment_results)
            if risk:
                self.risks.append(risk)
        
        # Calcular matriz de riesgo
        self._calculate_risk_matrix()
        
        # Análisis agregado
        risk_analysis = {
            'total_risks': len(self.risks),
            'risk_matrix': self.risk_matrix.tolist(),
            'risks_by_level': self._group_risks_by_level(),
            'risks_by_category': self._group_risks_by_category(),
            'top_risks': self._get_top_risks(10),
            'risk_score_distribution': self._calculate_risk_distribution(),
            'recommended_priorities': self._prioritize_risks(),
            'risk_treatment_plan': self._generate_treatment_plan(),
            'estimated_risk_reduction': self._estimate_risk_reduction(),
            'risk_appetite_analysis': self._analyze_risk_appetite(),
            'timestamp': datetime.now().isoformat()
        }
        
        self.logger.info(f"Análisis de riesgos completado. Total: {len(self.risks)}")
        return risk_analysis
    
    def _finding_to_risk(self, finding: Dict[str, Any], 
                        assessment_results: Dict[str, Any]) -> Risk:
        """Convertir un hallazgo en un objeto Risk"""
        # Mapear severidad a impacto y probabilidad
        severity = finding.get('severity', 'MEDIUM')
        impact, likelihood = self._severity_to_impact_likelihood(
            severity, finding, assessment_results
        )
        
        # Determinar categoría
        category = self._determine_risk_category(finding)
        
        # Recursos afectados
        affected_resources = self._extract_affected_resources(finding)
        
        # Generar mitigación sugerida
        mitigation = self._generate_mitigation(finding)
        
        return Risk(
            id=f"RISK-{finding.get('id', 'UNKNOWN')}",
            title=finding.get('message', 'Unknown Risk'),
            description=self._expand_description(finding),
            category=category,
            impact=impact,
            likelihood=likelihood,
            severity=severity,
            affected_resources=affected_resources,
            mitigation=mitigation
        )
    
    def _severity_to_impact_likelihood(self, severity: str, finding: Dict,
                                     assessment_results: Dict) -> Tuple[Impact, Likelihood]:
        """Mapear severidad a impacto y probabilidad"""
        # Impacto base según severidad
        impact_map = {
            'CRITICAL': Impact.CATASTROPHIC,
            'HIGH': Impact.MAJOR,
            'MEDIUM': Impact.MODERATE,
            'LOW': Impact.MINOR
        }
        impact = impact_map.get(severity, Impact.MODERATE)
        
        # Ajustar impacto basado en contexto
        if self._is_internet_exposed(finding):
            impact = Impact(min(impact.value + 1, 5))
        
        if self._affects_critical_data(finding, assessment_results):
            impact = Impact(min(impact.value + 1, 5))
        
        # Calcular probabilidad
        likelihood = self._calculate_likelihood(finding, assessment_results)
        
        return impact, likelihood
    
    def _calculate_likelihood(self, finding: Dict, 
                            assessment_results: Dict) -> Likelihood:
        """Calcular probabilidad de explotación"""
        base_likelihood = {
            'CRITICAL': Likelihood.LIKELY,
            'HIGH': Likelihood.POSSIBLE,
            'MEDIUM': Likelihood.POSSIBLE,
            'LOW': Likelihood.UNLIKELY
        }
        
        likelihood = base_likelihood.get(finding.get('severity'), Likelihood.POSSIBLE)
        
        # Factores que aumentan la probabilidad
        if self._is_internet_exposed(finding):
            likelihood = Likelihood(min(likelihood.value + 1, 5))
        
        if 'MFA' in finding.get('id', '') or 'mfa' in finding.get('message', '').lower():
            likelihood = Likelihood(min(likelihood.value + 1, 5))
        
        if self._is_common_attack_vector(finding):
            likelihood = Likelihood(min(likelihood.value + 1, 5))
        
        # Factores que disminuyen la probabilidad
        if self._has_compensating_controls(finding, assessment_results):
            likelihood = Likelihood(max(likelihood.value - 1, 1))
        
        return likelihood
    
    def _determine_risk_category(self, finding: Dict) -> str:
        """Determinar categoría del riesgo"""
        finding_id = finding.get('id', '')
        module = finding.get('module', '')
        
        if 'IAM' in finding_id or module == 'iam':
            return 'Gestión de Identidad y Acceso'
        elif 'NET' in finding_id or module == 'network':
            return 'Seguridad de Red'
        elif 'STO' in finding_id or module == 'storage':
            return 'Seguridad de Datos'
        elif 'MON' in finding_id or module == 'monitoring':
            return 'Monitoreo y Auditoría'
        elif 'BCM' in finding_id:
            return 'Continuidad del Negocio'
        elif 'COMP' in finding_id or module == 'compliance':
            return 'Cumplimiento Regulatorio'
        else:
            return 'Seguridad General'
    
    def _extract_affected_resources(self, finding: Dict) -> List[str]:
        """Extraer recursos afectados del hallazgo"""
        resources = []
        details = finding.get('details', {})
        
        # Buscar IDs de recursos comunes
        resource_keys = ['server_id', 'volume_id', 'bucket_name', 'vpc_id', 
                        'user_id', 'security_group', 'subnet_id']
        
        for key in resource_keys:
            if key in details:
                value = details[key]
                if isinstance(value, list):
                    resources.extend(value)
                else:
                    resources.append(str(value))
        
        # Si no hay recursos específicos, usar contador genérico
        if not resources:
            if 'count' in details:
                resources.append(f"{details['count']} recursos")
            else:
                resources.append("Múltiples recursos")
        
        return resources
    
    def _generate_mitigation(self, finding: Dict) -> str:
        """Generar estrategia de mitigación para el riesgo"""
        mitigations = {
            'IAM-001': "Implementar RBAC con principio de menor privilegio. Revisar y revocar permisos administrativos innecesarios.",
            'IAM-002': "Habilitar MFA obligatorio para todos los usuarios. Implementar políticas de acceso condicional.",
            'IAM-003': "Establecer rotación automática de access keys cada 90 días. Implementar monitoreo de uso.",
            'IAM-004': "Rotar inmediatamente las credenciales antiguas. Implementar proceso automatizado.",
            'NET-001': "Revisar y optimizar arquitectura de red. Implementar segmentación adecuada.",
            'NET-002': "Eliminar subnets públicas innecesarias. Usar NAT gateways para acceso saliente.",
            'NET-003': "Cerrar puertos administrativos. Implementar bastion hosts con MFA.",
            'NET-004': "Restringir reglas de security groups. Implementar principio de zero trust.",
            'STO-001': "Habilitar cifrado para todos los volúmenes. Usar KMS para gestión de claves.",
            'STO-004': "Hacer privados todos los buckets. Implementar políticas de acceso granulares.",
            'MON-001': "Expandir cobertura de monitoreo. Implementar alertas proactivas.",
            'MON-002': "Aumentar retención de logs según requisitos de compliance.",
            'BCM-001': "Implementar estrategia DR multi-región. Realizar pruebas periódicas.",
            'COMP-001': "Actualizar políticas para cumplir con frameworks. Implementar controles faltantes."
        }
        
        finding_id = finding.get('id', '')
        
        # Buscar mitigación específica
        for key, mitigation in mitigations.items():
            if key in finding_id:
                return mitigation
        
        # Mitigación genérica basada en severidad
        severity = finding.get('severity', 'MEDIUM')
        if severity == 'CRITICAL':
            return "Implementar remediación inmediata. Considerar solución temporal mientras se implementa fix permanente."
        elif severity == 'HIGH':
            return "Planificar remediación en sprint actual. Implementar controles compensatorios temporales."
        else:
            return "Incluir en backlog de seguridad. Evaluar en próxima revisión trimestral."
    
    def _expand_description(self, finding: Dict) -> str:
        """Expandir descripción del hallazgo con contexto adicional"""
        base_desc = finding.get('message', '')
        details = finding.get('details', {})
        
        # Agregar contexto cuantitativo
        if 'count' in details:
            base_desc += f" (Afecta a {details['count']} recursos)"
        
        if 'region' in details:
            base_desc += f" en región {details['region']}"
        
        # Agregar impacto potencial
        severity = finding.get('severity', 'MEDIUM')
        if severity == 'CRITICAL':
            base_desc += ". Esto representa un riesgo inmediato para la seguridad de la infraestructura."
        elif severity == 'HIGH':
            base_desc += ". Esto podría resultar en compromiso de datos o servicios."
        
        return base_desc
    
    def _is_internet_exposed(self, finding: Dict) -> bool:
        """Verificar si el hallazgo implica exposición a Internet"""
        indicators = ['0.0.0.0/0', 'exposed', 'public', 'internet', 'external']
        
        message = finding.get('message', '').lower()
        details_str = json.dumps(finding.get('details', {})).lower()
        
        return any(indicator in message or indicator in details_str 
                  for indicator in indicators)
    
    def _affects_critical_data(self, finding: Dict, assessment_results: Dict) -> bool:
        """Verificar si afecta datos críticos"""
        # Buscar indicadores de datos críticos
        critical_indicators = ['production', 'database', 'backup', 'customer', 
                             'payment', 'personal', 'sensitive']
        
        text_to_check = (finding.get('message', '') + 
                        json.dumps(finding.get('details', {}))).lower()
        
        return any(indicator in text_to_check for indicator in critical_indicators)
    
    def _is_common_attack_vector(self, finding: Dict) -> bool:
        """Verificar si es un vector de ataque común"""
        common_vectors = {
            'IAM-002': True,  # MFA no habilitado
            'NET-003': True,  # Puertos administrativos expuestos
            'NET-004': True,  # Puertos críticos expuestos
            'STO-004': True,  # Buckets públicos
        }
        
        return common_vectors.get(finding.get('id', ''), False)
    
    def _has_compensating_controls(self, finding: Dict, 
                                  assessment_results: Dict) -> bool:
        """Verificar si existen controles compensatorios"""
        # Ejemplo simplificado - en producción sería más sofisticado
        compensating_controls = {
            'NET-003': ['HSS', 'WAF'],  # Si hay HSS o WAF, reduce riesgo
            'STO-001': ['KMS'],  # Si hay KMS configurado
        }
        
        finding_id = finding.get('id', '')
        if finding_id in compensating_controls:
            # Verificar si los controles están presentes
            # Esto requeriría análisis más profundo de assessment_results
            return False  # Por ahora, asumir que no hay controles compensatorios
        
        return False
    
    def _calculate_risk_matrix(self):
        """Calcular matriz de riesgo 5x5"""
        self.risk_matrix = np.zeros((5, 5))
        
        for risk in self.risks:
            # Matriz usa índices 0-4, pero enums usan valores 1-5
            impact_idx = risk.impact.value - 1
            likelihood_idx = risk.likelihood.value - 1
            self.risk_matrix[likelihood_idx][impact_idx] += 1
    
    def _group_risks_by_level(self) -> Dict[str, List[Dict]]:
        """Agrupar riesgos por nivel"""
        grouped = {level.value: [] for level in RiskLevel}
        
        for risk in self.risks:
            risk_summary = {
                'id': risk.id,
                'title': risk.title,
                'score': risk.inherent_risk_score,
                'category': risk.category,
                'affected_resources': len(risk.affected_resources)
            }
            grouped[risk.risk_level.value].append(risk_summary)
        
        # Ordenar cada grupo por score
        for level in grouped:
            grouped[level].sort(key=lambda x: x['score'], reverse=True)
        
        return grouped
    
    def _group_risks_by_category(self) -> Dict[str, Dict]:
        """Agrupar riesgos por categoría"""
        grouped = {}
        
        for risk in self.risks:
            if risk.category not in grouped:
                grouped[risk.category] = {
                    'total': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'average_score': 0,
                    'risks': []
                }
            
            grouped[risk.category]['total'] += 1
            grouped[risk.category]['risks'].append(risk.id)
            
            # Contar por nivel
            level = risk.risk_level.value.lower()
            if level == 'crítico':
                grouped[risk.category]['critical'] += 1
            elif level == 'alto':
                grouped[risk.category]['high'] += 1
            elif level == 'medio':
                grouped[risk.category]['medium'] += 1
            elif level == 'bajo':
                grouped[risk.category]['low'] += 1
        
        # Calcular scores promedio
        for category in grouped:
            total = grouped[category]['total']
            total_score = sum(r.inherent_risk_score for r in self.risks 
                            if r.category == category)
            grouped[category]['average_score'] = round(total_score / total, 2) if total > 0 else 0
        
        return grouped
    
    def _get_top_risks(self, limit: int = 10) -> List[Dict]:
        """Obtener los principales riesgos"""
        sorted_risks = sorted(self.risks, 
                            key=lambda x: (x.inherent_risk_score, x.impact.value), 
                            reverse=True)
        
        top_risks = []
        for risk in sorted_risks[:limit]:
            top_risks.append({
                'id': risk.id,
                'title': risk.title,
                'description': risk.description,
                'category': risk.category,
                'risk_score': risk.inherent_risk_score,
                'risk_level': risk.risk_level.value,
                'impact': risk.impact.name,
                'likelihood': risk.likelihood.name,
                'affected_resources': risk.affected_resources,
                'mitigation': risk.mitigation
            })
        
        return top_risks
    
    def _calculate_risk_distribution(self) -> Dict[str, Any]:
        """Calcular distribución de scores de riesgo"""
        scores = [risk.inherent_risk_score for risk in self.risks]
        
        if not scores:
            return {}
        
        return {
            'min': min(scores),
            'max': max(scores),
            'mean': round(np.mean(scores), 2),
            'median': round(np.median(scores), 2),
            'std_dev': round(np.std(scores), 2),
            'percentiles': {
                '25': round(np.percentile(scores, 25), 2),
                '50': round(np.percentile(scores, 50), 2),
                '75': round(np.percentile(scores, 75), 2),
                '90': round(np.percentile(scores, 90), 2),
                '95': round(np.percentile(scores, 95), 2)
            }
        }
    
    def _prioritize_risks(self) -> List[Dict]:
        """Priorizar riesgos para tratamiento"""
        # Factores de priorización
        priorities = []
        
        for risk in self.risks:
            # Score base
            priority_score = risk.inherent_risk_score
            
            # Ajustes por factores adicionales
            if self._is_quick_win(risk):
                priority_score *= 1.5  # Boost para quick wins
            
            if risk.category == 'Gestión de Identidad y Acceso':
                priority_score *= 1.2  # IAM es crítico
            
            if len(risk.affected_resources) > 10:
                priority_score *= 1.1  # Impacto amplio
            
            priorities.append({
                'risk_id': risk.id,
                'title': risk.title,
                'priority_score': round(priority_score, 2),
                'is_quick_win': self._is_quick_win(risk),
                'estimated_effort': self._estimate_effort(risk),
                'recommended_timeline': self._recommend_timeline(risk)
            })
        
        # Ordenar por priority_score
        priorities.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return priorities[:20]  # Top 20
    
    def _is_quick_win(self, risk: Risk) -> bool:
        """Determinar si es un quick win"""
        quick_win_ids = ['IAM-002', 'MON-002', 'NET-003', 'IAM-004']
        
        # Verificar si el ID base está en quick wins
        base_id = risk.id.replace('RISK-', '')
        return any(qw in base_id for qw in quick_win_ids)
    
    def _estimate_effort(self, risk: Risk) -> str:
        """Estimar esfuerzo de remediación"""
        effort_map = {
            'IAM-002': 'Bajo (2-3 días)',
            'MON-002': 'Bajo (1 día)',
            'NET-003': 'Bajo (1-2 días)',
            'IAM-001': 'Medio (5-10 días)',
            'NET-001': 'Alto (10-15 días)',
            'BCM-001': 'Muy Alto (20-30 días)'
        }
        
        base_id = risk.id.replace('RISK-', '')
        for key, effort in effort_map.items():
            if key in base_id:
                return effort
        
        # Estimación por defecto basada en score
        if risk.inherent_risk_score >= 20:
            return 'Alto (10-20 días)'
        elif risk.inherent_risk_score >= 15:
            return 'Medio (5-10 días)'
        else:
            return 'Bajo (1-5 días)'
    
    def _recommend_timeline(self, risk: Risk) -> str:
        """Recomendar timeline para remediación"""
        if risk.risk_level == RiskLevel.CRITICAL:
            return 'Inmediato (0-7 días)'
        elif risk.risk_level == RiskLevel.HIGH:
            return 'Corto plazo (7-30 días)'
        elif risk.risk_level == RiskLevel.MEDIUM:
            return 'Medio plazo (30-60 días)'
        else:
            return 'Largo plazo (60-90 días)'
    
    def _generate_treatment_plan(self) -> Dict[str, List]:
        """Generar plan de tratamiento de riesgos"""
        treatment_plan = {
            'accept': [],
            'mitigate': [],
            'transfer': [],
            'avoid': []
        }
        
        for risk in self.risks:
            treatment = self._determine_treatment_strategy(risk)
            
            risk_treatment = {
                'risk_id': risk.id,
                'title': risk.title,
                'strategy': treatment,
                'rationale': self._get_treatment_rationale(risk, treatment),
                'actions': self._get_treatment_actions(risk, treatment)
            }
            
            treatment_plan[treatment].append(risk_treatment)
        
        return treatment_plan
    
    def _determine_treatment_strategy(self, risk: Risk) -> str:
        """Determinar estrategia de tratamiento para el riesgo"""
        score = risk.inherent_risk_score
        
        # Reglas de decisión
        if score >= 20:
            return 'mitigate'  # Crítico - siempre mitigar
        elif score >= 15:
            if risk.category == 'Cumplimiento Regulatorio':
                return 'mitigate'  # Compliance siempre se mitiga
            else:
                return 'mitigate'
        elif score >= 10:
            if self._is_cost_effective_to_mitigate(risk):
                return 'mitigate'
            else:
                return 'accept'
        else:
            return 'accept'  # Riesgos bajos generalmente se aceptan
    
    def _get_treatment_rationale(self, risk: Risk, strategy: str) -> str:
        """Obtener justificación para la estrategia de tratamiento"""
        rationales = {
            'accept': f"Riesgo dentro del apetito organizacional. Score {risk.inherent_risk_score} es manejable con controles actuales.",
            'mitigate': f"Riesgo excede el apetito organizacional. Requiere reducción de score actual {risk.inherent_risk_score}.",
            'transfer': f"Riesgo puede ser transferido mediante seguros o tercerización.",
            'avoid': f"Actividad que genera el riesgo debe ser eliminada."
        }
        
        return rationales.get(strategy, "Estrategia determinada por análisis costo-beneficio.")
    
    def _get_treatment_actions(self, risk: Risk, strategy: str) -> List[str]:
        """Obtener acciones específicas para el tratamiento"""
        if strategy == 'mitigate':
            return [
                risk.mitigation,
                "Implementar monitoreo continuo",
                "Validar efectividad post-implementación"
            ]
        elif strategy == 'accept':
            return [
                "Documentar aceptación del riesgo",
                "Revisar trimestralmente",
                "Monitorear cambios en el contexto"
            ]
        elif strategy == 'transfer':
            return [
                "Evaluar opciones de seguro cibernético",
                "Considerar servicios gestionados",
                "Revisar SLAs con proveedores"
            ]
        else:
            return ["Evaluar alternativas para eliminar la actividad"]
    
    def _is_cost_effective_to_mitigate(self, risk: Risk) -> bool:
        """Evaluar si es costo-efectivo mitigar el riesgo"""
        # Simplificado - en producción incluiría análisis de costos real
        if self._is_quick_win(risk):
            return True
        
        if risk.inherent_risk_score >= 12:
            return True
        
        return False
    
    def _estimate_risk_reduction(self) -> Dict[str, Any]:
        """Estimar reducción de riesgo post-tratamiento"""
        current_total_score = sum(r.inherent_risk_score for r in self.risks)
        
        # Estimar scores residuales
        residual_scores = []
        for risk in self.risks:
            treatment = self._determine_treatment_strategy(risk)
            
            if treatment == 'mitigate':
                # Asumir 60-80% de reducción
                residual = risk.inherent_risk_score * 0.3
            elif treatment == 'transfer':
                # Asumir 50% de reducción
                residual = risk.inherent_risk_score * 0.5
            elif treatment == 'avoid':
                # Eliminar completamente
                residual = 0
            else:  # accept
                residual = risk.inherent_risk_score
            
            residual_scores.append(residual)
        
        residual_total_score = sum(residual_scores)
        reduction_percentage = ((current_total_score - residual_total_score) / 
                              current_total_score * 100) if current_total_score > 0 else 0
        
        return {
            'current_total_risk_score': round(current_total_score, 2),
            'projected_residual_score': round(residual_total_score, 2),
            'risk_reduction_percentage': round(reduction_percentage, 2),
            'risks_mitigated': len([r for r in self.risks 
                                   if self._determine_treatment_strategy(r) == 'mitigate']),
            'risks_accepted': len([r for r in self.risks 
                                 if self._determine_treatment_strategy(r) == 'accept']),
            'implementation_cost_estimate': self._estimate_total_cost(),
            'roi_estimate': self._calculate_risk_roi(reduction_percentage)
        }
    
    def _estimate_total_cost(self) -> str:
        """Estimar costo total de implementación"""
        # Simplificado - basado en número de riesgos a mitigar
        mitigated_risks = [r for r in self.risks 
                          if self._determine_treatment_strategy(r) == 'mitigate']
        
        # Estimar horas por tipo de riesgo
        total_hours = 0
        for risk in mitigated_risks:
            effort = self._estimate_effort(risk)
            if 'Bajo' in effort:
                total_hours += 24  # 3 días promedio
            elif 'Medio' in effort:
                total_hours += 60  # 7.5 días promedio
            else:
                total_hours += 120  # 15 días promedio
        
        # Calcular costo (asumiendo $100/hora)
        total_cost = total_hours * 100
        
        return f"${total_cost:,} USD ({total_hours} horas)"
    
    def _calculate_risk_roi(self, reduction_percentage: float) -> str:
        """Calcular ROI estimado de la reducción de riesgo"""
        # Fórmula simplificada de ROI de seguridad
        # ROI = (ALE_reducción - Costo_controles) / Costo_controles * 100
        
        # Asumir pérdida anual esperada (ALE) basada en industria
        estimated_ale = 250000  # $250k pérdida potencial anual
        ale_reduction = estimated_ale * (reduction_percentage / 100)
        
        # Costo estimado de controles (del método anterior)
        control_cost = 50000  # Estimación base
        
        if ale_reduction > control_cost:
            roi = ((ale_reduction - control_cost) / control_cost) * 100
            return f"{roi:.0f}% en 12 meses"
        else:
            return "ROI positivo en 18-24 meses"
    
    def _analyze_risk_appetite(self) -> Dict[str, Any]:
        """Analizar apetito de riesgo organizacional"""
        # Definir umbrales de apetito de riesgo típicos
        risk_appetite = {
            'current_posture': self._determine_risk_posture(),
            'recommended_posture': 'Moderado',
            'risks_exceeding_appetite': [],
            'appetite_thresholds': {
                'Gestión de Identidad y Acceso': 10,  # Bajo apetito
                'Seguridad de Datos': 10,  # Bajo apetito
                'Seguridad de Red': 15,  # Moderado
                'Monitoreo y Auditoría': 15,  # Moderado
                'Continuidad del Negocio': 12,  # Bajo-Moderado
                'Cumplimiento Regulatorio': 8   # Muy bajo apetito
            }
        }
        
        # Identificar riesgos que exceden el apetito
        for risk in self.risks:
            threshold = risk_appetite['appetite_thresholds'].get(risk.category, 15)
            if risk.inherent_risk_score > threshold:
                risk_appetite['risks_exceeding_appetite'].append({
                    'risk_id': risk.id,
                    'title': risk.title,
                    'category': risk.category,
                    'score': risk.inherent_risk_score,
                    'threshold': threshold,
                    'excess': risk.inherent_risk_score - threshold
                })
        
        # Ordenar por exceso
        risk_appetite['risks_exceeding_appetite'].sort(
            key=lambda x: x['excess'], reverse=True
        )
        
        return risk_appetite
    
    def _determine_risk_posture(self) -> str:
        """Determinar postura actual de riesgo"""
        avg_score = np.mean([r.inherent_risk_score for r in self.risks]) if self.risks else 0
        
        if avg_score < 8:
            return "Conservador"
        elif avg_score < 12:
            return "Moderado"
        elif avg_score < 16:
            return "Agresivo"
        else:
            return "Muy Agresivo"
    
    def generate_risk_report(self) -> Dict[str, Any]:
        """Generar reporte ejecutivo de riesgos"""
        return {
            'executive_summary': {
                'total_risks_identified': len(self.risks),
                'critical_risks': len([r for r in self.risks if r.risk_level == RiskLevel.CRITICAL]),
                'high_risks': len([r for r in self.risks if r.risk_level == RiskLevel.HIGH]),
                'average_risk_score': round(np.mean([r.inherent_risk_score for r in self.risks]), 2) if self.risks else 0,
                'highest_risk_category': self._get_highest_risk_category(),
                'recommended_immediate_actions': self._get_immediate_actions()
            },
            'risk_trends': self._analyze_risk_trends(),
            'risk_correlations': self._analyze_risk_correlations(),
            'scenario_analysis': self._perform_scenario_analysis()
        }
    
    def _get_highest_risk_category(self) -> str:
        """Obtener categoría con mayor riesgo promedio"""
        category_scores = {}
        
        for risk in self.risks:
            if risk.category not in category_scores:
                category_scores[risk.category] = []
            category_scores[risk.category].append(risk.inherent_risk_score)
        
        # Calcular promedios
        category_avgs = {
            cat: np.mean(scores) 
            for cat, scores in category_scores.items()
        }
        
        if category_avgs:
            return max(category_avgs.items(), key=lambda x: x[1])[0]
        return "No determinado"
    
    def _get_immediate_actions(self) -> List[str]:
        """Obtener acciones inmediatas recomendadas"""
        actions = []
        
        # Top 3 riesgos críticos
        critical_risks = [r for r in self.risks if r.risk_level == RiskLevel.CRITICAL]
        for risk in critical_risks[:3]:
            actions.append(f"{risk.title}: {risk.mitigation.split('.')[0]}")
        
        return actions
    
    def _analyze_risk_trends(self) -> Dict[str, Any]:
        """Analizar tendencias de riesgo"""
        # En un escenario real, compararía con assessments anteriores
        return {
            'trend_direction': 'Primera evaluación',
            'areas_of_concern': self._identify_areas_of_concern(),
            'positive_indicators': self._identify_positive_indicators()
        }
    
    def _identify_areas_of_concern(self) -> List[str]:
        """Identificar áreas de preocupación"""
        concerns = []
        
        # Categorías con múltiples riesgos altos
        category_high_risks = {}
        for risk in self.risks:
            if risk.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                if risk.category not in category_high_risks:
                    category_high_risks[risk.category] = 0
                category_high_risks[risk.category] += 1
        
        for category, count in category_high_risks.items():
            if count >= 3:
                concerns.append(f"{category}: {count} riesgos altos/críticos")
        
        # Exposición a Internet
        internet_exposed = len([r for r in self.risks 
                              if any('internet' in str(r.affected_resources).lower() 
                                    for _ in [1])])
        if internet_exposed > 5:
            concerns.append(f"Alta exposición a Internet: {internet_exposed} riesgos")
        
        return concerns
    
    def _identify_positive_indicators(self) -> List[str]:
        """Identificar indicadores positivos"""
        positives = []
        
        # Riesgos bajos
        low_risks = len([r for r in self.risks if r.risk_level == RiskLevel.LOW])
        if low_risks > 0:
            positives.append(f"{low_risks} riesgos identificados son de nivel bajo")
        
        # Quick wins disponibles
        quick_wins = len([r for r in self.risks if self._is_quick_win(r)])
        if quick_wins > 0:
            positives.append(f"{quick_wins} quick wins identificados para mejora rápida")
        
        return positives
    
    def _analyze_risk_correlations(self) -> Dict[str, List[str]]:
        """Analizar correlaciones entre riesgos"""
        correlations = {
            'authentication_chain': [],
            'data_exposure_chain': [],
            'compliance_chain': []
        }
        
        # Cadena de autenticación
        auth_risks = ['IAM-001', 'IAM-002', 'IAM-003', 'IAM-004']
        for risk in self.risks:
            if any(auth_id in risk.id for auth_id in auth_risks):
                correlations['authentication_chain'].append(risk.title)
        
        # Cadena de exposición de datos
        data_risks = ['STO-001', 'STO-004', 'NET-003', 'NET-004']
        for risk in self.risks:
            if any(data_id in risk.id for data_id in data_risks):
                correlations['data_exposure_chain'].append(risk.title)
        
        # Cadena de cumplimiento
        compliance_risks = ['MON-002', 'COMP-001', 'BCM-001']
        for risk in self.risks:
            if any(comp_id in risk.id for comp_id in compliance_risks):
                correlations['compliance_chain'].append(risk.title)
        
        return correlations
    
    def _perform_scenario_analysis(self) -> Dict[str, Dict]:
        """Realizar análisis de escenarios"""
        scenarios = {
            'worst_case': self._analyze_worst_case_scenario(),
            'most_likely': self._analyze_most_likely_scenario(),
            'best_case': self._analyze_best_case_scenario()
        }
        
        return scenarios
    
    def _analyze_worst_case_scenario(self) -> Dict:
        """Analizar escenario del peor caso"""
        # Asumir que todos los riesgos altos/críticos se materializan
        critical_high_risks = [r for r in self.risks 
                             if r.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
        
        total_impact = sum(r.inherent_risk_score for r in critical_high_risks)
        
        return {
            'description': "Materialización de todos los riesgos críticos y altos",
            'probability': "Baja (5-10%)",
            'potential_impact': f"Score total: {total_impact}",
            'estimated_loss': "$500,000 - $1,000,000",
            'business_disruption': "Severa - Posible pérdida de operación 24-72 horas",
            'reputation_impact': "Alto - Pérdida de confianza de clientes",
            'regulatory_impact': "Multas y sanciones probables"
        }
    
    def _analyze_most_likely_scenario(self) -> Dict:
        """Analizar escenario más probable"""
        # Asumir materialización de algunos riesgos medios y altos
        likely_risks = [r for r in self.risks 
                       if r.likelihood in [Likelihood.LIKELY, Likelihood.POSSIBLE]]
        
        total_impact = sum(r.inherent_risk_score for r in likely_risks[:5])  # Top 5
        
        return {
            'description': "Materialización de riesgos con alta probabilidad",
            'probability': "Media-Alta (40-60%)",
            'potential_impact': f"Score total: {total_impact}",
            'estimated_loss': "$100,000 - $250,000",
            'business_disruption': "Moderada - Degradación de servicios",
            'reputation_impact': "Medio - Impacto contenible",
            'regulatory_impact': "Posibles observaciones de auditoría"
        }
    
    def _analyze_best_case_scenario(self) -> Dict:
        """Analizar escenario del mejor caso"""
        # Asumir implementación exitosa de mitigaciones
        return {
            'description': "Implementación exitosa de todas las mitigaciones",
            'probability': "Media (30-40%) con inversión adecuada",
            'potential_impact': "Mínimo - Solo riesgos residuales bajos",
            'estimated_loss': "<$50,000",
            'business_disruption': "Mínima - Incidentes menores aislados",
            'reputation_impact': "Positivo - Mejora de imagen de seguridad",
            'regulatory_impact': "Cumplimiento demostrado"
        }


def calculate_cvss_score(finding: Dict) -> float:
    """Calcular score CVSS aproximado basado en características del hallazgo"""
    # Implementación simplificada de CVSS v3.1
    base_score = 5.0
    
    # Ajustar por severidad
    severity_scores = {
        'CRITICAL': 9.0,
        'HIGH': 7.5,
        'MEDIUM': 5.0,
        'LOW': 3.0
    }
    
    base_score = severity_scores.get(finding.get('severity', 'MEDIUM'), 5.0)
    
    # Ajustes adicionales
    if 'internet' in str(finding).lower() or '0.0.0.0/0' in str(finding):
        base_score = min(base_score + 1.5, 10.0)
    
    if 'admin' in str(finding).lower() or 'root' in str(finding).lower():
        base_score = min(base_score + 1.0, 10.0)
    
    if 'no authentication' in str(finding).lower() or 'sin mfa' in str(finding).lower():
        base_score = min(base_score + 0.5, 10.0)
    
    return round(base_score, 1)