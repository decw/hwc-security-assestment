#!/usr/bin/env python3
"""
Script principal para ejecutar el Assessment de Seguridad de Huawei Cloud
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

# Verificar dependencias antes de importar
try:
    from huaweicloudsdkcore.auth.credentials import BasicCredentials
except ImportError:
    print("ERROR: Huawei Cloud SDK no está instalado.")
    print("Por favor ejecute: pip install huaweicloudsdkcore")
    sys.exit(1)

# Importar colectores con manejo de errores
try:
    from collectors.iam_collector import IAMCollector
except ImportError as e:
    print(f"WARNING: No se pudo importar IAMCollector: {e}")
    IAMCollector = None

try:
    from collectors.network_collector import NetworkCollector
except ImportError as e:
    print(f"WARNING: No se pudo importar NetworkCollector: {e}")
    NetworkCollector = None

try:
    from collectors.storage_collector import StorageCollector
except ImportError as e:
    print(f"WARNING: No se pudo importar StorageCollector: {e}")
    StorageCollector = None

try:
    from collectors.monitoring_collector import MonitoringCollector
except ImportError as e:
    print(f"WARNING: No se pudo importar MonitoringCollector: {e}")
    MonitoringCollector = None

try:
    from collectors.compliance_collector import ComplianceCollector
except ImportError as e:
    print(f"WARNING: No se pudo importar ComplianceCollector: {e}")
    ComplianceCollector = None

# Importar utilidades
from utils.logger import SecurityLogger

try:
    from utils.report_generator import ReportGenerator
except ImportError as e:
    print(f"WARNING: No se pudo importar ReportGenerator: {e}")
    ReportGenerator = None

from config.settings import OUTPUT_DIR, REPORT_TIMESTAMP, CLIENT_NAME

class SecurityAssessment:
    """Orquestador principal del assessment de seguridad"""
    
    def __init__(self):
        self.logger = SecurityLogger('SecurityAssessment')
        self.results = {
            'client': CLIENT_NAME,
            'assessment_date': datetime.now().isoformat(),
            'version': '1.0',
            'modules': {}
        }
        
    async def run_assessment(self):
        """Ejecutar assessment completo"""
        self.logger.info(f"=== Iniciando Security Assessment para {CLIENT_NAME} ===")
        
        try:
            # Fase 1: Recolección de datos
            self.logger.info("FASE 1: Recolección de datos")
            
            # IAM
            if IAMCollector:
                self.logger.info("Recolectando datos IAM...")
                iam_collector = IAMCollector()
                self.results['modules']['iam'] = await iam_collector.collect_all()
                self._save_intermediate_results('iam')
            else:
                self.logger.warning("IAMCollector no disponible - saltando módulo IAM")
            
            # Network
            if NetworkCollector:
                self.logger.info("Recolectando datos de red...")
                network_collector = NetworkCollector()
                self.results['modules']['network'] = await network_collector.collect_all()
                self._save_intermediate_results('network')
            else:
                self.logger.warning("NetworkCollector no disponible - saltando módulo Network")
            
            # Storage
            if StorageCollector:
                self.logger.info("Recolectando datos de almacenamiento...")
                storage_collector = StorageCollector()
                self.results['modules']['storage'] = await storage_collector.collect_all()
                self._save_intermediate_results('storage')
            else:
                self.logger.warning("StorageCollector no disponible - saltando módulo Storage")
            
            # Monitoring
            if MonitoringCollector:
                self.logger.info("Recolectando datos de monitoreo...")
                monitoring_collector = MonitoringCollector()
                self.results['modules']['monitoring'] = await monitoring_collector.collect_all()
                self._save_intermediate_results('monitoring')
            else:
                self.logger.warning("MonitoringCollector no disponible - saltando módulo Monitoring")
            
            # Fase 2: Análisis de Compliance
            self.logger.info("FASE 2: Análisis de Compliance")
            if ComplianceCollector and len(self.results['modules']) > 0:
                compliance_collector = ComplianceCollector(
                    self.results['modules'].get('iam', {}),
                    self.results['modules'].get('network', {}),
                    self.results['modules'].get('storage', {}),
                    self.results['modules'].get('monitoring', {})
                )
                self.results['modules']['compliance'] = await compliance_collector.collect_all()
                self._save_intermediate_results('compliance')
            else:
                self.logger.warning("ComplianceCollector no disponible o sin datos para analizar")
            
            # Fase 3: Consolidación y Análisis
            self.logger.info("FASE 3: Consolidación de resultados")
            self._consolidate_findings()
            self._calculate_risk_scores()
            self._generate_executive_summary()
            
            # Guardar resultados finales
            self._save_final_results()
            
            # Fase 4: Generación de reportes
            self.logger.info("FASE 4: Generación de reportes")
            if ReportGenerator:
                report_gen = ReportGenerator(self.results)
                
                # Generar diferentes formatos de reporte
                report_gen.generate_technical_report()
                report_gen.generate_executive_report()
                report_gen.generate_findings_csv()
                report_gen.generate_remediation_plan()
            else:
                self.logger.warning("ReportGenerator no disponible - guardando solo JSON")
                
            self.logger.info("=== Assessment completado exitosamente ===")
            
            # Mostrar resumen
            self._print_summary()
            
        except Exception as e:
            self.logger.error(f"Error durante el assessment: {str(e)}")
            self.logger.error(f"Tipo de error: {type(e).__name__}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    
    def _save_intermediate_results(self, module_name: str):
        """Guardar resultados intermedios para cada módulo"""
        output_file = OUTPUT_DIR / f"{module_name}_results_{REPORT_TIMESTAMP}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results['modules'][module_name], f, indent=2, ensure_ascii=False)
        self.logger.info(f"Resultados de {module_name} guardados en {output_file}")
    
    def _consolidate_findings(self):
        """Consolidar todos los hallazgos en una lista única"""
        all_findings = []
        
        for module_name, module_data in self.results['modules'].items():
            if 'findings' in module_data:
                for finding in module_data['findings']:
                    finding['module'] = module_name
                    all_findings.append(finding)
        
        # Ordenar por severidad y timestamp
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        all_findings.sort(key=lambda x: (severity_order.get(x['severity'], 99), x['timestamp']))
        
        self.results['consolidated_findings'] = all_findings
        self.results['findings_summary'] = {
            'total': len(all_findings),
            'by_severity': {
                'CRITICAL': len([f for f in all_findings if f['severity'] == 'CRITICAL']),
                'HIGH': len([f for f in all_findings if f['severity'] == 'HIGH']),
                'MEDIUM': len([f for f in all_findings if f['severity'] == 'MEDIUM']),
                'LOW': len([f for f in all_findings if f['severity'] == 'LOW'])
            },
            'by_module': {}
        }
        
        # Contar por módulo
        for module in self.results['modules'].keys():
            self.results['findings_summary']['by_module'][module] = len(
                [f for f in all_findings if f.get('module') == module]
            )
    
    def _calculate_risk_scores(self):
        """Calcular scores de riesgo agregados"""
        risk_weights = {
            'CRITICAL': 10,
            'HIGH': 5,
            'MEDIUM': 2,
            'LOW': 1
        }
        
        total_risk_score = 0
        for finding in self.results.get('consolidated_findings', []):
            total_risk_score += risk_weights.get(finding['severity'], 0)
        
        # Normalizar score (0-100)
        max_possible_score = len(self.results.get('consolidated_findings', [])) * 10
        if max_possible_score > 0:
            normalized_score = 100 - ((total_risk_score / max_possible_score) * 100)
        else:
            normalized_score = 100
        
        self.results['risk_analysis'] = {
            'total_risk_score': total_risk_score,
            'normalized_security_score': round(normalized_score, 2),
            'risk_level': self._get_risk_level(normalized_score),
            'maturity_level': self.results['modules'].get('compliance', {}).get('maturity_level', 0)
        }
    
    def _get_risk_level(self, score: float) -> str:
        """Determinar nivel de riesgo basado en score"""
        if score >= 90:
            return 'BAJO'
        elif score >= 70:
            return 'MEDIO'
        elif score >= 50:
            return 'ALTO'
        else:
            return 'CRÍTICO'
    
    def _generate_executive_summary(self):
        """Generar resumen ejecutivo"""
        summary = self.results['findings_summary']
        
        self.results['executive_summary'] = {
            'assessment_scope': {
                'total_resources_analyzed': self._count_total_resources(),
                'regions_covered': len(set(
                    region for module in self.results['modules'].values()
                    for region in module.get('regions', [])
                )),
                'services_evaluated': len(self.results['modules'])
            },
            'key_findings': {
                'critical_issues': summary['by_severity']['CRITICAL'],
                'high_priority_issues': summary['by_severity']['HIGH'],
                'total_findings': summary['total']
            },
            'compliance_status': {
                'overall_compliance': self.results['modules'].get('compliance', {}).get('overall_compliance', 0),
                'maturity_level': self.results['modules'].get('compliance', {}).get('maturity_level', 0),
                'target_maturity': 3.0
            },
            'top_risks': self._get_top_risks(5),
            'immediate_actions_required': self._get_immediate_actions()
        }
    
    def _count_total_resources(self) -> int:
        """Contar total de recursos analizados"""
        count = 0
        
        # IAM
        iam = self.results['modules'].get('iam', {})
        count += len(iam.get('users', []))
        count += len(iam.get('groups', []))
        count += len(iam.get('policies', []))
        
        # Network
        network = self.results['modules'].get('network', {})
        for region_data in network.get('vpcs', {}).values():
            count += len(region_data)
        for region_data in network.get('security_groups', {}).values():
            count += len(region_data)
        
        # Storage
        storage = self.results['modules'].get('storage', {})
        for region_data in storage.get('evs_volumes', {}).values():
            count += len(region_data)
        count += len(storage.get('obs_buckets', []))
        
        return count
    
    def _get_top_risks(self, limit: int) -> list:
        """Obtener los principales riesgos"""
        critical_findings = [
            f for f in self.results.get('consolidated_findings', [])
            if f['severity'] in ['CRITICAL', 'HIGH']
        ]
        
        return [{
            'finding_id': f['id'],
            'severity': f['severity'],
            'message': f['message'],
            'module': f.get('module', 'unknown')
        } for f in critical_findings[:limit]]
    
    def _get_immediate_actions(self) -> list:
        """Obtener acciones inmediatas requeridas"""
        actions = []
        
        # Basado en hallazgos críticos
        for finding in self.results.get('consolidated_findings', []):
            if finding['severity'] == 'CRITICAL':
                if 'IAM-001' in finding['id']:
                    actions.append('Eliminar permisos administrativos excesivos')
                elif 'IAM-002' in finding['id']:
                    actions.append('Habilitar MFA para todos los usuarios privilegiados')
                elif 'NET-003' in finding['id']:
                    actions.append('Cerrar puertos críticos expuestos a Internet')
                elif 'BCM-001' in finding['id']:
                    actions.append('Implementar backup cross-region para sistemas críticos')
        
        # Eliminar duplicados y limitar
        return list(dict.fromkeys(actions))[:5]
    
    def _save_final_results(self):
        """Guardar resultados finales consolidados"""
        output_file = OUTPUT_DIR / f"assessment_complete_{REPORT_TIMESTAMP}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        self.logger.info(f"Resultados completos guardados en {output_file}")
    
    def _print_summary(self):
        """Imprimir resumen en consola"""
        summary = self.results['findings_summary']
        risk = self.results['risk_analysis']
        
        print("\n" + "="*60)
        print(f"RESUMEN DEL ASSESSMENT DE SEGURIDAD")
        print(f"Cliente: {CLIENT_NAME}")
        print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print("="*60)
        
        print("\nHALLAZGOS POR SEVERIDAD:")
        print(f"  🔴 CRÍTICOS: {summary['by_severity']['CRITICAL']}")
        print(f"  🟠 ALTOS:    {summary['by_severity']['HIGH']}")
        print(f"  🟡 MEDIOS:   {summary['by_severity']['MEDIUM']}")
        print(f"  🟢 BAJOS:    {summary['by_severity']['LOW']}")
        print(f"  📊 TOTAL:    {summary['total']}")
        
        print("\nANÁLISIS DE RIESGO:")
        print(f"  Score de Seguridad: {risk['normalized_security_score']}/100")
        print(f"  Nivel de Riesgo: {risk['risk_level']}")
        print(f"  Nivel de Madurez: {risk['maturity_level']}/5.0")
        
        print("\nCUMPLIMIENTO:")
        compliance = self.results['modules'].get('compliance', {})
        print(f"  Overall Compliance: {compliance.get('overall_compliance', 0)}%")
        
        print("\nREPORTES GENERADOS:")
        print(f"  📁 Directorio: {OUTPUT_DIR}")
        print(f"  📄 Reporte Técnico")
        print(f"  📊 Reporte Ejecutivo")
        print(f"  📋 CSV de Hallazgos")
        print(f"  🗺️  Plan de Remediación")
        
        print("\n" + "="*60)


async def main():
    """Función principal"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║        HUAWEI CLOUD SECURITY ASSESSMENT TOOL v1.0         ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  Cliente: CGP                                             ║
    ║  Powered by: Security Team                                ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Verificar variables de entorno
    from config.settings import HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY, HUAWEI_PROJECT_ID
    
    if not all([HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY, HUAWEI_PROJECT_ID]):
        print("❌ ERROR: Credenciales de Huawei Cloud no configuradas")
        print("Por favor configure las siguientes variables de entorno:")
        print("  - HUAWEI_ACCESS_KEY")
        print("  - HUAWEI_SECRET_KEY")
        print("  - HUAWEI_PROJECT_ID")
        print("  - HUAWEI_DOMAIN_ID")
        sys.exit(1)
    
    # Confirmar ejecución
    print("\n⚠️  Este proceso analizará TODOS los recursos en las regiones configuradas.")
    print("Tiempo estimado: 30-60 minutos\n")
    
    response = input("¿Desea continuar? (s/n): ")
    if response.lower() != 's':
        print("Assessment cancelado.")
        sys.exit(0)
    
    # Ejecutar assessment
    assessment = SecurityAssessment()
    await assessment.run_assessment()
    
    print("\n✅ Assessment completado exitosamente!")
    print(f"Los resultados se encuentran en: {OUTPUT_DIR}")


if __name__ == "__main__":
    asyncio.run(main())