#!/usr/bin/env python3
"""
Generador de reportes para el Assessment de Seguridad
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.backends.backend_pdf import PdfPages
import pandas as pd
import numpy as np

from config.settings import REPORTS_DIR, CLIENT_NAME, REPORT_TIMESTAMP
from config.constants import SEVERITY_MAPPING

class ReportGenerator:
    """Generador de reportes en múltiples formatos"""
    
    def __init__(self, assessment_results: Dict[str, Any]):
        self.results = assessment_results
        self.timestamp = REPORT_TIMESTAMP
        
    def generate_technical_report(self):
        """Generar reporte técnico detallado en formato Markdown"""
        report_path = REPORTS_DIR / f"technical_report_{self.timestamp}.md"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            # Header
            f.write(f"# Assessment de Seguridad - {CLIENT_NAME}\n\n")
            f.write(f"**Fecha**: {datetime.now().strftime('%d/%m/%Y')}\n")
            f.write(f"**Versión**: 1.0\n")
            f.write(f"**Clasificación**: CONFIDENCIAL\n\n")
            
            # Tabla de contenidos
            f.write("## Tabla de Contenidos\n\n")
            f.write("1. [Resumen Ejecutivo](#resumen-ejecutivo)\n")
            f.write("2. [Metodología](#metodología)\n")
            f.write("3. [Hallazgos por Módulo](#hallazgos-por-módulo)\n")
            f.write("4. [Análisis de Cumplimiento](#análisis-de-cumplimiento)\n")
            f.write("5. [Recomendaciones](#recomendaciones)\n")
            f.write("6. [Anexos](#anexos)\n\n")
            
            # Resumen Ejecutivo
            f.write("## 1. Resumen Ejecutivo\n\n")
            summary = self.results.get('executive_summary', {})
            
            f.write("### Alcance del Assessment\n\n")
            scope = summary.get('assessment_scope', {})
            f.write(f"- **Recursos Analizados**: {scope.get('total_resources_analyzed', 0)}\n")
            f.write(f"- **Regiones Cubiertas**: {scope.get('regions_covered', 0)}\n")
            f.write(f"- **Servicios Evaluados**: {scope.get('services_evaluated', 0)}\n\n")
            
            f.write("### Hallazgos Clave\n\n")
            findings_summary = self.results.get('findings_summary', {})
            f.write("| Severidad | Cantidad | Porcentaje |\n")
            f.write("|-----------|----------|------------|\n")
            
            total = findings_summary.get('total', 1)  # Evitar división por cero
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = findings_summary.get('by_severity', {}).get(severity, 0)
                percentage = (count / total * 100) if total > 0 else 0
                icon = SEVERITY_MAPPING[severity]['icon']
                f.write(f"| {icon} {severity} | {count} | {percentage:.1f}% |\n")
            
            # Estado de Madurez
            f.write("\n### Estado de Madurez\n\n")
            risk = self.results.get('risk_analysis', {})
            f.write(f"- **Score de Seguridad**: {risk.get('normalized_security_score', 0)}/100\n")
            f.write(f"- **Nivel de Riesgo**: {risk.get('risk_level', 'No determinado')}\n")
            f.write(f"- **Nivel de Madurez Actual**: {risk.get('maturity_level', 0)}/5.0\n")
            f.write(f"- **Nivel de Madurez Objetivo**: 3.0/5.0\n\n")
            
            # Metodología
            f.write("## 2. Metodología\n\n")
            f.write("El assessment siguió los siguientes frameworks y estándares:\n\n")
            f.write("- CIS Benchmarks for Cloud Security v1.4.0\n")
            f.write("- NIST Cybersecurity Framework v2.0\n")
            f.write("- ISO 27001:2022\n")
            f.write("- Huawei Cloud Security Best Practices\n\n")
            
            # Hallazgos por módulo
            f.write("## 3. Hallazgos por Módulo\n\n")
            
            modules_order = ['iam', 'network', 'storage', 'monitoring']
            for module in modules_order:
                if module in self.results.get('modules', {}):
                    self._write_module_findings(f, module, self.results['modules'][module])
            
            # Análisis de Cumplimiento
            f.write("## 4. Análisis de Cumplimiento\n\n")
            compliance = self.results.get('modules', {}).get('compliance', {})
            
            if compliance:
                f.write(f"**Cumplimiento General**: {compliance.get('overall_compliance', 0)}%\n\n")
                
                # Cumplimiento por framework
                f.write("### Cumplimiento por Framework\n\n")
                f.write("| Framework | Cumplimiento | Estado |\n")
                f.write("|-----------|--------------|--------|\n")
                
                for fw_name, fw_data in compliance.get('frameworks', {}).items():
                    compliance_pct = fw_data.get('compliance_percentage', 0)
                    status = "✅ Aceptable" if compliance_pct >= 80 else "⚠️ Requiere Mejora" if compliance_pct >= 60 else "❌ Crítico"
                    f.write(f"| {fw_name} | {compliance_pct}% | {status} |\n")
            
            # Recomendaciones
            f.write("\n## 5. Recomendaciones\n\n")
            self._write_recommendations(f)
            
            # Anexos
            f.write("\n## 6. Anexos\n\n")
            f.write("### A. Detalle de Hallazgos\n\n")
            self._write_detailed_findings(f)
            
        print(f"✅ Reporte técnico generado: {report_path}")
    
    def generate_executive_report(self):
        """Generar reporte ejecutivo en PDF con gráficos"""
        report_path = REPORTS_DIR / f"executive_report_{self.timestamp}.pdf"
        
        with PdfPages(report_path) as pdf:
            # Página 1: Portada
            self._create_cover_page(pdf)
            
            # Página 2: Resumen de hallazgos
            self._create_findings_summary_page(pdf)
            
            # Página 3: Análisis de riesgo
            self._create_risk_analysis_page(pdf)
            
            # Página 4: Cumplimiento
            self._create_compliance_page(pdf)
            
            # Página 5: Roadmap
            self._create_roadmap_page(pdf)
            
        print(f"✅ Reporte ejecutivo generado: {report_path}")
    
    def generate_findings_csv(self):
        """Generar CSV con todos los hallazgos para análisis"""
        csv_path = REPORTS_DIR / f"findings_{self.timestamp}.csv"
        
        findings = self.results.get('consolidated_findings', [])
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['ID', 'Severidad', 'Módulo', 'Mensaje', 'Detalles', 'Timestamp']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for finding in findings:
                writer.writerow({
                    'ID': finding.get('id', ''),
                    'Severidad': finding.get('severity', ''),
                    'Módulo': finding.get('module', ''),
                    'Mensaje': finding.get('message', ''),
                    'Detalles': json.dumps(finding.get('details', {}), ensure_ascii=False),
                    'Timestamp': finding.get('timestamp', '')
                })
        
        print(f"✅ CSV de hallazgos generado: {csv_path}")
    
    def generate_remediation_plan(self):
        """Generar plan de remediación detallado"""
        plan_path = REPORTS_DIR / f"remediation_plan_{self.timestamp}.md"
        
        with open(plan_path, 'w', encoding='utf-8') as f:
            f.write(f"# Plan de Remediación - {CLIENT_NAME}\n\n")
            f.write(f"**Fecha**: {datetime.now().strftime('%d/%m/%Y')}\n\n")
            
            # Quick Wins (0-30 días)
            f.write("## 🚀 Quick Wins (0-30 días)\n\n")
            f.write("### Acciones de impacto inmediato con bajo esfuerzo\n\n")
            
            quick_wins = self._identify_quick_wins()
            for idx, win in enumerate(quick_wins, 1):
                f.write(f"#### {idx}. {win['title']}\n")
                f.write(f"- **Hallazgo**: {win['finding_id']}\n")
                f.write(f"- **Impacto**: {win['impact']}\n")
                f.write(f"- **Esfuerzo**: {win['effort']}\n")
                f.write(f"- **Pasos**:\n")
                for step in win['steps']:
                    f.write(f"  1. {step}\n")
                f.write("\n")
            
            # Corto Plazo (30-60 días)
            f.write("## 📈 Corto Plazo (30-60 días)\n\n")
            short_term = self._identify_short_term_actions()
            self._write_action_items(f, short_term)
            
            # Medio Plazo (60-90 días)
            f.write("## 🎯 Medio Plazo (60-90 días)\n\n")
            medium_term = self._identify_medium_term_actions()
            self._write_action_items(f, medium_term)
            
            # Matriz de Priorización
            f.write("## 📊 Matriz de Priorización\n\n")
            f.write("| Acción | Impacto | Esfuerzo | Prioridad | Timeline |\n")
            f.write("|--------|---------|----------|-----------|----------|\n")
            
            all_actions = quick_wins + short_term + medium_term
            for action in sorted(all_actions, key=lambda x: x.get('priority', 99)):
                f.write(f"| {action['title'][:40]}... | {action['impact']} | {action['effort']} | {action['priority']} | {action['timeline']} |\n")
            
            # Métricas de éxito
            f.write("\n## 📈 Métricas de Éxito\n\n")
            f.write("| KPI | Baseline | Meta 30d | Meta 60d | Meta 90d |\n")
            f.write("|-----|----------|----------|----------|----------|\n")
            f.write(f"| Hallazgos Críticos | {self._count_findings_by_severity('CRITICAL')} | 0 | 0 | 0 |\n")
            f.write(f"| Hallazgos Altos | {self._count_findings_by_severity('HIGH')} | 50% | 20% | 0 |\n")
            f.write(f"| Score de Seguridad | {self.results.get('risk_analysis', {}).get('normalized_security_score', 0)}% | +20% | +40% | +60% |\n")
            f.write(f"| Nivel de Madurez | {self.results.get('risk_analysis', {}).get('maturity_level', 0)} | 2.5 | 3.0 | 3.5 |\n")
            
        print(f"✅ Plan de remediación generado: {plan_path}")
    
    def _write_module_findings(self, f, module_name: str, module_data: dict):
        """Escribir hallazgos de un módulo específico"""
        f.write(f"### {module_name.upper()}\n\n")
        
        # Estadísticas del módulo
        if 'statistics' in module_data:
            f.write("**Estadísticas**:\n\n")
            stats = module_data['statistics']
            
            if module_name == 'iam':
                f.write(f"- Total de usuarios: {stats.get('total_users', 0)}\n")
                f.write(f"- Usuarios sin MFA: {stats.get('users_without_mfa', 0)}\n")
                f.write(f"- Compliance MFA: {stats.get('mfa_compliance_rate', 0)}%\n")
                f.write(f"- Access Keys antiguas: {stats.get('old_access_keys', 0)}\n")
            elif module_name == 'network':
                f.write(f"- Total VPCs: {stats.get('total_vpcs', 0)}\n")
                f.write(f"- Security Groups: {stats.get('total_security_groups', 0)}\n")
                f.write(f"- Recursos expuestos: {stats.get('exposed_resources', 0)}\n")
                f.write(f"- Puertos críticos expuestos: {stats.get('critical_ports_exposed', 0)}\n")
            elif module_name == 'storage':
                f.write(f"- Volúmenes EVS: {stats.get('total_evs_volumes', 0)}\n")
                f.write(f"- Buckets OBS: {stats.get('total_obs_buckets', 0)}\n")
                f.write(f"- Compliance de cifrado: {stats.get('encryption_compliance', {}).get('overall', 0)}%\n")
                f.write(f"- Buckets públicos: {stats.get('public_buckets', 0)}\n")
            elif module_name == 'monitoring':
                f.write(f"- Total de alarmas: {stats.get('total_alarms', 0)}\n")
                f.write(f"- Cloud Trace habilitado: {'Sí' if stats.get('cts_enabled', False) else 'No'}\n")
                f.write(f"- Retención promedio de logs: {stats.get('average_log_retention', 0)} días\n")
            
            f.write("\n")
        
        # Hallazgos principales
        module_findings = [f for f in self.results.get('consolidated_findings', []) 
                          if f.get('module') == module_name]
        
        if module_findings:
            f.write("**Hallazgos principales**:\n\n")
            for finding in module_findings[:5]:  # Top 5
                icon = SEVERITY_MAPPING[finding['severity']]['icon']
                f.write(f"- {icon} **[{finding['id']}]** {finding['message']}\n")
            
            if len(module_findings) > 5:
                f.write(f"- *(y {len(module_findings) - 5} hallazgos más)*\n")
        
        f.write("\n")
    
    def _write_recommendations(self, f):
        """Escribir recomendaciones priorizadas"""
        recommendations = self.results.get('modules', {}).get('compliance', {}).get('recommendations', [])
        
        if not recommendations:
            # Generar recomendaciones basadas en hallazgos
            recommendations = self._generate_recommendations_from_findings()
        
        # Agrupar por prioridad
        critical_recs = [r for r in recommendations if r.get('priority') == 'CRITICAL']
        high_recs = [r for r in recommendations if r.get('priority') == 'HIGH']
        medium_recs = [r for r in recommendations if r.get('priority') == 'MEDIUM']
        
        if critical_recs:
            f.write("### 🔴 Prioridad Crítica\n\n")
            for rec in critical_recs:
                f.write(f"**{rec['title']}**\n")
                f.write(f"- {rec['description']}\n")
                f.write(f"- Impacto: {rec['impact']}\n")
                f.write(f"- Esfuerzo: {rec['effort']}\n\n")
        
        if high_recs:
            f.write("### 🟠 Prioridad Alta\n\n")
            for rec in high_recs:
                f.write(f"**{rec['title']}**\n")
                f.write(f"- {rec['description']}\n\n")
        
        if medium_recs:
            f.write("### 🟡 Prioridad Media\n\n")
            for rec in medium_recs:
                f.write(f"**{rec['title']}**\n")
                f.write(f"- {rec['description']}\n\n")
    
    def _write_detailed_findings(self, f):
        """Escribir tabla detallada de todos los hallazgos"""
        findings = self.results.get('consolidated_findings', [])
        
        if not findings:
            f.write("No se encontraron hallazgos significativos.\n")
            return
        
        f.write("| ID | Severidad | Módulo | Descripción |\n")
        f.write("|----|-----------|--------|-------------|\n")
        
        for finding in findings:
            icon = SEVERITY_MAPPING[finding['severity']]['icon']
            module = finding.get('module', 'N/A')
            message = finding['message'][:80] + '...' if len(finding['message']) > 80 else finding['message']
            f.write(f"| {finding['id']} | {icon} {finding['severity']} | {module} | {message} |\n")
    
    def _create_cover_page(self, pdf):
        """Crear página de portada para el PDF"""
        fig = plt.figure(figsize=(8.5, 11))
        ax = fig.add_subplot(111)
        ax.axis('off')
        
        # Título
        ax.text(0.5, 0.8, 'ASSESSMENT DE SEGURIDAD', 
                ha='center', va='center', fontsize=24, fontweight='bold')
        ax.text(0.5, 0.75, 'HUAWEI CLOUD', 
                ha='center', va='center', fontsize=20)
        
        # Cliente
        ax.text(0.5, 0.6, CLIENT_NAME, 
                ha='center', va='center', fontsize=18)
        
        # Fecha
        ax.text(0.5, 0.5, f"Fecha: {datetime.now().strftime('%d de %B de %Y')}", 
                ha='center', va='center', fontsize=14)
        
        # Clasificación
        ax.text(0.5, 0.4, 'CONFIDENCIAL', 
                ha='center', va='center', fontsize=16, 
                bbox=dict(boxstyle="round,pad=0.3", facecolor="red", alpha=0.3))
        
        # Footer
        ax.text(0.5, 0.1, 'Preparado por: IPLAN Security Team', 
                ha='center', va='center', fontsize=12)
        
        pdf.savefig(fig, bbox_inches='tight')
        plt.close()
    
    def _create_findings_summary_page(self, pdf):
        """Crear página de resumen de hallazgos"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(8.5, 11))
        
        # Gráfico de pie - Hallazgos por severidad
        summary = self.results.get('findings_summary', {})
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        counts = [summary.get('by_severity', {}).get(sev, 0) for sev in severities]
        colors = ['#FF0000', '#FFA500', '#FFFF00', '#00FF00']
        
        # Filtrar severidades con 0 hallazgos
        non_zero = [(s, c, col) for s, c, col in zip(severities, counts, colors) if c > 0]
        if non_zero:
            labels, sizes, colors_filtered = zip(*non_zero)
            ax1.pie(sizes, labels=labels, colors=colors_filtered, autopct='%1.1f%%')
            ax1.set_title('Distribución de Hallazgos por Severidad')
        else:
            ax1.text(0.5, 0.5, 'Sin hallazgos', ha='center', va='center')
            ax1.set_title('Distribución de Hallazgos por Severidad')
        
        # Gráfico de barras - Hallazgos por módulo
        modules = list(summary.get('by_module', {}).keys())
        module_counts = list(summary.get('by_module', {}).values())
        
        if modules:
            ax2.bar(modules, module_counts)
            ax2.set_title('Hallazgos por Módulo')
            ax2.set_xlabel('Módulo')
            ax2.set_ylabel('Cantidad')
            ax2.tick_params(axis='x', rotation=45)
        
        # Score de seguridad (gauge chart simulado)
        score = self.results.get('risk_analysis', {}).get('normalized_security_score', 0)
        ax3.clear()
        
        # Crear un gráfico tipo velocímetro
        theta = (100 - score) * 1.8  # Convertir score a ángulo (0-180 grados)
        colors_gauge = ['#00FF00', '#FFFF00', '#FFA500', '#FF0000']
        
        # Dibujar arcos de colores
        for i, (start, end, color) in enumerate([(0, 45, colors_gauge[3]), 
                                                  (45, 90, colors_gauge[2]), 
                                                  (90, 135, colors_gauge[1]), 
                                                  (135, 180, colors_gauge[0])]):
            ax3.add_patch(mpatches.Wedge((0.5, 0), 0.4, start, end, 
                                        facecolor=color, alpha=0.3))
        
        # Agregar aguja
        ax3.plot([0.5, 0.5 + 0.35 * np.cos(np.radians(theta))], 
                [0, 0.35 * np.sin(np.radians(theta))], 'k-', linewidth=3)
        
        ax3.set_xlim(0, 1)
        ax3.set_ylim(-0.1, 0.5)
        ax3.axis('off')
        ax3.text(0.5, -0.05, f'Score de Seguridad: {score}%', 
                ha='center', fontsize=14, fontweight='bold')
        
        # Tabla de resumen
        ax4.axis('tight')
        ax4.axis('off')
        
        risk = self.results.get('risk_analysis', {})
        table_data = [
            ['Métrica', 'Valor'],
            ['Score de Seguridad', f"{score}%"],
            ['Nivel de Riesgo', risk.get('risk_level', 'N/A')],
            ['Nivel de Madurez', f"{risk.get('maturity_level', 0)}/5.0"],
            ['Total de Hallazgos', summary.get('total', 0)],
            ['Hallazgos Críticos', summary.get('by_severity', {}).get('CRITICAL', 0)]
        ]
        
        table = ax4.table(cellText=table_data, loc='center', cellLoc='left')
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1, 2)
        
        # Estilo de la tabla
        for i in range(len(table_data)):
            if i == 0:  # Header
                for j in range(2):
                    table[(i, j)].set_facecolor('#4472C4')
                    table[(i, j)].set_text_props(weight='bold', color='white')
            else:
                for j in range(2):
                    table[(i, j)].set_facecolor('#F2F2F2' if i % 2 == 0 else 'white')
        
        plt.suptitle('Resumen de Hallazgos de Seguridad', fontsize=16, fontweight='bold')
        plt.tight_layout()
        pdf.savefig(fig, bbox_inches='tight')
        plt.close()
    
    def _create_risk_analysis_page(self, pdf):
        """Crear página de análisis de riesgo"""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8.5, 11))
        
        # Matriz de riesgo
        ax1.set_title('Matriz de Riesgo', fontsize=14, fontweight='bold')
        
        # Crear grid de matriz de riesgo
        impact_levels = ['Bajo', 'Medio', 'Alto', 'Crítico']
        likelihood_levels = ['Improbable', 'Posible', 'Probable', 'Muy Probable']
        
        # Colores para la matriz
        risk_colors = [
            ['#90EE90', '#90EE90', '#FFFF00', '#FFA500'],  # Improbable
            ['#90EE90', '#FFFF00', '#FFA500', '#FF0000'],  # Posible
            ['#FFFF00', '#FFA500', '#FFA500', '#FF0000'],  # Probable
            ['#FFA500', '#FF0000', '#FF0000', '#FF0000']   # Muy Probable
        ]
        
        # Dibujar la matriz
        for i, likelihood in enumerate(likelihood_levels):
            for j, impact in enumerate(impact_levels):
                rect = plt.Rectangle((j, i), 1, 1, 
                                   facecolor=risk_colors[i][j], 
                                   edgecolor='black', linewidth=1)
                ax1.add_patch(rect)
        
        # Agregar hallazgos a la matriz (simplificado)
        # Aquí deberías mapear los hallazgos reales a la matriz
        findings_by_severity = self.results.get('findings_summary', {}).get('by_severity', {})
        
        # Ejemplo de posicionamiento
        if findings_by_severity.get('CRITICAL', 0) > 0:
            ax1.scatter(3.5, 2.5, s=findings_by_severity['CRITICAL'] * 50, 
                       c='black', marker='o', alpha=0.7, 
                       label=f"Críticos ({findings_by_severity['CRITICAL']})")
        
        if findings_by_severity.get('HIGH', 0) > 0:
            ax1.scatter(2.5, 2.5, s=findings_by_severity['HIGH'] * 50, 
                       c='darkred', marker='o', alpha=0.7,
                       label=f"Altos ({findings_by_severity['HIGH']})")
        
        ax1.set_xlim(0, 4)
        ax1.set_ylim(0, 4)
        ax1.set_xticks([0.5, 1.5, 2.5, 3.5])
        ax1.set_xticklabels(impact_levels)
        ax1.set_yticks([0.5, 1.5, 2.5, 3.5])
        ax1.set_yticklabels(likelihood_levels)
        ax1.set_xlabel('Impacto', fontweight='bold')
        ax1.set_ylabel('Probabilidad', fontweight='bold')
        ax1.legend()
        
        # Top riesgos
        ax2.axis('tight')
        ax2.axis('off')
        ax2.set_title('Top 5 Riesgos Identificados', fontsize=14, fontweight='bold', pad=20)
        
        top_risks = self.results.get('executive_summary', {}).get('top_risks', [])[:5]
        
        risk_table = [['#', 'ID', 'Severidad', 'Descripción']]
        for i, risk in enumerate(top_risks, 1):
            desc = risk['message'][:50] + '...' if len(risk['message']) > 50 else risk['message']
            risk_table.append([
                str(i),
                risk['finding_id'],
                risk['severity'],
                desc
            ])
        
        table = ax2.table(cellText=risk_table, loc='center', cellLoc='left')
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1, 2)
        
        # Estilo
        for i in range(len(risk_table)):
            if i == 0:  # Header
                for j in range(4):
                    table[(i, j)].set_facecolor('#4472C4')
                    table[(i, j)].set_text_props(weight='bold', color='white')
            else:
                severity = risk_table[i][2]
                color = {'CRITICAL': '#FFE6E6', 'HIGH': '#FFF0E6', 
                        'MEDIUM': '#FFFDE6', 'LOW': '#E6FFE6'}.get(severity, 'white')
                for j in range(4):
                    table[(i, j)].set_facecolor(color)
        
        plt.tight_layout()
        pdf.savefig(fig, bbox_inches='tight')
        plt.close()
    
    def _create_compliance_page(self, pdf):
        """Crear página de cumplimiento"""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8.5, 11))
        
        compliance = self.results.get('modules', {}).get('compliance', {})
        
        # Gráfico de cumplimiento por framework
        frameworks = []
        percentages = []
        
        for fw_name, fw_data in compliance.get('frameworks', {}).items():
            frameworks.append(fw_name.replace('_', ' '))
            percentages.append(fw_data.get('compliance_percentage', 0))
        
        if frameworks:
            bars = ax1.barh(frameworks, percentages)
            
            # Colorear barras según el porcentaje
            for bar, pct in zip(bars, percentages):
                if pct >= 80:
                    bar.set_color('#00FF00')
                elif pct >= 60:
                    bar.set_color('#FFFF00')
                else:
                    bar.set_color('#FF0000')
            
            ax1.set_xlim(0, 100)
            ax1.set_xlabel('Porcentaje de Cumplimiento (%)')
            ax1.set_title('Cumplimiento por Framework', fontsize=14, fontweight='bold')
            
            # Agregar valores en las barras
            for bar, pct in zip(bars, percentages):
                ax1.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2, 
                        f'{pct:.1f}%', va='center')
        
        # Nivel de madurez
        ax2.clear()
        maturity = compliance.get('maturity_level', 0)
        
        # Crear visualización de niveles de madurez
        levels = ['Inicial', 'Repetible', 'Definido', 'Gestionado', 'Optimizado']
        level_values = [1, 2, 3, 4, 5]
        
        # Dibujar escalera de madurez
        for i, (level, value) in enumerate(zip(levels, level_values)):
            color = '#00FF00' if value <= maturity else '#E0E0E0'
            rect = plt.Rectangle((i, 0), 1, value, 
                               facecolor=color, edgecolor='black', linewidth=1)
            ax2.add_patch(rect)
            ax2.text(i + 0.5, value + 0.1, level, 
                    ha='center', rotation=45, fontsize=10)
        
        # Marcar nivel actual
        current_level_idx = int(maturity) - 1
        if 0 <= current_level_idx < 5:
            ax2.plot(current_level_idx + 0.5, maturity, 'ro', markersize=15)
            ax2.text(current_level_idx + 0.5, maturity + 0.5, 
                    f'Actual: {maturity}', ha='center', fontweight='bold')
        
        # Marcar objetivo
        target_idx = 2  # Nivel 3 - Definido
        ax2.plot(target_idx + 0.5, 3, 'b^', markersize=15)
        ax2.text(target_idx + 0.5, 3.5, 'Objetivo: 3.0', 
                ha='center', fontweight='bold', color='blue')
        
        ax2.set_xlim(-0.5, 5.5)
        ax2.set_ylim(0, 6)
        ax2.set_title('Nivel de Madurez de Seguridad', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Nivel')
        ax2.set_xticks([])
        
        plt.tight_layout()
        pdf.savefig(fig, bbox_inches='tight')
        plt.close()
    
    def _create_roadmap_page(self, pdf):
        """Crear página de roadmap"""
        fig = plt.figure(figsize=(8.5, 11))
        ax = fig.add_subplot(111)
        
        # Crear timeline
        phases = [
            ('Quick Wins\n(0-30 días)', 30, '#00FF00'),
            ('Corto Plazo\n(30-60 días)', 30, '#FFFF00'),
            ('Medio Plazo\n(60-90 días)', 30, '#FFA500')
        ]
        
        y_pos = 0.7
        x_start = 0.1
        bar_height = 0.1
        
        for phase, duration, color in phases:
            # Dibujar barra
            rect = plt.Rectangle((x_start, y_pos), duration/100 * 0.8, bar_height,
                               facecolor=color, edgecolor='black', linewidth=1)
            ax.add_patch(rect)
            
            # Agregar texto
            ax.text(x_start + (duration/100 * 0.8)/2, y_pos + bar_height + 0.02,
                   phase, ha='center', va='bottom', fontsize=10, fontweight='bold')
            
            x_start += duration/100 * 0.8
            y_pos -= 0.2
        
        # Agregar hitos clave
        milestones = [
            (0.15, 0.5, 'MFA\n100%'),
            (0.35, 0.3, 'Segmentación\nRed'),
            (0.55, 0.1, 'DR\nCross-Region'),
            (0.75, -0.1, 'Automatización\nSeguridad')
        ]
        
        for x, y, text in milestones:
            ax.plot(x, y, 'ro', markersize=10)
            ax.text(x, y - 0.05, text, ha='center', va='top', fontsize=8)
        
        ax.set_xlim(0, 1)
        ax.set_ylim(-0.3, 1)
        ax.axis('off')
        ax.set_title('Roadmap de Implementación de Seguridad', 
                    fontsize=16, fontweight='bold', pad=20)
        
        # Agregar leyenda de inversión
        investment_text = """
        Inversión Estimada:
        • Personal Interno: 750 horas ($75,000)
        • Consultoría Externa: 250 horas ($50,000)
        • Licencias y Herramientas: $35,000
        • Total Proyecto: $175,000
        
        ROI Esperado: 280% en 12 meses
        """
        
        ax.text(0.5, -0.2, investment_text, ha='center', va='top',
               fontsize=10, bbox=dict(boxstyle="round,pad=0.5", 
                                    facecolor="lightgray", alpha=0.5))
        
        pdf.savefig(fig, bbox_inches='tight')
        plt.close()
    
    def _identify_quick_wins(self) -> list:
        """Identificar quick wins basados en hallazgos"""
        quick_wins = []
        
        # MFA para usuarios privilegiados
        if self._has_finding('IAM-002'):
            quick_wins.append({
                'title': 'Habilitar MFA para todos los usuarios',
                'finding_id': 'IAM-002',
                'impact': 'Crítico',
                'effort': '2-3 días',
                'priority': 1,
                'timeline': '0-7 días',
                'steps': [
                    'Identificar todos los usuarios sin MFA',
                    'Enviar comunicación a usuarios',
                    'Configurar MFA obligatorio en IAM',
                    'Verificar cumplimiento'
                ]
            })
        
        # Cerrar puertos críticos
        if self._has_finding('NET-003'):
            quick_wins.append({
                'title': 'Cerrar puertos administrativos expuestos',
                'finding_id': 'NET-003',
                'impact': 'Crítico',
                'effort': '1-2 días',
                'priority': 1,
                'timeline': '0-3 días',
                'steps': [
                    'Identificar security groups con puertos 22/3389 abiertos',
                    'Implementar bastion hosts',
                    'Actualizar reglas de security groups',
                    'Validar conectividad'
                ]
            })
        
        # Aumentar retención de logs
        if self._has_finding('MON-002'):
            quick_wins.append({
                'title': 'Aumentar retención de logs a 90 días',
                'finding_id': 'MON-002',
                'impact': 'Alto',
                'effort': '1 día',
                'priority': 2,
                'timeline': '0-1 día',
                'steps': [
                    'Modificar configuración de CTS',
                    'Actualizar políticas de retención en LTS',
                    'Verificar espacio de almacenamiento',
                    'Documentar cambios'
                ]
            })
        
        return quick_wins
    
    def _identify_short_term_actions(self) -> list:
        """Identificar acciones de corto plazo"""
        actions = []
        
        # Segmentación de red
        actions.append({
            'title': 'Implementar micro-segmentación de red',
            'finding_id': 'NET-002',
            'impact': 'Alto',
            'effort': '10-15 días',
            'priority': 3,
            'timeline': '30-45 días',
            'steps': []
        })
        
        # Cifrado de datos
        if self._has_finding('STO-001'):
            actions.append({
                'title': 'Cifrar todos los volúmenes EVS',
                'finding_id': 'STO-001',
                'impact': 'Alto',
                'effort': '5-10 días',
                'priority': 4,
                'timeline': '30-40 días',
                'steps': []
            })
        
        return actions
    
    def _identify_medium_term_actions(self) -> list:
        """Identificar acciones de medio plazo"""
        actions = []
        
        # DR Cross-region
        if self._has_finding('BCM-001'):
            actions.append({
                'title': 'Implementar DR cross-region',
                'finding_id': 'BCM-001',
                'impact': 'Crítico',
                'effort': '20-30 días',
                'priority': 2,
                'timeline': '60-90 días',
                'steps': []
            })
        
        # Automatización
        actions.append({
            'title': 'Automatizar controles de seguridad',
            'finding_id': 'GENERAL',
            'impact': 'Transformacional',
            'effort': '30-40 días',
            'priority': 5,
            'timeline': '60-90 días',
            'steps': []
        })
        
        return actions
    
    def _write_action_items(self, f, actions: list):
        """Escribir items de acción en el plan"""
        for idx, action in enumerate(actions, 1):
            f.write(f"### {idx}. {action['title']}\n")
            f.write(f"- **Impacto**: {action['impact']}\n")
            f.write(f"- **Esfuerzo**: {action['effort']}\n")
            f.write(f"- **Timeline**: {action['timeline']}\n\n")
    
    def _has_finding(self, finding_id: str) -> bool:
        """Verificar si existe un hallazgo específico"""
        return any(f['id'] == finding_id for f in self.results.get('consolidated_findings', []))
    
    def _count_findings_by_severity(self, severity: str) -> int:
        """Contar hallazgos por severidad"""
        return self.results.get('findings_summary', {}).get('by_severity', {}).get(severity, 0)
    
    def _generate_recommendations_from_findings(self) -> list:
        """Generar recomendaciones basadas en hallazgos"""
        recommendations = []
        findings = self.results.get('consolidated_findings', [])
        
        # Mapear hallazgos a recomendaciones
        finding_to_rec = {
            'IAM-001': {
                'title': 'Implementar modelo de permisos basado en roles (RBAC)',
                'description': 'Eliminar permisos administrativos directos y usar roles específicos',
                'priority': 'CRITICAL',
                'impact': 'Muy Alto',
                'effort': 'Medio'
            },
            'IAM-002': {
                'title': 'Habilitar MFA obligatorio',
                'description': 'Implementar autenticación multifactor para todos los usuarios',
                'priority': 'CRITICAL',
                'impact': 'Muy Alto',
                'effort': 'Bajo'
            },
            'NET-003': {
                'title': 'Implementar arquitectura de bastion hosts',
                'description': 'Eliminar acceso directo SSH/RDP desde Internet',
                'priority': 'CRITICAL',
                'impact': 'Muy Alto',
                'effort': 'Medio'
            }
        }
        
        # Agregar recomendaciones basadas en hallazgos
        added = set()
        for finding in findings:
            if finding['id'] in finding_to_rec and finding['id'] not in added:
                recommendations.append(finding_to_rec[finding['id']])
                added.add(finding['id'])
        
        return recommendations