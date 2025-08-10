# 📚 Guía de Migración - Analyzers Modulares

## 🎯 Resumen de Cambios

La estructura de analyzers ha sido **modularizada por dominio** para mejor mantenibilidad y escalabilidad.

### Antes (Estructura Monolítica)
```
analyzers/
└── vulnerability_analizer_modules_iam_network.py  # Todo junto
```

### Ahora (Estructura Modular)
```
analyzers/
├── __init__.py                           # Exporta todas las clases
├── vulnerability_analyzer_base.py        # Clase base común
├── vulnerability_analyzer_iam.py         # IAM-001 a IAM-030
├── vulnerability_analyzer_network.py     # NET-001 a NET-008
├── vulnerability_analyzer_modules.py     # Coordinador principal
└── README_MIGRATION.md                   # Esta guía
```

## 🔄 Mapeo con security_references.csv

Cada analyzer ahora está **sincronizado con los códigos del CSV**:

| Archivo | Códigos | Controles |
|---------|---------|-----------|
| `vulnerability_analyzer_iam.py` | IAM-001 a IAM-030 | 30 controles IAM |
| `vulnerability_analyzer_network.py` | NET-001 a NET-008 | 8 controles Network |
| `vulnerability_analyzer_storage.py` | STO-001 a STO-009 | 9 controles Storage (pendiente) |
| `vulnerability_analyzer_monitoring.py` | MON-001 a MON-007 | 7 controles Monitoring (pendiente) |

## 📦 Importaciones y Compatibilidad

### ✅ Código Nuevo (Recomendado)

```python
# Importar analyzers específicos
from analyzers.vulnerability_analyzer_iam import IAMVulnerabilityAnalyzer
from analyzers.vulnerability_analyzer_network import NetworkVulnerabilityAnalyzer

# O usar el coordinador
from analyzers import ModuleVulnerabilityAnalyzer
```

### 🔧 Compatibilidad con Código Existente

El código antiguo **sigue funcionando sin cambios**:

```python
# Esta importación sigue siendo válida
from analyzers import IAMNetworkVulnerabilityAnalyzer

# Los métodos antiguos funcionan igual
analyzer = IAMNetworkVulnerabilityAnalyzer()
analyzer.analyze_iam_vulnerabilities(iam_data)
analyzer.analyze_network_vulnerabilities(network_data)
```

## 🚀 Guía de Migración Paso a Paso

### 1️⃣ Para `main.py`

**Antes:**
```python
from analyzers.vulnerability_analizer_modules_iam_network import IAMNetworkVulnerabilityAnalyzer

analyzer = IAMNetworkVulnerabilityAnalyzer()
```

**Después (sin cambios necesarios):**
```python
# Opción 1: Mantener compatibilidad
from analyzers import IAMNetworkVulnerabilityAnalyzer

# Opción 2: Usar nuevo nombre (recomendado)
from analyzers import ModuleVulnerabilityAnalyzer
analyzer = ModuleVulnerabilityAnalyzer()
```

### 2️⃣ Para `collectors/iam_collector.py`

**Si necesitas solo análisis IAM:**
```python
from analyzers import IAMVulnerabilityAnalyzer

iam_analyzer = IAMVulnerabilityAnalyzer()
vulnerabilities = iam_analyzer.analyze(iam_data)
```

### 3️⃣ Para `clients/iam_cli.py`

**Mantener compatibilidad:**
```python
try:
    # Intentar importación nueva
    from analyzers import IAMVulnerabilityAnalyzer as Analyzer
except ImportError:
    # Fallback a compatibilidad
    from analyzers import IAMNetworkVulnerabilityAnalyzer as Analyzer
```

## 🎯 Ventajas de la Nueva Estructura

### 1. **Separación de Responsabilidades**
- Cada dominio tiene su propio archivo
- Más fácil de mantener y actualizar
- Reduce conflictos en control de versiones

### 2. **Mapeo Directo con CSV**
- Cada código en el analyzer corresponde al CSV
- Datos de severidad, CVSS, y frameworks vienen del CSV
- Actualización centralizada de referencias

### 3. **Escalabilidad**
- Fácil agregar nuevos dominios (Storage, Monitoring, etc.)
- No afecta código existente
- Pruebas unitarias más simples

### 4. **Reutilización de Código**
- Clase base común (`VulnerabilityAnalyzerBase`)
- Métodos helper compartidos
- Reducción de duplicación

## 📊 Ejemplo de Uso Completo

```python
#!/usr/bin/env python3
"""Ejemplo de análisis modular completo"""

from analyzers import ModuleVulnerabilityAnalyzer

def run_security_assessment(assessment_data):
    # Crear analyzer
    analyzer = ModuleVulnerabilityAnalyzer()
    
    # Analizar cada módulo
    if 'iam' in assessment_data:
        analyzer.analyze_iam_vulnerabilities(assessment_data['iam'])
    
    if 'network' in assessment_data:
        analyzer.analyze_network_vulnerabilities(assessment_data['network'])
    
    if 'storage' in assessment_data:
        analyzer.analyze_storage_vulnerabilities(assessment_data['storage'])
    
    if 'monitoring' in assessment_data:
        analyzer.analyze_monitoring_vulnerabilities(assessment_data['monitoring'])
    
    # Análisis cross-módulo
    analyzer.analyze_cross_module_vulnerabilities(assessment_data)
    
    # Obtener resultados
    summary = analyzer.get_consolidated_summary()
    report = analyzer.export_modular_report()
    
    return report

# Ejecutar
data = {
    'iam': {...},
    'network': {...},
    'storage': {...},
    'monitoring': {...}
}

report = run_security_assessment(data)
print(f"Vulnerabilidades encontradas: {report['summary']['total_vulnerabilities']}")
```

## 🔍 Verificación de Códigos CSV

Para verificar que un código existe en el CSV:

```python
import pandas as pd

# Cargar referencias
df = pd.read_csv('security_references.csv')

# Ver todos los códigos IAM
iam_codes = df[df['Dominio'] == 'IAM']['Codigo'].tolist()
print(f"Códigos IAM: {iam_codes}")

# Verificar un código específico
code = 'IAM-001'
if code in df['Codigo'].values:
    row = df[df['Codigo'] == code].iloc[0]
    print(f"{code}: {row['Control']}")
    print(f"Severidad: {row['Severidad']}")
    print(f"CVSS: {row['CVSS_Score']}")
```

## ⚠️ Consideraciones Importantes

1. **NO modificar** `vulnerability_analyzer_base.py` sin actualizar todos los módulos
2. **Siempre verificar** que los códigos nuevos existan en `security_references.csv`
3. **Mantener sincronizados** los códigos entre analyzers y CSV
4. **Documentar** cualquier código CROSS-XXX adicional que no esté en el CSV

## 📝 Checklist de Migración

- [ ] Actualizar importaciones en `main.py`
- [ ] Verificar que `collectors/` usen los nuevos módulos
- [ ] Actualizar `clients/` para compatibilidad
- [ ] Ejecutar pruebas de regresión
- [ ] Verificar que todos los códigos mapeen al CSV
- [ ] Actualizar documentación del proyecto
- [ ] Comunicar cambios al equipo

## 🆘 Troubleshooting

### Error: "No module named 'vulnerability_analizer_modules_iam_network'"
**Solución:** Cambiar importación a `from analyzers import IAMNetworkVulnerabilityAnalyzer`

### Error: "IAMVulnerabilityAnalyzer not found"
**Solución:** Verificar que `__init__.py` esté presente en `analyzers/`

### Error: "Code XXX-999 not found in references"
**Solución:** Agregar el código a `security_references.csv` o usar un código existente

## 📞 Soporte

Si encuentras problemas con la migración:
1. Revisa esta guía
2. Verifica los ejemplos en `examples/analyzer_usage_example.py`
3. Contacta al equipo de seguridad

---
*Última actualización: Agosto 2025*
*Versión de analyzers: 2.0.0*