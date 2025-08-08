# Proyecto de Análisis de Seguridad en la Nube

## 🗂️ Estructura del Proyecto

huawei-security-assessment/
├── config/
│   ├── settings.py          # Configuración central
│   └── constants.py         # Constantes de seguridad
├── collectors/
│   ├── iam_collector.py     # Análisis de IAM
│   ├── network_collector.py # Análisis de red
│   ├── storage_collector.py # Análisis de almacenamiento
│   ├── monitoring_collector.py # Análisis de monitoreo
│   └── compliance_collector.py # Evaluación de cumplimiento
├── analyzers/
│   ├── vulnerability_analizer_modules_iam_network.py # Análisis IAM y Network
│   ├── vulnerability_analizer_modules_storage_monitoring.py # Análisis Storage y Monitoring
│   └── risk_analyzer.py     # Análisis de riesgo
├── clients/
│   ├── __init__.py          # Inicialización del módulo clients
│   ├── iam_cli.py           # CLI unificado para IAM
│   ├── network_cli.py       # CLI unificado para Network
│   ├── storage_cli.py       # CLI unificado para Storage
│   ├── monitoring_cli.py    # CLI unificado para Monitoring
│   └── compliance_cli.py    # CLI unificado para Compliance
├── utils/
│   ├── logger.py           # Sistema de logging
│   └── report_generator.py # Generador de reportes
├── main.py                 # Script principal
├── requirements.txt        # Dependencias
└── README.md              # Documentación

## 🔑 Características Principales

### Colectores Modulares:
- **IAM**: Usuarios, grupos, políticas, MFA, access keys
- **Network**: VPCs, security groups, puertos expuestos
- **Storage**: EVS, OBS, cifrado, backups
- **Monitoring**: Cloud Eye, CTS, retención de logs
- **Compliance**: CIS, ISO 27001, NIST CSF

### Análisis Automatizado:
- Detección de configuraciones inseguras
- Evaluación de cumplimiento
- Cálculo de scores de riesgo
- Priorización de hallazgos

### Reportes Completos:
- Técnico (Markdown)
- Ejecutivo (PDF con gráficos)
- CSV para análisis
- Plan de remediación

### Seguridad Integrada:
- Sin credenciales hardcodeadas
- Variables de entorno
- Logs seguros
- Solo operaciones de lectura

## 🚀 Configuración y Uso

### Configurar el entorno:

```bash
# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
export HUAWEI_ACCESS_KEY="tu_access_key"
export HUAWEI_SECRET_KEY="tu_secret_key"
export HUAWEI_PROJECT_ID="tu_project_id"
export HUAWEI_DOMAIN_ID="tu_domain_id"
```

## 📋 Ejecución del Assessment

### Assessment Completo
```bash
python3 main.py
```

### CLIs Individuales (Nueva Estructura)

#### IAM - Recolección y análisis
```bash
# Recolección completa + análisis
python3 -m clients.iam_cli

# Solo recolección (sin análisis)
python3 -m clients.iam_cli --collect-only

# Solo análisis (requiere archivo de datos)
python3 -m clients.iam_cli --analyze-only --input datos.json

# Modo específico
python3 -m clients.iam_cli --check-mfa-only
python3 -m clients.iam_cli --check-users-only
python3 -m clients.iam_cli --check-policies-only
python3 -m clients.iam_cli --check-access-keys-only

# Archivo de salida personalizado
python3 -m clients.iam_cli --output mi_reporte.json

# Modo verbose sin confirmación
python3 -m clients.iam_cli --verbose --no-confirm
```

#### Network - Recolección y análisis
```bash
# Recolección completa + análisis
python3 -m clients.network_cli

# Solo recolección
python3 -m clients.network_cli --collect-only

# Solo análisis
python3 -m clients.network_cli --analyze-only --input network_data.json
```

#### Storage - Recolección y análisis
```bash
# Recolección completa + análisis
python3 -m clients.storage_cli

# Solo recolección
python3 -m clients.storage_cli --collect-only
```

#### Monitoring - Recolección y análisis
```bash
# Recolección completa + análisis
python3 -m clients.monitoring_cli

# Solo recolección
python3 -m clients.monitoring_cli --collect-only
```

#### Compliance - Recolección y análisis
```bash
# Recolección completa + análisis
python3 -m clients.compliance_cli

# Solo recolección
python3 -m clients.compliance_cli --collect-only
```

### Opciones Comunes de los CLIs
```bash
# Ver ayuda
python3 -m clients.iam_cli --help

# Modo verbose con logs detallados
python3 -m clients.iam_cli --verbose

# Ejecutar sin confirmación
python3 -m clients.iam_cli --no-confirm

# Archivo de salida simple
python3 -m clients.iam_cli --simple-output
```

## 🏗️ Arquitectura de los CLIs

### Estructura Modular
- **Collectors**: Recolectan datos de Huawei Cloud
- **Analyzers**: Analizan vulnerabilidades y riesgos
- **CLIs**: Interfaz unificada para cada módulo

### Funcionalidades
- ✅ Recolección completa de datos
- ✅ Análisis de vulnerabilidades automático
- ✅ Múltiples modos de operación
- ✅ Salida en formato JSON
- ✅ Manejo de errores robusto
- ✅ Logs detallados opcionales

### Ventajas de la Nueva Estructura
- 🎯 **Sin duplicación**: Un solo CLI por módulo
- 🔧 **Mantenible**: Lógica centralizada en collectors y analyzers
- 📦 **Modular**: Cada CLI importa solo lo necesario
- 🚀 **Escalable**: Fácil agregar nuevos módulos
- 📚 **Documentado**: Ayuda integrada en cada CLI

##  Salida de los CLIs

### Archivos Generados
- `*_results.json`: Datos recolectados
- `*_analysis.json`: Resultados del análisis de vulnerabilidades
- `*_analysis_results.json`: Solo análisis (modo --analyze-only)

### Estructura de Salida
```json
{
  "vulnerabilities": [...],
  "summary": {
    "total_vulnerabilities": 0,
    "by_severity": {...},
    "by_type": {...}
  },
  "timestamp": "2024-01-01T12:00:00"
}
```

### Revisar resultados:
- `output/`: JSONs con datos raw
- `reports/`: Reportes formateados  
- `logs/`: Logs de ejecución
- `*_results.json`: Resultados de los CLIs individuales

## ⚠️ Consideraciones Importantes

- **APIs de Huawei Cloud**: Algunos métodos pueden necesitar ajustes según la versión exacta del SDK
- **Permisos**: Requiere permisos de lectura en todos los servicios
- **Tiempo**: El análisis completo puede tomar 30-60 minutos
- **Recursos**: Analiza TODOS los recursos en las regiones configuradas

## 🔧 Personalización

Los scripts están diseñados para ser extensibles:

- Agregar nuevos colectores en `collectors/`
- Agregar nuevos analizadores en `analyzers/`
- Crear nuevos CLIs en `clients/`
- Modificar umbrales en `config/constants.py`
- Personalizar reportes en `utils/report_generator.py`
- Agregar nuevos frameworks de compliance

## 🆘 Troubleshooting

### Error de Importación
```
❌ ERROR: No se pudo importar IAMCollector
```
**Solución:** Verificar que esté en el directorio raíz del proyecto

### Error de Credenciales
```
❌ ERROR: Credenciales de Huawei Cloud no configuradas
```
**Solución:** Configurar variables de entorno

### Error de Análisis
```
⚠️ ADVERTENCIA: No se pudo importar IAMNetworkVulnerabilityAnalyzer
```
**Solución:** Verificar que el analizador esté disponible

##  Migración desde la Estructura Anterior

Los siguientes archivos han sido **eliminados** y reemplazados por la nueva estructura:

### Archivos Eliminados:
- `iam_cli.py` → `clients/iam_cli.py`
- `run_iam_collector.py` → `clients/iam_cli.py`
- `collectors/run_iam.py` → `clients/iam_cli.py`
- `test_iam_cli.py` → No necesario (funcionalidad integrada)
- `README_IAM_CLI.md` → Documentación integrada en este README

### Nuevos Comandos:
```bash
# Antes
python3 iam_cli.py
python3 run_iam_collector.py --check-mfa-only

# Ahora
python3 -m clients.iam_cli
python3 -m clients.iam_cli --check-mfa-only
```

##  Próximos Pasos

1. **Configurar credenciales** de Huawei Cloud
2. **Instalar dependencias** con `pip install -r requirements.txt`
3. **Ejecutar assessment completo** con `python3 main.py`
4. **Usar CLIs individuales** según necesidades específicas
5. **Revisar resultados** en los archivos JSON generados
