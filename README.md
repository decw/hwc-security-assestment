# Proyecto de Análisis de Seguridad en la Nube
# Proyecto de Análisis de Seguridad en la Nube
🗂️ Estructura del Proyecto

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
├── utils/
│   ├── logger.py           # Sistema de logging
│   └── report_generator.py # Generador de reportes
├── main.py                 # Script principal
├── requirements.txt        # Dependencias
└── README.md              # Documentación

🔑 Características Principales

Colectores Modulares:

IAM: Usuarios, grupos, políticas, MFA, access keys
Network: VPCs, security groups, puertos expuestos
Storage: EVS, OBS, cifrado, backups
Monitoring: Cloud Eye, CTS, retención de logs
Compliance: CIS, ISO 27001, NIST CSF


Análisis Automatizado:

Detección de configuraciones inseguras
Evaluación de cumplimiento
Cálculo de scores de riesgo
Priorización de hallazgos


Reportes Completos:

Técnico (Markdown)
Ejecutivo (PDF con gráficos)
CSV para análisis
Plan de remediación


Seguridad Integrada:

Sin credenciales hardcodeadas
Variables de entorno
Logs seguros
Solo operaciones de lectura



🚀 Próximos Pasos para Usar los Scripts

Configurar el entorno:

```bash
# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
export HUAWEI_ACCESS_KEY=tu_access_key
export HUAWEI_SECRET_KEY=tu_secret_key
export HUAWEI_PROJECT_ID=tu_project_id
export HUAWEI_DOMAIN_ID=tu_domain_id
```

## Ejecución del Assessment

### Assessment Completo
```bash
python3 main.py
```

### Colector IAM Individual
```bash
# Script simple
python3 iam_cli.py

# Script con opciones avanzadas
python3 run_iam_collector.py --help

# Ejemplos de uso específico
python3 run_iam_collector.py --check-mfa-only
python3 run_iam_collector.py --check-users-only --verbose
python3 run_iam_collector.py --check-policies-only --output mi_reporte.json
```

### Desde el directorio collectors
```bash
cd collectors/
python3 run_iam.py
```

Revisar resultados:

- `output/`: JSONs con datos raw
- `reports/`: Reportes formateados  
- `logs/`: Logs de ejecución
- `iam_*.json`: Resultados del colector IAM individual



⚠️ Consideraciones Importantes

APIs de Huawei Cloud: Algunos métodos pueden necesitar ajustes según la versión exacta del SDK
Permisos: Requiere permisos de lectura en todos los servicios
Tiempo: El análisis completo puede tomar 30-60 minutos
Recursos: Analiza TODOS los recursos en las regiones configuradas

🔧 Personalización
Los scripts están diseñados para ser extensibles:

Agregar nuevos colectores en collectors/
Modificar umbrales en constants.py
Personalizar reportes en report_generator.py
Agregar nuevos frameworks de compliance

## 📋 Scripts CLI Individuales

### Colector IAM
- `iam_cli.py`: Script simple para recolección completa
- `run_iam_collector.py`: Script avanzado con múltiples opciones
- `collectors/run_iam.py`: Script directo desde el directorio collectors

### Opciones Disponibles
- Recolección completa de datos IAM
- Verificación específica de MFA
- Análisis de usuarios únicamente
- Revisión de políticas y roles
- Verificación de access keys
- Modo verbose para debugging

### Documentación Detallada
Ver `README_IAM_CLI.md` para información completa sobre el uso de los scripts CLI del colector IAM.