# Network CLI - Documentación

## 📋 Descripción
El Network CLI es una herramienta de línea de comandos para recolectar y analizar configuraciones de red en Huawei Cloud. Sigue la misma arquitectura modular que el IAM CLI.

## 🚀 Instalación y Configuración

### 1. Requisitos Previos
```bash
# Instalar dependencias
pip install -r requirements.txt

# Configurar credenciales
export HUAWEI_ACCESS_KEY=tu_access_key
export HUAWEI_SECRET_KEY=tu_secret_key
export HUAWEI_PROJECT_ID=tu_project_id
```

### 2. Actualizar Network Collector
Agregar los métodos del archivo `network_collector_updates.py` a tu `collectors/network_collector.py` existente.

## 📖 Uso

### Ejecución Básica

```bash
# Recolección y análisis completo
python3 -m clients.network_cli

# Ver todas las opciones disponibles
python3 -m clients.network_cli --help
```

### Modos de Operación

#### 1. Solo Recolección
```bash
python3 -m clients.network_cli --collect-only
```

#### 2. Solo Análisis (requiere datos previos)
```bash
python3 -m clients.network_cli --analyze-only --input network_results_20250110.json
```

#### 3. Recolección y Análisis (modo por defecto)
```bash
python3 -m clients.network_cli
```

### Opciones de Recolección Específica

#### Verificar solo VPCs
```bash
python3 -m clients.network_cli --check-vpcs-only
```

#### Verificar solo Security Groups
```bash
python3 -m clients.network_cli --check-sgs-only
```

#### Verificar solo recursos expuestos
```bash
python3 -m clients.network_cli --check-exposed-only
```

#### Verificar solo Subnets
```bash
python3 -m clients.network_cli --check-subnets-only
```

#### Verificar solo Elastic IPs
```bash
python3 -m clients.network_cli --check-eips-only
```

### Filtros de Región

#### Analizar una región específica
```bash
python3 -m clients.network_cli --region LA-Santiago
```

#### Omitir regiones específicas
```bash
python3 -m clients.network_cli --skip-regions "CN-Hong Kong" "AP-Bangkok"
```

### Opciones Avanzadas

#### Modo verbose con timeout personalizado
```bash
python3 -m clients.network_cli --verbose --timeout 60
```

#### Guardar en archivo personalizado
```bash
python3 -m clients.network_cli --output mi_analisis_red.json
```

#### Deshabilitar colores en la salida
```bash
python3 -m clients.network_cli --no-color
```

## 📊 Estructura de Salida

El CLI genera un archivo JSON con la siguiente estructura:

```json
{
  "execution_info": {
    "timestamp": "2025-01-10T10:00:00",
    "mode": "full",
    "args": {}
  },
  "collection_data": {
    "vpcs": {},
    "subnets": {},
    "security_groups": {},
    "elastic_ips": {},
    "exposed_resources": [],
    "findings": [],
    "statistics": {}
  },
  "analysis_data": {
    "vulnerabilities": [],
    "summary": {
      "total_vulnerabilities": 0,
      "by_severity": {},
      "by_type": {}
    }
  }
}
```

## 🎯 Casos de Uso Comunes

### 1. Auditoría Rápida de Seguridad
```bash
# Verificar exposiciones críticas
python3 -m clients.network_cli --check-exposed-only --check-sgs-only
```

### 2. Análisis Regional
```bash
# Analizar solo Buenos Aires
python3 -m clients.network_cli --region "LA-Buenos Aires1" --verbose
```

### 3. Verificación de Compliance
```bash
# Recolección completa con análisis detallado
python3 -m clients.network_cli --verbose --output compliance_network_$(date +%Y%m%d).json
```

### 4. Re-análisis de Datos Existentes
```bash
# Analizar datos previamente recolectados
python3 -m clients.network_cli --analyze-only --input network_data_anterior.json
```

## 🔍 Interpretación de Resultados

### Severidades de Hallazgos
- 🔴 **CRITICAL**: Requiere acción inmediata (ej: puerto 22 abierto a 0.0.0.0/0)
- 🟠 **HIGH**: Remediar en 7-30 días (ej: rangos de red muy amplios)
- 🟡 **MEDIUM**: Remediar en 30-60 días (ej: VPCs sin uso)
- 🟢 **LOW**: Remediar en 60-90 días (ej: optimizaciones)

### Métricas Clave
- **Total VPCs**: Número de VPCs configuradas
- **Security Groups**: Grupos de seguridad y sus reglas
- **Exposed Resources**: Recursos accesibles desde internet
- **Critical Ports**: Puertos sensibles expuestos (22, 3389, 3306, etc.)

## 🛠️ Integración con el Assessment Completo

### Ejecución Coordinada con IAM
```bash
# Paso 1: Recolectar datos IAM
python3 -m clients.iam_cli --collect-only --output iam_data.json

# Paso 2: Recolectar datos de Red
python3 -m clients.network_cli --collect-only --output network_data.json

# Paso 3: Análisis combinado (si tienes un analizador conjunto)
python3 analyze_all.py --iam iam_data.json --network network_data.json
```

### Pipeline Automatizado
```bash
#!/bin/bash
# script: full_network_assessment.sh

echo "🔍 Iniciando Assessment de Red..."
python3 -m clients.network_cli \
  --verbose \
  --timeout 60 \
  --output "network_assessment_$(date +%Y%m%d_%H%M%S).json"

echo "✅ Assessment completado"
```

## 📝 Notas Importantes

1. **Multi-región**: El collector analiza automáticamente todas las regiones configuradas
2. **Inventario**: Basado en el inventario real de CAMUZZI (437 recursos en 5 regiones)
3. **Sin modificaciones**: Solo operaciones de lectura, no modifica recursos
4. **Hallazgos automáticos**: Detecta configuraciones inseguras según CIS Benchmarks

## 🐛 Troubleshooting

### Error: "No se pudo importar NetworkCollector"
```bash
# Verificar que estés en el directorio raíz del proyecto
cd /path/to/huawei-security-assessment
python3 -m clients.network_cli
```

### Error: "Credenciales no configuradas"
```bash
# Verificar variables de entorno
echo $HUAWEI_ACCESS_KEY
echo $HUAWEI_SECRET_KEY
```

### Error: "Timeout en región X"
```bash
# Aumentar timeout o skipear región problemática
python3 -m clients.network_cli --timeout 120 --skip-regions "CN-Hong Kong"
```

## 📚 Referencias

- [CIS Benchmarks for Cloud Security](https://www.cisecurity.org/)
- [NIST Cybersecurity Framework v2.0](https://www.nist.gov/cyberframework)
- [Huawei Cloud Security Best Practices](https://support.huaweicloud.com/intl/en-us/bestpractice-vpc/)

## 🤝 Soporte

Para dudas o problemas, contactar al equipo de seguridad o revisar los logs en:
- `logs/network_collector_*.log`
- `output/network_results_*.json`