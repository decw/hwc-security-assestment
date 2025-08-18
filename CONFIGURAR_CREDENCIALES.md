# 🔑 Configuración de Credenciales Huawei Cloud

## ❌ **Problema Actual**
El sistema no puede acceder a las credenciales de Huawei Cloud porque no están configuradas correctamente.

```
WARNING: Credenciales de Huawei Cloud no configuradas.
Por favor, configure las variables en el archivo .env
```

## ✅ **Solución: Configurar archivo .env**

### **Paso 1: Crear archivo .env**
```bash
cp .env.template .env
```

### **Paso 2: Editar el archivo .env con las credenciales reales**
```bash
nano .env
# o usar cualquier editor de texto
```

### **Paso 3: Completar con las credenciales**
```bash
# Archivo: .env
HUAWEI_ACCESS_KEY=AKIA*********************
HUAWEI_SECRET_KEY=****************************************
HUAWEI_PROJECT_ID=07c695df*********************
HUAWEI_DOMAIN_ID=77aed4ae*********************

# Región principal
HUAWEI_PRIMARY_REGION=sa-argentina-1

# Configuración opcional
LOG_LEVEL=INFO
```

## 🔍 **¿Dónde encontrar las credenciales?**

### **En la Consola de Huawei Cloud:**
1. **Access Key & Secret Key**:
   - Ir a: `My Credentials` → `Access Keys`
   - Crear nuevo Access Key si es necesario
   - **IMPORTANTE**: Guardar el Secret Key cuando se crea (solo se muestra una vez)

2. **Domain ID**:
   - Ir a: `My Credentials` → `API Credentials`
   - Copiar el `Domain ID`

3. **Project ID**:
   - Ir a: `My Credentials` → `API Credentials` 
   - Seleccionar el proyecto/región deseada
   - Copiar el `Project ID`

## 🛠️ **Alternativa: Variables de Entorno del Sistema**

Si prefieres no usar archivo .env, puedes configurar las variables directamente:

```bash
# Configurar para la sesión actual
export HUAWEI_ACCESS_KEY="tu_access_key"
export HUAWEI_SECRET_KEY="tu_secret_key"
export HUAWEI_PROJECT_ID="tu_project_id"
export HUAWEI_DOMAIN_ID="tu_domain_id"

# Para que persistan, agregar al ~/.bashrc o ~/.profile
echo 'export HUAWEI_ACCESS_KEY="tu_access_key"' >> ~/.bashrc
echo 'export HUAWEI_SECRET_KEY="tu_secret_key"' >> ~/.bashrc
echo 'export HUAWEI_PROJECT_ID="tu_project_id"' >> ~/.bashrc
echo 'export HUAWEI_DOMAIN_ID="tu_domain_id"' >> ~/.bashrc
```

## ✅ **Verificar Configuración**

Después de configurar las credenciales, verifica que funcionen:

```bash
# Verificar que las variables se cargan
python3 -c "
from config.settings import HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY, HUAWEI_DOMAIN_ID
print(f'Access Key: {HUAWEI_ACCESS_KEY[:10]}***' if HUAWEI_ACCESS_KEY else 'No configurado')
print(f'Secret Key: {HUAWEI_SECRET_KEY[:10]}***' if HUAWEI_SECRET_KEY else 'No configurado')  
print(f'Domain ID: {HUAWEI_DOMAIN_ID[:10]}***' if HUAWEI_DOMAIN_ID else 'No configurado')
"

# Probar recolección básica
python3 -m clients.iam_cli --check-users-only --no-confirm
```

## 🔒 **Seguridad de Credenciales**

### **IMPORTANTE - Buenas Prácticas:**

1. **Nunca subir credenciales al repositorio**
   ```bash
   # Verificar que .env está en .gitignore
   cat .gitignore | grep .env
   ```

2. **Permisos restrictivos al archivo .env**
   ```bash
   chmod 600 .env
   ```

3. **Rotar credenciales periódicamente**
   - Crear nuevas Access Keys cada 90 días
   - Eliminar las antiguas después de actualizar

4. **Usar credenciales con permisos mínimos**
   - Solo los permisos necesarios para el assessment
   - Evitar credenciales de administrador completo

## 🚨 **Troubleshooting**

### **Error: "No module named 'dotenv'"**
```bash
pip install python-dotenv
```

### **Error: "Permission denied"**
```bash
# Verificar permisos del archivo .env
ls -la .env
# Debe mostrar: -rw------- (600)
```

### **Las credenciales siguen sin funcionar**
```bash
# Verificar que no hay espacios extra
cat .env | sed 's/^/[/' | sed 's/$/]/'

# Verificar que no hay caracteres especiales
file .env
```

## 📞 **Contacto para Soporte**

Si sigues teniendo problemas:
1. Verificar que tienes las credenciales correctas de Huawei Cloud
2. Contactar al administrador de la cuenta Huawei Cloud
3. Revisar los logs en `logs/` para errores específicos

---

**Próximo paso**: Una vez configuradas las credenciales, podrás ejecutar:
```bash
python3 -m clients.iam_cli --no-confirm
```
