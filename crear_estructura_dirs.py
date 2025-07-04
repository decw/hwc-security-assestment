
import os

# Estructura de directorios y archivos
structure = {
    "config": ["__init__.py", "settings.py", "constants.py"],
    "collectors": [
        "__init__.py", "iam_collector.py", "network_collector.py",
        "storage_collector.py", "monitoring_collector.py", "compliance_collector.py"
    ],
    "analyzers": ["__init__.py", "risk_analyzer.py", "vulnerability_analyzer.py"],
    "utils": ["__init__.py", "logger.py", "report_generator.py"],
    ".": ["main.py", "requirements.txt", "README.md"]
}

# Crear carpetas y archivos
for folder, files in structure.items():
    if folder != ".":
        os.makedirs(folder, exist_ok=True)
    for file in files:
        path = os.path.join(folder, file) if folder != "." else file
        with open(path, 'w') as f:
            if file == "__init__.py":
                f.write("# Package initializer\n")
            elif file.endswith(".py"):
                f.write(f"# {file.replace('_', ' ').title().replace('.Py', '')}\n")
            elif file == "README.md":
                f.write("# Proyecto de Análisis de Seguridad en la Nube\n")
            elif file == "requirements.txt":
                f.write("# Agrega tus dependencias aquí\n")

print("Estructura creada correctamente.")

