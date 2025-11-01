<div align="center">
   <h1>🛡️ POC para Uso de MITRE ATT&CK para Mapear Técnicas de Ransomware</h1>
   <p>Simulación y detección de técnicas de ransomware usando MITRE ATT&CK y Caldera</p>
</div>

---

## 📋 Propósito

Este proyecto es un Proof of Concept (POC) que busca demostrar cómo la integración de la matriz MITRE ATT&CK y la plataforma Caldera permite mapear, analizar y detectar técnicas empleadas por ransomware en entornos simulados. El objetivo es facilitar la comprensión de los patrones de ataque y fortalecer la defensa en ciberseguridad.

## 🏗️ Estructura del Proyecto

```
README.md
├── dashboard/
│   ├── app.py
│   ├── details.html
│   └── templates/
│       └── details.html
├── data/
│   ├── events.json
│   ├── events1.json
│   ├── events2.json
│   └── events3.json
├── db/
│   └── attacks.db.README.txt
├── scripts/
│   ├── create_mapped_db.py
│   └── detector.py
```

- **dashboard/**: Aplicación web para visualizar eventos, técnicas y alertas.
- **data/**: Archivos JSON con eventos simulados generados por Caldera.
- **db/**: Base de datos ligera para almacenar el mapeo de eventos y técnicas.
- **scripts/**: Scripts para procesar, mapear y detectar secuencias de TTPs.

## 🚀 Ejecución Rápida

1. **Instala las dependencias**
   ```bash
   pip install -r requirements.txt
   ```

2. **Genera la base de datos mapeada**
   ```bash
   python scripts/create_mapped_db.py
   ```

3. **Ejecuta el detector de TTPs**
   ```bash
   python scripts/detector.py
   ```

4. **Inicia el dashboard web**
   ```bash
   python dashboard/app.py
   ```
   Accede a la interfaz en tu navegador en `http://localhost:5000`

## 🧩 ¿Cómo funciona?

- Los eventos simulados se generan con Caldera y se almacenan en archivos JSON.
- Los scripts procesan estos eventos, los mapean a técnicas ATT&CK y los guardan en la base de datos.
- El detector analiza la base de datos en busca de secuencias de TTPs y genera alertas.
- El dashboard permite visualizar los resultados y explorar los patrones de ataque.

## 🔬 Tecnologías principales
- Python
- Flask
- Pandas
- SQLite
- Caldera (para simulación de ataques)

## 📚 Más información
- [Repositorio de Caldera](https://github.com/mitre/caldera)
- [MITRE ATT&CK](https://attack.mitre.org/)

## 📦 Repositorio

Todo el código fuente y documentación está disponible en:

https://github.com/CamiloQuinteroR/ransom-lab.git

---

<div align="center">
   <em>Desarrollado por el equipo de Ransom-Lab para fines educativos y de investigación.</em>
</div>

---

## 👥 Autores

- Camilo Andrés Quintero Rodríguez
- Juan Sebastián Velásquez Rodríguez
- Santiago Díaz Rojas

Estudiantes de Ingeniería de Sistemas, Escuela Colombiana de Ingeniería Julio Garavito.

Este POC fue desarrollado como parte del seminario de Seguridad Informática.

---

## 🎥 Video Explicativo

En este [video explicativo](https://youtu.be/dtboGRp4xXQ) se detalla el funcionamiento del POC, incluyendo cómo se detectan las técnicas de ransomware y cómo se visualizan los resultados en el dashboard.
