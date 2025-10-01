# Imagen base de Python
FROM python:3.11-slim

# Crear directorio de trabajo
WORKDIR /app

# Copiar requirements y app
COPY requirements.txt .
COPY app.py .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Exponer puerto Flask
EXPOSE 5000

# Ejecutar la app
CMD ["python", "app.py"]
