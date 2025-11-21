# Ejemplo de cómo hacer un login y ver los permisos

import requests

# URL del servidor
url = "http://localhost:8000/api/login"

# Datos de login
data = {
    "username": "carlos",  # Cambia por tu usuario
    "password": "tu_password"  # Cambia por tu contraseña
}

# Hacer la petición
response = requests.post(url, json=data)

# Ver la respuesta
print("Status:", response.status_code)
print("\nRespuesta completa:")
print(response.json())
