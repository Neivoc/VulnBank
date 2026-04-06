# 🏦 VulnBank

**VulnBank** es una aplicación web bancaria deliberadamente vulnerable, construida con fines educativos y para la práctica de pruebas de penetración (*pentesting*). Simula una aplicación web moderna y realista con una elegante interfaz SPA (*Single Page Application*) utilizando *Dark Glassmorphism*, mientras que de forma intencional implementa prácticas de seguridad terribles en el *backend*.

⚠️ **ADVERTENCIA:** Esta aplicación es explícitamente vulnerable y **nunca** debe ser desplegada en producción ni ser accesible a través de internet público. Úsala únicamente en entornos locales y aislados con fines educativos.

---

## 🚀 Inicio Rápido

La forma más sencilla de ejecutar VulnBank es a través de Docker:

```bash
# Clonar el repositorio
git clone https://github.com/Neivoc/VulnBank.git
cd VulnBank

# Construir e iniciar el contenedor
docker compose up --build -d
```

La aplicación estará accesible en: `http://localhost:4000`

### Cuentas por Defecto
| Username | Password | Role |
|----------|----------|------|
| `admin`  | `admin123` | Administrator |
| `carlos` | `carlos123`| Standard User |
| `maria`  | `maria123` | Standard User |

*(Nota: ¡También puedes registrar tu propio usuario personalizado directamente desde la página de inicio de sesión!)*

---

## 🎯 Mapeo de Vulnerabilidades

VulnBank contiene **8 vulnerabilidades** específicas para descubrir y explotar. Para hacer que el desafío sea más realista, no existen "pruebas" o pistas visuales explícitas en la interfaz; debes encontrarlas de la misma forma en la que lo harías en un *pentest* real.

1. **JWT Tampering (Signature Bypass):** La lógica de JWT está configurada de manera deficiente y acepta el *payload* a ciegas utilizando `jwt.decode()` en lugar de validar correctamente la firma criptográfica (no hace `jwt.verify()`). ¡Se pueden escalar privilegios sin necesidad de conocer la llave secreta (*secret key*)!
2. **User Enumeration:** Los *endpoints* de inicio de sesión y registro exponen mensajes de error demasiado específicos, lo cual revela fácilmente si una cuenta existe o no en el sistema.
3. **Insecure Direct Object Reference (IDOR):** Alterar los IDs directamente en las peticiones a la API o manipular las *URLs* internas como `/profile/1` te permitirá leer los datos sensibles de otros usuarios sin ser bloqueado por controles de autorización.
4. **Information Disclosure:** El *endpoint* `/api/debug` fue expuesto por error sin requerir autenticación. Esto provoca una fuga de información interna crítica (como los *tokens*, esquemas de la base de datos y llaves secretas).
5. **SQL Injection (SQLi):** El buscador de transacciones inyecta los *strings* directamente en las consultas de SQLite en lugar de emplear *parameterized queries*.
6. **Sensitive Data in Local Storage:** Parámetros de sesión enteros, el rol real del usuario e incluso el token JWT puro se almacenan de manera insegura en el `localStorage` del navegador.
7. **Stored XSS:** La aplicación confía por completo en el *input* del usuario (como mensajes de tickets de soporte o descripciones de transferencias), almacenándolos tal cual en la base de datos y renderizándolos sin sanitizar directamente en el DOM.
8. **Insecure File Upload (Client-Side Check Bypass):** El cargador de avatares cuenta con una supuesta capa de seguridad Frontend en Javascript que limita los archivos a PNG/JPG. Sin embargo, el *backend* descarta por completo la validación del tipo de archivo, permitiendo subir código remoto como archivos `.html` o `.js` simplemente interceptando la petición (*request*) o mediante cURL.

---

## 💻 Tech Stack
* **Backend:** Node.js, Express.js
* **Database:** SQLite3
* **Frontend:** Vanilla HTML/CSS/JS (Dark Glassmorphism Theme)

¡Disfruta del Hacking! 🧑‍💻
