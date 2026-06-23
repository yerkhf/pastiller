# CUTSA - Pastillero Inteligente Local

Versión simple en Streamlit + SQLite. No usa Firebase, Vercel ni Mailtrap.

## Funciones

- Registro e inicio de sesión local.
- Perfil de cliente/farmacia.
- CRUD de medicamentos.
- CRUD de horarios.
- Gestión de mensajes y respuestas.
- Simulación de concentración de medicamento con derivadas.

## Instalación

```bash
pip install -r requirements.txt
```

## Ejecución

```bash
streamlit run app.py
```

Luego abre el enlace que aparece en la terminal, normalmente:

```text
http://localhost:8501
```

## Usuario demo

Al abrir la app puedes crear un usuario demo desde la pantalla de inicio:

- Correo: demo@farmacia.cl
- Contraseña: 12345678

## Modelo matemático

La concentración se modela con:

```text
C(t)=C0 e^(-kt)
```

Su derivada es:

```text
C'(t)=-kC0 e^(-kt)
```

La derivada representa la velocidad con la que disminuye la concentración del medicamento.

## Aviso

Este proyecto es educativo y no entrega indicaciones médicas reales.
