SMSec: Sistema de Mensajería Segura
---


Pasos para ejecutarlo:

1. Crear la imagen:

```docker build . -t smsec```

2. Crear el contenedor:

```docker run -p 5000:5000 smsec```

3. Acceder a la app en el navegador

```curl http://localhost:5000/```


# PK

1. Generar PKI

```venv/bin/python pki.py```

2. Verificar PKI

```venv/bin/python test_pki.py```