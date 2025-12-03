
import datetime
from datetime import timezone
import os
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import shutil


def setup_pki():
    """
    Inicializa la PKI ejecutando los scripts OpenSSL necesarios.
    Crea los archivos necesarios para que los tests funcionen.
    """
    # Obtener el directorio base del proyecto (donde están los scripts)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Copiar archivos de configuración al directorio de trabajo actual
    # necesario para que los tests funcionen en directorios temporales
    os.makedirs("pki", exist_ok=True)
    config_files = ["ca-root.cnf", "ca-intermediate.cnf"]
    for config_file in config_files:
        src = os.path.join(script_dir, "pki", config_file)
        dst = os.path.join("pki", config_file)
        if os.path.exists(src) and not os.path.exists(dst):
            shutil.copy(src, dst)
    
    # Ejecutar create_root_ca.sh
    root_script = os.path.join(script_dir, "create_root_ca.sh")
    if os.path.exists(root_script):
        result = subprocess.run(
            ["bash", root_script],
            cwd=os.getcwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if result.returncode != 0:
            raise RuntimeError(f"Error ejecutando create_root_ca.sh: {result.stderr.decode()}")
    else:
        # Si no existe el script, crear la estructura mínima manualmente
        os.makedirs("pki/root/private", exist_ok=True)
        os.makedirs("pki/root/certs", exist_ok=True)
        os.makedirs("pki/root/newcerts", exist_ok=True)
        if not os.path.exists("pki/root/index.txt"):
            open("pki/root/index.txt", "w").close()
        if not os.path.exists("pki/root/serial"):
            with open("pki/root/serial", "w") as f:
                f.write("1000")
        
        # Generar Root CA
        subprocess.run(
            ["openssl", "genrsa", "-out", "pki/root/private/root.key.pem", "4096"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        config_path = os.path.join(script_dir, "pki", "ca-root.cnf")
        subprocess.run(
            ["openssl", "req", "-config", config_path,
             "-key", "pki/root/private/root.key.pem",
             "-new", "-x509", "-days", "3650", "-sha256", "-extensions", "v3_ca",
             "-batch", "-out", "pki/root/certs/root.cert.pem"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    
    # Ejecutar create_intermediate_ca.sh
    inter_script = os.path.join(script_dir, "create_intermediate_ca.sh")
    if os.path.exists(inter_script):
        result = subprocess.run(
            ["bash", inter_script],
            cwd=os.getcwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if result.returncode != 0:
            raise RuntimeError(f"Error ejecutando create_intermediate_ca.sh: {result.stderr.decode()}")
    else:
        # Si no existe el script, crear la estructura mínima manualmente
        os.makedirs("pki/intermediate/private", exist_ok=True)
        os.makedirs("pki/intermediate/certs", exist_ok=True)
        os.makedirs("pki/intermediate/newcerts", exist_ok=True)
        os.makedirs("pki/intermediate/crl", exist_ok=True)
        if not os.path.exists("pki/intermediate/index.txt"):
            open("pki/intermediate/index.txt", "w").close()
        if not os.path.exists("pki/intermediate/serial"):
            with open("pki/intermediate/serial", "w") as f:
                f.write("1000")
        if not os.path.exists("pki/intermediate/crlnumber"):
            with open("pki/intermediate/crlnumber", "w") as f:
                f.write("1000")
        
        # Generar Intermediate CA
        subprocess.run(
            ["openssl", "genrsa", "-out", "pki/intermediate/intermediate.key", "4096"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        inter_config_path = os.path.join(script_dir, "pki", "ca-intermediate.cnf")
        root_config_path = os.path.join(script_dir, "pki", "ca-root.cnf")
        
        # Generar CSR
        subprocess.run(
            ["openssl", "req", "-config", inter_config_path, "-new", "-sha256", "-batch",
             "-key", "pki/intermediate/intermediate.key",
             "-out", "pki/intermediate/intermediate.csr"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Firmar con Root CA
        subprocess.run(
            ["openssl", "ca", "-config", root_config_path, "-extensions", "v3_intermediate_ca",
             "-days", "1825", "-notext", "-md", "sha256",
             "-in", "pki/intermediate/intermediate.csr",
             "-out", "pki/intermediate/intermediate.crt",
             "-batch"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Generar CRL inicial
        subprocess.run(
            ["openssl", "ca", "-config", inter_config_path, "-gencrl",
             "-out", "pki/intermediate/crl.pem"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    
    # Copiar archivos a los nombres que esperan los tests (si existen)
    if os.path.exists("pki/root/certs/root.cert.pem"):
        shutil.copy("pki/root/certs/root.cert.pem", "root_ca.crt")
    if os.path.exists("pki/intermediate/intermediate.crt"):
        shutil.copy("pki/intermediate/intermediate.crt", "intermediate_ca.crt")
    if os.path.exists("pki/intermediate/intermediate.key"):
        shutil.copy("pki/intermediate/intermediate.key", "intermediate_ca.key")
    if os.path.exists("pki/intermediate/crl.pem"):
        shutil.copy("pki/intermediate/crl.pem", "intermediate_ca.crl")


def load_certificate(filename):
    """Carga un certificado desde un archivo PEM."""
    with open(filename, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def generate_csr(private_key, common_name):
    """
    Genera una CSR para un usuario.
    """
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Mi Organizacion"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(private_key, hashes.SHA256())
    return csr

def issue_certificate(username, csr_pem):
    """
    Emite un certificado de usuario delegando TODA la lógica en OpenSSL (`openssl ca`).

    - Usa la CA intermedia definida en `pki/ca-intermediate.cnf`.
    - Registra el certificado en la base de datos OpenSSL (pki/intermediate/index.txt).
    - Genera el fichero de salida `certs/<username>.crt`.

    Args:
        username (str): Nombre de usuario (se usa solo para el nombre del fichero).
        csr_pem (bytes): CSR en formato PEM.

    Returns:
        bytes: Certificado emitido en formato PEM.
    """
    # Verificar que la PKI OpenSSL existe
    inter_key_path = "pki/intermediate/intermediate.key"
    inter_cert_path = "pki/intermediate/intermediate.crt"
    inter_conf_path = "pki/ca-intermediate.cnf"

    for path in [inter_key_path, inter_cert_path, inter_conf_path]:
        if not os.path.exists(path):
            raise RuntimeError(
                f"Infraestructura PKI incompleta. Falta '{path}'. "
                "Inicializa la PKI ejecutando los scripts OpenSSL (create_root_ca.sh, create_intermediate_ca.sh)."
            )

    # Guardar CSR temporalmente en pki/users/
    os.makedirs("pki/users", exist_ok=True)
    csr_path = os.path.join("pki", "users", f"{username}.csr.pem")
    with open(csr_path, "wb") as f:
        f.write(csr_pem)

    # Asegurar directorio de certificados de aplicación
    os.makedirs("certs", exist_ok=True)
    cert_path = os.path.join("certs", f"{username}.crt")

    # Invocar OpenSSL CA intermedia
    # Nota: la configuración de extensiones, días de validez, etc. se controla desde ca-intermediate.cnf
    cmd = [
        "openssl", "ca",
        "-config", inter_conf_path,
        "-in", csr_path,
        "-out", cert_path,
        "-batch",
    ]

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        error_msg = result.stderr.decode("utf-8", errors="ignore")
        raise RuntimeError(f"Error al emitir certificado con OpenSSL: {error_msg}")

    # Leer certificado emitido
    with open(cert_path, "rb") as f:
        cert_pem = f.read()

    # Registrar en log propio de la app (además del índice OpenSSL)
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        serial_number = cert.serial_number
    except Exception:
        serial_number = "UNKNOWN"

    with open("issued_certs.log", "a") as log:
        log.write(
            f"{serial_number},{datetime.datetime.now(timezone.utc).isoformat()},{username},Valid\n"
        )

    return cert_pem

def revoke_certificate(serial):
    """
    Revoca un certificado usando exclusivamente OpenSSL:

    - Llama a `openssl ca -revoke` con la CA intermedia.
    - Regenera la CRL oficial con `openssl ca -gencrl` en `pki/intermediate/crl.pem`.

    Args:
        serial (int): Número de serie del certificado a revocar.

    Returns:
        bool: True si la revocación fue exitosa.
    """
    inter_conf_path = "pki/ca-intermediate.cnf"
    crl_path = "pki/intermediate/crl.pem"

    if not os.path.exists(inter_conf_path):
        raise RuntimeError(
            "No se encontró la configuración de la CA intermedia (pki/ca-intermediate.cnf). "
            "Asegúrate de inicializar la PKI con los scripts OpenSSL."
        )

    # Buscar el certificado en el directorio certs/ por su número de serie
    cert_path = None
    if os.path.isdir("certs"):
        for filename in os.listdir("certs"):
            if not filename.endswith(".crt"):
                continue
            full_path = os.path.join("certs", filename)
            try:
                cert = load_certificate(full_path)
                if cert.serial_number == serial:
                    cert_path = full_path
                    break
            except Exception:
                continue

    if cert_path is None:
        # Certificado no encontrado, retornar False en lugar de lanzar excepción
        print(f"Advertencia: No se encontró ningún certificado con el número de serie {serial}")
        return False

    # 1) Revocar en la base de datos OpenSSL
    cmd_revoke = [
        "openssl", "ca",
        "-config", inter_conf_path,
        "-revoke", cert_path,
        "-batch",
    ]
    result_revoke = subprocess.run(
        cmd_revoke,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result_revoke.returncode != 0:
        error_msg = result_revoke.stderr.decode("utf-8", errors="ignore")
        raise RuntimeError(f"Error al revocar certificado con OpenSSL: {error_msg}")

    # 2) Regenerar CRL oficial
    cmd_crl = [
        "openssl", "ca",
        "-config", inter_conf_path,
        "-gencrl",
        "-out", crl_path,
        "-batch",
    ]
    result_crl = subprocess.run(
        cmd_crl,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result_crl.returncode != 0:
        error_msg = result_crl.stderr.decode("utf-8", errors="ignore")
        raise RuntimeError(f"Error al generar CRL con OpenSSL: {error_msg}")

    # Actualizar log de la aplicación (si existe el serial)
    if os.path.exists("issued_certs.log"):
        lines = []
        with open("issued_certs.log", "r") as f:
            for line in f:
                parts = line.strip().split(",")
                if not parts:
                    continue
                if str(parts[0]) == str(serial):
                    # Marcar como Revoked
                    if len(parts) >= 4:
                        parts[3] = "Revoked"
                        line = ",".join(parts) + "\n"
                lines.append(line)
        with open("issued_certs.log", "w") as f:
            f.writelines(lines)

    print(f"Certificado con serial {serial} revocado exitosamente (OpenSSL CA).")
    return True

def is_revoked(cert_pem):
    """
    Verifica si un certificado está revocado usando EXCLUSIVAMENTE la CRL OpenSSL.

    Args:
        cert_pem (bytes): Certificado en formato PEM.

    Returns:
        bool: True si el certificado está revocado, False en caso contrario.
    """
    crl_path = "pki/intermediate/crl.pem"

    try:
        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
    except FileNotFoundError:
        # Si no existe la CRL oficial, asumimos que no hay certificados revocados todavía
        return False

    # Parsear el certificado
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:
        raise ValueError(f"Certificado PEM inválido: {e}")

    # Verificar si el número de serie está en la CRL
    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    return revoked is not None


if __name__ == "__main__":
    raise SystemExit(
        "Este módulo ya no inicializa la PKI.\n"
        "Usa los scripts OpenSSL 'create_root_ca.sh' y 'create_intermediate_ca.sh' "
        "para crear la PKI en pki/root y pki/intermediate."
    )
