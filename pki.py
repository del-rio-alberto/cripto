
import datetime
from datetime import timezone
import os
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID




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
        raise ValueError(f"No se encontró ningún certificado en 'certs/' con el número de serie {serial}")

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
