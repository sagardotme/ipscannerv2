import socket
import ssl
import json
from datetime import timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
import warnings

warnings.filterwarnings("ignore", message="Parsed a serial number which wasn't positive")
warnings.filterwarnings("ignore", message="Attribute's length must be")

def _get_name_values(name, oid):
    return [attr.value for attr in name.get_attributes_for_oid(oid)]


def _dt_iso(cert, attr_new, attr_old):
    """
    cryptography newer versions have *_utc fields.
    Older versions have naive datetime fields.
    """
    value = getattr(cert, attr_new, None)
    if value is not None:
        return value.isoformat()

    value = getattr(cert, attr_old)
    return value.replace(tzinfo=timezone.utc).isoformat()


def get_ssl_cert_for_ip(ip, port=443, sni=None, timeout=10):
    """
    ip: target IP, example: "13.202.56.119"
    sni: optional hostname for TLS SNI, example: "api.ivacbd.com"

    Important:
    - If sni=None, server may return its default certificate.
    - If sni="api.ivacbd.com", server may return certificate for api.ivacbd.com.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with context.wrap_socket(sock, server_hostname=sni) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            tls_version = ssock.version()
            cipher = ssock.cipher()

    cert = x509.load_der_x509_certificate(der_cert)

    subject_cn = _get_name_values(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _get_name_values(cert.issuer, NameOID.COMMON_NAME)
    issuer_org = _get_name_values(cert.issuer, NameOID.ORGANIZATION_NAME)

    dns_names = []
    ip_names = []

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value

        dns_names = san.get_values_for_type(x509.DNSName)
        ip_names = [str(x) for x in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass

    commonname = subject_cn[0] if subject_cn else None
    foundip = False
    if commonname == "*.ivacbd.com":
        foundip = True

    # Also check SAN DNS names if CN didn't match
    if not foundip:
        for name in dns_names:
            if name == "*.ivacbd.com":
                foundip = True
                break

    return foundip


def checkipssl(ip, timeout=10):
    try:
        info = get_ssl_cert_for_ip(ip, sni="api.ivacbd.com", timeout=timeout)
    except Exception:
        info = False
    return info
