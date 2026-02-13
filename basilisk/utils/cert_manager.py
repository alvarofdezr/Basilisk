# basilisk/utils/cert_manager.py
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from basilisk.utils.logger import Logger


class CertManager:
    """
    Automated PKI Infrastructure.
    Generates self-signed X.509 certificates on the fly if missing.
    """

    def __init__(self, cert_dir: str = "certs"):
        self.logger = Logger()
        self.cert_dir = os.path.abspath(cert_dir)
        self.cert_path = os.path.join(self.cert_dir, "server_cert.pem")
        self.key_path = os.path.join(self.cert_dir, "server_key.pem")

    def ensure_certificates(self) -> tuple[str, str]:
        """
        Checks for existing certificates. Generates new ones if missing.
        Returns tuple (cert_path, key_path).
        """
        if not os.path.exists(self.cert_dir):
            os.makedirs(self.cert_dir)
            self.logger.info(f"📁 Created certificate directory: {self.cert_dir}")

        if not os.path.exists(self.cert_path) or not os.path.exists(self.key_path):
            self.logger.warning("⚠️ SSL Certificates missing. Generating new PKI identity...")
            self._generate_self_signed_cert()
        else:
            self.logger.success("✅ SSL Certificates found.")

        return self.cert_path, self.key_path

    def _generate_self_signed_cert(self):
        # 1. Generate Private Key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        # 2. Generate Certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Seville"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Basilisk Lab"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Basilisk C2"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Valid for 5 years
            datetime.datetime.utcnow() + datetime.timedelta(days=365 * 5)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(key, hashes.SHA256())

        # 3. Save to Disk
        with open(self.key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(self.cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        self.logger.success(f"🔐 New SSL Identity generated at: {self.cert_dir}")
