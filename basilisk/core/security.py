# basilisk/core/security.py
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Configuración por defecto recomendada por OWASP
ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Genera un hash Argon2 seguro."""
    return ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """
    Verifica una contraseña contra su hash Argon2.
    Devuelve True si coincide, False si no.
    """
    try:
        # verify() lanza excepción si falla, devuelve True si acierta
        return ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        # Captura cualquier otro error (hash mal formado, etc.)
        return False
