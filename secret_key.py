# secret_key.py
# Chiave segreta condivisa tra server e client per cifratura messaggi segreti
# Deve essere lunga 32 byte per Fernet (AES)

from cryptography.fernet import Fernet

SHARED_KEY = b"3b0O0Q3KpYfX5S5KjX4ZsXvOwF7QF8oNn6j5nYpFqvA="

# Crea un oggetto Fernet pronto all’uso
CIPHER = Fernet(SHARED_KEY)