from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os


def generate_key(key_length: int) -> bytes:
    """
    Генерирует случайный ключ заданной длины для алгоритма AES.

    param key_length: Длина ключа в байтах (должна быть 16, 24 или 32).
    return: Сгенерированный ключ.
    """
    return os.urandom(key_length)


def encrypt_data(key: bytes, data: str) -> bytes:
    """
    Шифрует данные с использованием алгоритма AES в режиме CBC.

    param key: Ключ шифрования AES.
    param data: Данные для шифрования.
    return: Зашифрованные данные.
    """
    data_bytes = data.encode('utf-8')

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data_bytes) + padder.finalize()

    iv = os.urandom(16) 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_data 

def decrypt_data(key: bytes, encrypted_data: bytes) -> str:
    """
    Расшифровывает данные с использованием алгоритма AES в режиме CBC.

    param key: Ключ шифрования AES.
    param encrypted_data: Зашифрованные данные.
    return: Расшифрованные данные в виде строки.
    """
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode('utf-8')
