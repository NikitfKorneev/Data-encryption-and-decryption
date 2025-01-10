import os
from encryption import generate_key, encrypt_data, decrypt_data
from password_manager import validate_input
import getpass


def encrypt_operation():
    """
    Выполняет операцию шифрования данных.
    Запрашивает у пользователя логин и пароль, генерирует ключ для шифрования,
    затем шифрует данные с использованием AES и выводит зашифрованные данные.
    После этого расшифровывает данные и проверяет их корректность.
    """
    print("Вы выбрали шифрование данных.")

    username = input("Введите ваш логин: ")
    password = getpass.getpass("Введите ваш пароль: ")

    if not validate_input(username, password):
        return

    key_length = int(input("Введите длину ключа AES (16, 24 или 32 байта): "))
    if key_length not in [16, 24, 32]:
        print("Недопустимая длина ключа! Используйте 16, 24 или 32 байта.")
        return

    key = generate_key(key_length)
    print(f"Сгенерированный ключ: {key.hex()}")

    encrypted_username = encrypt_data(key, username)
    encrypted_password = encrypt_data(key, password)

    print(f"Зашифрованный логин: {encrypted_username.hex()}")
    print(f"Зашифрованный пароль: {encrypted_password.hex()}")

    decrypted_username = decrypt_data(key, encrypted_username)
    decrypted_password = decrypt_data(key, encrypted_password)

    if decrypted_username == username and decrypted_password == password:
        print("\nУспешная проверка: логин и пароль верны после расшифровки.")
    else:
        print("\nОшибка: данные после расшифровки не совпадают с исходными!")


def decrypt_operation():
    """
    Выполняет операцию расшифровки данных.
    Запрашивает у пользователя зашифрованные данные (в шестнадцатеричном формате),
    затем расшифровывает их с использованием AES и выводит расшифрованные данные.
    """
    print("Вы выбрали расшифровку данных.")

    encrypted_username_hex = input("Введите зашифрованный логин (в шестнадцатеричном формате): ")
    encrypted_password_hex = input("Введите зашифрованный пароль (в шестнадцатеричном формате): ")

    try:
        encrypted_username = bytes.fromhex(encrypted_username_hex)
        encrypted_password = bytes.fromhex(encrypted_password_hex)
    except ValueError:
        print("Неверный формат данных! Используйте только шестнадцатеричные символы.")
        return

    key_length = int(input("Введите длину ключа AES (16, 24 или 32 байта): "))
    if key_length not in [16, 24, 32]:
        print("Недопустимая длина ключа! Используйте 16, 24 или 32 байта.")
        return

    key_hex = input(f"Введите ваш ключ (в шестнадцатеричном формате, длина {key_length} байт): ")
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        print("Неверный формат ключа! Используйте только шестнадцатеричные символы.")
        return

    if len(key) != key_length:
        print(f"Некорректная длина ключа. Ожидается {key_length} байт.")
        return

    try:
        decrypted_username = decrypt_data(key, encrypted_username)
        decrypted_password = decrypt_data(key, encrypted_password)

        print(f"Расшифрованный логин: {decrypted_username}")
        print(f"Расшифрованный пароль: {decrypted_password}")
    except Exception as e:
        print(f"Ошибка расшифровки данных: {e}")


def exit_program():
    """
    Завершает выполнение программы.
    """
    print("Выход из программы.")
    exit()


def main():
    """
    Основная функция программы, которая предоставляет меню для выбора действий.
    Пользователь может выбрать одно из следующих действий: шифрование данных,
    расшифровка данных или выход из программы.
    """
    print("Добро пожаловать в систему шифрования!")

    actions = {
        '1': encrypt_operation,
        '2': decrypt_operation,
        '3': exit_program
    }

    while True:
        print("\nЧто вы хотите сделать?")
        print("1. Зашифровать данные")
        print("2. Расшифровать данные")
        print("3. Выйти")

        choice = input("Введите номер операции (1, 2 или 3): ")

        action = actions.get(choice)
        if action:
            action()
        else:
            print("Ошибка: введите корректный номер операции (1, 2 или 3). Попробуйте снова.")


if __name__ == "__main__":
    main()
