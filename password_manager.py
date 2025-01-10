import re


def validate_input(username: str, password: str) -> bool:
    """
    Проверяет корректность ввода логина и пароля.

    param username: Логин пользователя.
    param password: Пароль пользователя.
    return: True, если ввод корректен, иначе False.
    """
    if not username or not password:
        print("Логин и пароль не могут быть пустыми.")
        return False
    if len(password) < 8:
        print("Пароль должен содержать минимум 8 символов.")
        return False
    if not re.match(r'[A-Za-z0-9@#$%^&+=]', password):
        print("Пароль должен содержать только латинские буквы, цифры и специальные символы.")
        return False
    return True