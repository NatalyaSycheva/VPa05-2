import os
import sqlite3
import hashlib
import string
import secrets
from cryptography.fernet import Fernet

# --- 1. Класс DatabaseManager ---
class DatabaseManager:
    """Отвечает за взаимодействие с базой данных SQLite3."""
    def __init__(self, db_name="passwords.db"):
        self.db_name = db_name
        self.init_database()

    def init_database(self):
        """Инициализирует таблицы в базе данных."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            # Таблица для мастер-пароля (хранит только хэш)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS master (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_hash TEXT NOT NULL
                )
            """)
            # Таблица для зашифрованных аккаунтов
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    login TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL
                )
            """)
            conn.commit()

    def get_master_password(self):
        """Возвращает хэш мастер-пароля, если он существует."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM master LIMIT 1")
            row = cursor.fetchone()
            return row if row else None

    def set_master_password(self, password_hash):
        """Устанавливает хэш мастер-пароля при первом запуске."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO master (password_hash) VALUES (?)", (password_hash,))
            conn.commit()

    def add_password(self, name, login, encrypted_password):
        """Добавляет новую запись или обновляет существующую."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO credentials (name, login, encrypted_password)
                VALUES (?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET 
                    login=excluded.login, 
                    encrypted_password=excluded.encrypted_password
            """, (name, login, encrypted_password))
            conn.commit()

    def get_password(self, name):
        """Возвращает логин и зашифрованный пароль по названию сервиса."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT login, encrypted_password FROM credentials WHERE name = ?", (name,))
            return cursor.fetchone()

    def list_passwords(self):
        """Возвращает список всех записей (название и логин)."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, login FROM credentials ORDER BY name ASC")
            return cursor.fetchall()

    def delete_password(self, name):
        """Удаляет запись по названию сервиса. Возвращает True, если удалено успешно."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM credentials WHERE name = ?", (name,))
            conn.commit()
            return cursor.rowcount > 0


# --- 2. Класс EncryptionManager ---
class EncryptionManager:
    """Управляет шифрованием и дешифрованием через Fernet."""
    def __init__(self, key_file=".key"):
        self.key_file = key_file
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)

    def _load_or_generate_key(self):
        """Считывает или генерирует секретный ключ шифрования локально."""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            return key

    def encrypt(self, plain_text):
        """Зашифровывает строку текста."""
        return self.cipher.encrypt(plain_text.encode('utf-8')).decode('utf-8')

    def decrypt(self, cipher_text):
        """Расшифровывает строку обратно в читаемый вид."""
        return self.cipher.decrypt(cipher_text.encode('utf-8')).decode('utf-8')

# --- 3. Класс PasswordGenerator (Основной CLI) ---
class PasswordGenerator:
    """Отвечает за генерацию надежных паролей и интерфейс пользователя."""
    def __init__(self):
        self.db = DatabaseManager()
        self.crypto = EncryptionManager()

    def _clean_input(self, text):
        """Гарантированно удаляет любые скрытые символы Windows/Linux из ввода."""
        if not text:
            return ""
        return text.replace("\r", "").replace("\n", "").strip()

    def _hash_password(self, password):
        """Вычисляет SHA-256 хэш строго очищенной строки."""
        cleaned = self._clean_input(password)
        return hashlib.sha256(cleaned.encode('utf-8')).hexdigest()

    def setup_master_password(self):
        """Запрашивает установку мастер-пароля, если база чистая."""
        stored_hash = self.db.get_master_password()
        if not stored_hash:
            print("=== ПЕРВЫЙ ЗАПУСК: Создание мастер-пароля ===")
            while True:
                pwd = input("Придумайте надежный мастер-пароль для входа: ")
                confirm = input("Повторите мастер-пароль: ")
                
                pwd_cleaned = self._clean_input(pwd)
                confirm_cleaned = self._clean_input(confirm)
                
                if not pwd_cleaned:
                    print("Пароль не может быть пустым!")
                    continue
                if pwd_cleaned == confirm_cleaned:
                    new_hash = self._hash_password(pwd_cleaned)
                    # Сохраняем строку хэша напрямую
                    self.db.set_master_password(new_hash)
                    print("Мастер-пароль успешно установлен и сохранен!\n")
                    break
                print("Пароли не совпадают. Попробуйте снова.")

    def authenticate(self):
        """Требует ввод мастер-пароля для авторизации."""
        stored_hash_row = self.db.get_master_password()
        # Извлекаем чистую строку хэша из кортежа БД
        stored_hash = stored_hash_row[0] if stored_hash_row else None
        
        attempts = 3
        while attempts > 0:
            pwd = input("Введите мастер-пароль для входа: ")
            pwd_cleaned = self._clean_input(pwd)
            current_hash = self._hash_password(pwd_cleaned)
            
            if current_hash == stored_hash:
                return True
            attempts -= 1
            print(f"Неверный пароль! Осталось попыток: {attempts}")
        print("Доступ заблокирован. Слишком много неверных попыток.")
        return False

    def generate_password_interactive(self):
        """Генерирует криптографически стойкий случайный пароль."""
        print("\n--- Генератор надежного пароля ---")
        try:
            length = input("Введите длину пароля (по умолчанию 16): ")
            length = int(self._clean_input(length)) if length else 16
        except ValueError:
            print("Ошибка: длина должна быть числом. Установлено: 16.")
            length = 16

        use_upper = self._clean_input(input("Использовать ЗАГЛАВНЫЕ буквы? (Y/n): ")).lower() != 'n'
        use_lower = self._clean_input(input("Использовать строчные буквы? (Y/n): ")).lower() != 'n'
        use_digits = self._clean_input(input("Использовать цифры? (Y/n): ")).lower() != 'n'
        use_spec = self._clean_input(input("Использовать спецсимволы (@, #, $...)? (Y/n): ")).lower() != 'n'

        charset = ""
        if use_upper: charset += string.ascii_uppercase
        if use_lower: charset += string.ascii_lowercase
        if use_digits: charset += string.digits
        if use_spec: charset += string.punctuation

        if not charset:
            print("Ошибка: вы не выбрали ни один тип символов! Выбраны настройки по умолчанию.")
            charset = string.ascii_letters + string.digits

        password = "".join(secrets.choice(charset) for _ in range(length))
        print(f"\nСгенерированный пароль: {password}")
        return password

    def add_password(self):
        """Команда: add — добавление или создание новой записи."""
        print("\n--- Добавление новой записи ---")
        name = self._clean_input(input("Введите название/откуда (например, Google): "))
        if not name:
            print("Название не может быть пустым.")
            return

        login = self._clean_input(input("Введите логин: "))
        
        choice = self._clean_input(input("Сгенерировать пароль автоматически? (Y/n): ")).lower()
        if choice != 'n':
            password = self.generate_password_interactive()
        else:
            password = input("Введите ваш пароль вручную: ")

        password_cleaned = self._clean_input(password)
        if not password_cleaned:
            print("Пароль не может быть пустым.")
            return

        encrypted_pwd = self.crypto.encrypt(password_cleaned)
        self.db.add_password(name, login, encrypted_pwd)
        print(f"Запись для '{name}' успешно сохранена.")

    def get_password(self):
        """Команда: get — получить скрытый пароль по названию."""
        name = self._clean_input(input("\nВведите название сервиса для поиска: "))
        record = self.db.get_password(name)
        
        if not record:
            print(f"Запись с названием '{name}' не найдена.")
            return

        print("\nВнимание! Для просмотра пароля требуется подтверждение.")
        if self.authenticate():
            login, encrypted_pwd = record
            decrypted_pwd = self.crypto.decrypt(encrypted_pwd)
            print(f"\nДанные для '{name}':")
            print(f"Логин:  {login}")
            print(f"Пароль: {decrypted_pwd}")

    def list_passwords(self):
        """Команда: list — список всех названий и логинов."""
        records = self.db.list_passwords()
        if not records:
            print("\nБаза данных паролей пуста.")
            return

        print(f"\n--- Список сохраненных записей (Всего: {len(records)}) ---")
        print(f"{'Название (Сервис)':<25} | {'Логин':<30}")
        print("-" * 60)
        for name, login in records:
            print(f"{name:<25} | {login:<30}")

    def delete_password(self):
        """Команда: delete — удаление пароля."""
        name = self._clean_input(input("\nВведите название сервиса для УДАЛЕНИЯ: "))
        if self.db.delete_password(name):
            print(f"Запись '{name}' успешно удалена из базы.")
        else:
            print(f"Ошибка: запись '{name}' не найдена.")

    def show_menu(self):
        """Основной CLI-обработчик циклического меню команд."""
        self.setup_master_password()
        
        if not self.authenticate():
            return

        while True:
            print("\n================ МЕНЮ КОМАНД ================")
            print("add    - добавить новую запись")
            print("get    - получить пароль по названию")
            print("list   - показать список всех записей")
            print("delete - удалить запись по названию")
            print("new    - сгенерировать новый надежный пароль")
            print("exit   - выход из программы")
            print("=============================================")
            
            command = self._clean_input(input("Введите команду: ")).lower()
            
            if command == "add":
                self.add_password()
            elif command == "get":
                self.get_password()
            elif command == "list":
                self.list_passwords()
            elif command == "delete":
                self.delete_password()
            elif command == "new":
                self.generate_password_interactive()
            elif command == "exit":
                print("Программа успешно завершена. Все данные надежно зашифрованы.")
                break
            else:
                print("Неизвестная команда. Пожалуйста, выберите команду из списка.")

if __name__ == "__main__":
    app = PasswordGenerator()
    app.show_menu()
