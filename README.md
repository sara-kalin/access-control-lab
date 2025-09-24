# access-control-lab
Навчальний проєкт із дисципліни «Політики безпеки», мета якого — розробка прототипу системи контролю доступу. Система реалізована на основі Flask + SQLAlchemy + PostgreSQL 
##НЕ НЕСЕ НАУКОВОЇ ТА ПРИКЛАДНОЇ ЦІННОСТІ

# Access Control Lab

Прототип системи контролю доступу з підтримкою:
- **Аутентифікації** (реєстрація та вхід користувачів),
- **Авторизації** (ролі: `admin`, `moderator`, `user`),
- **RBAC (Role-Based Access Control)**,
- **Журналу аудиту** (фіксація подій входу, зміни ролей тощо).

Розроблено у рамках лабораторної роботи з дисципліни **«Політики безпеки»**.

---

## 🚀 Запуск на локальній машині

### 1. Клонувати репозиторій
```bash
git clone https://github.com/sara-kalin/access-control-lab.git
cd access-control-lab
```
## 2. Створити та активувати віртуальне середовище
```bash
python3 -m venv .venv
source .venv/bin/activate   # Linux / macOS
# або
.venv\Scripts\activate      # Windows PowerShell
```
## 3. Встановити залежності
```bash
pip install --upgrade pip
pip install -r requirements.txt
```
## 4. Створити файл .env
У корені проєкту створи файл .env з такими змінними:
```bash
SECRET_KEY=devkey
DATABASE_URL=sqlite:///app.db
```
За замовчуванням використовується SQLite.
Якщо хочете Postgres — зміни DATABASE_URL, наприклад:
postgresql+psycopg://ac_user:ac_password@localhost:5432/ac_db

## 5. Ініціалізувати базу даних та запустити застосунок
```bash
python app/app.py
```
При першому запуску створяться таблиці та буде додано адміністратора:
```bash
username: admin
password: administrator
```
## 6. Відкрити у браузері
http://127.0.0.1:8000
   
