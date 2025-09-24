# легка база
FROM python:3.12-slim

# не ставити .pyc і буфери
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# системні залежності (якщо треба збирання деяких пакетів)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl && \
    rm -rf /var/lib/apt/lists/*

# робоча директорія
WORKDIR /app

# спочатку залежності
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# потім код (щоб кеш краще працював)
COPY . /app

# порт всередині контейнера
EXPOSE 8000

# стартуємо через gunicorn (виробничий WSGI-сервер)
# у тебе app = Flask(...), тому модуль:об'єкт = app:app
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "app:app"]