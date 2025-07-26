# 🔐 Auth Service — Задания №4 и №5 (Spring Security + JWT + Docker)

## 📚 Описание

Это сервис авторизации и аутентификации пользователей с использованием JWT-токенов, реализующий требования заданий 4 и 5 из курса T1 School.

---

## ✅ Задание 4 — Основной функционал

Сервис реализует:

- ✅ Регистрацию новых пользователей.
- ✅ Аутентификацию (логин) с генерацией `access` и `refresh` токенов.
- ✅ Поддержку **трёх ролей**:
  - `ADMIN`
  - `PREMIUM_USER`
  - `GUEST`
- ✅ Уникальные поля:
  - `логин`
  - `email`
- ✅ Безопасное хранение пароля (BCrypt).
- ✅ Время жизни `access` токена ограничено.
- ✅ Повторное получение токена через `refresh` (без логина/пароля).
- ✅ Возможность **отозвать токены** (и access, и refresh).

---

## 🔐 Задание 5 — Безопасность токенов

> По условиям — токен передаётся по незащищённому каналу, и его нужно защитить от **компрометации** и **подмены**.

Сервис дополнительно реализует:

- 🔒 Шифрование `access` токена с помощью **AES-GCM** (256-бит).
- 🛡️ Проверка IP-адреса и `User-Agent` для защиты от подмены.
- 📜 Хранение `access` токенов в **белом списке** (`validAccessTokenRepository`).
- 🍪 `refreshToken` передаётся через `HttpOnly` cookie.
- 🔄 Отзыв access/refresh токенов (удаление из хранилища).

---

## 🧩 Технологии

- Java 21
- Spring Boot 3.x
- Spring Security
- JWT (`java-jwt` + AES шифрование)
- H2 / PostgreSQL
- Spring Data JPA / Hibernate
- Docker / Docker Compose
- BCryptPasswordEncoder

---

## 🐳 Запуск в Docker

### ⚙️ Требования

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)

### 🛠 Инструкция
1. Запуск проекта
   ``` bash
    docker-compose up --build
   ```
2. Приложение будет доступно по адресу:
   http://localhost:8089

## 📌 Эндпоинты
### 🔸 Регистрация
POST /api/auth/register
```json
{
  "login": "user123",
  "email": "user@example.com",
  "password": "123456",
  "roles": ["GUEST"]
}
```
### 🔸 Логин
POST /api/auth/register
```json
{
  "login": "user123",
  "password": "123456"
}
```
---
## 🛠 Примечания
Пароли хранятся в BCrypt, токены — зашифрованы.

accessToken действителен 1 час.

refreshToken — 7 дней.

Все токены проверяются на соответствие IP и User-Agent.

Невалидные или отозванные access токены удаляются из белого списка и становятся недействительными.
---

## 👨‍💻 Автор
Разработано в рамках курса T1 School — Backend Spring Boot
