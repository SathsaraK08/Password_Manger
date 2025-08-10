# Secure Password Vault

This repository contains a simple internal password vault built with a Python FastAPI backend and a lightweight HTML/Bootstrap front‑end. The application provides user registration and login, AES‑256 encrypted credential storage, role‑based access control and an audit log of all access and modifications.

## Features

- **User Accounts**: Supports both `admin` and `member` roles. Admins can manage users and credentials across the system whereas members can only view their own credentials.
- **Secure Password Storage**: Passwords are encrypted using AES‑256 with a unique IV per credential. The encryption key is read from an environment variable and **never** checked into version control.
- **Authentication**: JWT bearer tokens are issued on login. The API requires a valid token for all endpoints except registration and login.
- **Role‑Based Authorization**: Admin‑only endpoints (e.g. deleting users, editing credentials) return HTTP 403 when accessed by non‑admins.
- **Audit Log**: Every credential view, creation, edit and deletion is recorded with the acting user and timestamp.
- **Search & Filtering**: Credential list endpoints accept a `search` query parameter to filter by site name, username or notes.
- **Dockerized**: Includes a `Dockerfile` for building a backend container. Deploy behind a reverse proxy with TLS in production.

## Project Structure

```
password_vault/
├── backend/
│   ├── auth.py          # Authentication helpers and dependencies
│   ├── crud.py          # Database operations for models
│   ├── database.py      # SQLAlchemy engine and session setup
│   ├── Dockerfile       # Container specification for backend
│   ├── main.py          # FastAPI application and API routes
│   ├── models.py        # ORM model definitions (User, Credential, AuditLog)
│   ├── schemas.py       # Pydantic schemas for request/response bodies
│   ├── utils.py         # AES encryption, password hashing and JWT helpers
│   ├── requirements.txt # Python package dependencies
│   └── .env.example     # Sample environment configuration
├── frontend/
│   ├── index.html       # Login page
│   ├── register.html    # User registration page
│   ├── dashboard.html   # Main dashboard listing credentials
│   ├── add.html         # Form to add a new credential
│   ├── edit.html        # Form to edit an existing credential (admin only)
│   ├── view.html        # View details of a credential
│   ├── users.html       # Manage users (admin only)
│   └── audit.html       # View the audit log (admin only)
└── README.md            # This file
```

## Running Locally

1. **Clone** the repository and change into the project directory.

2. **Create a virtual environment** (optional but recommended):

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install backend dependencies**:

   ```bash
   pip install -r backend/requirements.txt
   ```

4. **Configure environment variables**:

   Copy `.env.example` to `.env` in the `backend/` directory and set `SECRET_KEY`, `AES_KEY` and `DATABASE_URL` appropriately. The `AES_KEY` must be a 32‑byte key encoded in base64. You can generate one using Python:

   ```bash
   python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
   ```

5. **Initialize the database**: The first time you run the backend it will automatically create the SQLite database and tables based on the models.

6. **Run the backend server**:

   ```bash
   uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
   ```

7. **Open the front‑end**: Since the front‑end consists of static HTML files you can open them directly in your browser. For example, open `frontend/index.html` in your browser and point it at the running API (default `http://localhost:8000`).

## Security Considerations

This prototype demonstrates several best practices but is not production ready. In a real deployment you should:

- Serve the API and front‑end over HTTPS using a reverse proxy such as Nginx or Caddy.
- Use a proper secrets management solution to supply `SECRET_KEY` and `AES_KEY` to the application rather than `.env` files.
- Set CORS origins to a specific domain rather than `*`.
- Implement rate limiting and brute force protection on login.
- Encrypt the SQLite database file at rest or use a managed database service.
- Add CSRF protection for forms if you serve pages from the backend.

## Deployment with Docker

Build and run the backend container using Docker:

```bash
cd password_vault/backend
docker build -t password-vault-backend .
docker run -d -p 8000:8000 --env-file .env password-vault-backend
```

You will still need to host the `frontend/` directory with a static web server (e.g. Nginx) or include it in a container.