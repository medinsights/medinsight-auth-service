# MedInsight Auth Service

Authentication & Identity microservice for MedInsight System using Django REST Framework with JWT (RS256).

## 🏗️ Project Structure

```
medinsight-auth-service/
├── manage.py                 # Django management script
├── setup.sh                  # Linux/Mac setup script
├── setup.bat                 # Windows setup script
├── requirements.txt          # Production dependencies
├── requirements-dev.txt      # Development dependencies
├── .env.example             # Environment variables template
├── src/
│   ├── keys/                # RSA keys for JWT (generated, gitignored)
│   ├── db.sqlite3           # SQLite database (development)
│   ├── auth_service/        # Django project settings
│   │   ├── settings.py      # Project configuration
│   │   ├── urls.py          # Main URL routing
│   │   ├── wsgi.py          # WSGI application
│   │   └── asgi.py          # ASGI application
│   └── authentication/      # Authentication app
│       ├── models.py        # User model & RefreshToken
│       ├── views.py         # API endpoints
│       ├── serializers.py   # Request/response serializers
│       ├── backends.py      # JWT authentication backend
│       └── jwt_utils.py     # JWT token handling
└── api/
    └── openapi.yaml         # API documentation
```

## 🚀 Quick Start

### Automated Setup

#### **Linux/Mac:**
```bash
chmod +x setup.sh
./setup.sh
```

#### **Windows:**
```cmd
setup.bat
```

The setup scripts will:
- Create a virtual environment
- Install all dependencies
- Generate RSA keys for JWT
- Run database migrations
- Optionally create a superuser

### Manual Setup

#### 1. Create Virtual Environment

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

#### 2. Install Dependencies

```bash
pip install -r requirements-dev.txt
```

#### 3. Environment Configuration

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your settings (optional for development)
```

#### 4. Generate RSA Keys

**Using OpenSSL (Linux/Mac/Windows with OpenSSL):**
```bash
mkdir -p src/keys
openssl genrsa -out src/keys/private.pem 2048
openssl rsa -in src/keys/private.pem -pubout -out src/keys/public.pem
chmod 600 src/keys/private.pem  # Linux/Mac only
```

**Using Python (if OpenSSL not available):**
```bash
python -c "from cryptography.hazmat.primitives.asymmetric import rsa; from cryptography.hazmat.primitives import serialization; from cryptography.hazmat.backends import default_backend; import os; os.makedirs('src/keys', exist_ok=True); key = rsa.generate_private_key(65537, 2048, default_backend()); open('src/keys/private.pem', 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); open('src/keys/public.pem', 'wb').write(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))"
```

#### 5. Run Migrations

```bash
python manage.py migrate
```

#### 6. Create Superuser (Optional)

```bash
python manage.py createsuperuser
```

## 🎯 Running the Server

### Linux/Mac:
```bash
source venv/bin/activate
python3 manage.py runserver
```

### Windows:
```cmd
venv\Scripts\activate.bat
python manage.py runserver
```

The API will be available at: **`http://127.0.0.1:8000/`**

### Run on Different Port:
```bash
python manage.py runserver 8080
```

### Run on All Interfaces:
```bash
python manage.py runserver 0.0.0.0:8000
```

## 📡 API Endpoints

### Authentication

- **Register**: `POST /api/auth/register/`
- **Login**: `POST /api/auth/login/`
- **Refresh Token**: `POST /api/auth/refresh/`
- **Logout**: `POST /api/auth/logout/`
- **Current User**: `GET /api/auth/me/`
- **Public Key (JWKS)**: `GET /api/auth/jwks/`

### Health & Admin

- **Health Check**: `GET /health/`
- **Admin Panel**: `http://127.0.0.1:8000/admin/` (requires superuser)

## 🔐 JWT Authentication

This service uses **RS256 (RSA asymmetric encryption)** for JWT tokens:

- **Access Token**: Short-lived (15 minutes) - sent in response body
- **Refresh Token**: Long-lived (30 days) - stored as HttpOnly cookie

### Authentication Flow

1. User registers/logs in → receives access token + refresh token (cookie)
2. Client uses access token in `Authorization: Bearer <token>` header
3. When access token expires → use refresh token endpoint to get new access token
4. Refresh token rotates on each use for enhanced security

## 🛠️ Development Commands

```bash
# Activate virtual environment
source venv/bin/activate          # Linux/Mac
venv\Scripts\activate.bat         # Windows

# Check for issues
python manage.py check

# Run migrations
python manage.py migrate

# Create migrations after model changes
python manage.py makemigrations

# Create superuser
python manage.py createsuperuser

# Run development server
python manage.py runserver

# Access Python shell
python manage.py shell

# Run tests
python manage.py test

# Collect static files (production)
python manage.py collectstatic
```

## 📦 Dependencies

- **Django 5.0** - Web framework
- **Django REST Framework** - API toolkit
- **PyJWT** - JWT token handling
- **cryptography** - RSA key generation
- **django-cors-headers** - CORS support
- **django-ratelimit** - Rate limiting
- **python-dotenv** - Environment variables
- **psycopg2-binary** - PostgreSQL adapter (optional)

## 🔒 Security Features

- ✅ **RS256** asymmetric JWT (more secure than HS256)
- ✅ **HttpOnly cookies** for refresh tokens
- ✅ **Token rotation** on refresh
- ✅ **Rate limiting** on authentication endpoints
- ✅ **CORS** configuration
- ✅ **Password validation** (min 8 chars, complexity requirements)
- ✅ **HTTPS ready** (configure in production)

## 🌐 CORS Configuration

Update `CORS_ALLOWED_ORIGINS` in `.env` to match your frontend URL:

```env
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

For development with React/Vue/Angular running on different port.

## ⚙️ Environment Variables

Key variables in `.env` (see `.env.example` for full list):

```env
# Django
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# JWT
JWT_ACCESS_TOKEN_LIFETIME=900         # 15 minutes
JWT_REFRESH_TOKEN_LIFETIME=2592000    # 30 days

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:5173

# Database (optional - defaults to SQLite)
DATABASE_URL=postgresql://user:pass@localhost/dbname
```

## 🧪 API Testing Examples

### Register User
```bash
curl -X POST http://127.0.0.1:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePass123!",
    "password_confirm": "SecurePass123!",
    "first_name": "Test",
    "last_name": "User"
  }'
```

### Login
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }' \
  -c cookies.txt
```

### Get Current User
```bash
curl -X GET http://127.0.0.1:8000/api/auth/me/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Refresh Token
```bash
curl -X POST http://127.0.0.1:8000/api/auth/refresh/ \
  -b cookies.txt
```

## 🚀 Production Deployment

### Checklist

- [ ] Set `DEBUG=False` in `.env`
- [ ] Set strong `SECRET_KEY`
- [ ] Configure `ALLOWED_HOSTS`
- [ ] Enable HTTPS settings in `settings.py`
- [ ] Use PostgreSQL instead of SQLite
- [ ] Set up proper logging
- [ ] Configure rate limiting
- [ ] Use production WSGI server (gunicorn/uwsgi)
- [ ] Set up reverse proxy (nginx/Apache)
- [ ] Secure RSA keys with proper permissions
- [ ] Enable database backups
- [ ] Set up monitoring and alerts

### Using Gunicorn (Production)

```bash
pip install gunicorn
gunicorn auth_service.wsgi:application --bind 0.0.0.0:8000
```

## 📝 Troubleshooting

### RSA Keys Not Found
```bash
# Regenerate keys
mkdir -p src/keys
openssl genrsa -out src/keys/private.pem 2048
openssl rsa -in src/keys/private.pem -pubout -out src/keys/public.pem
```

### Module Not Found
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate.bat # Windows

# Reinstall dependencies
pip install -r requirements-dev.txt
```

### Port Already in Use
```bash
# Use different port
python manage.py runserver 8080

# Or kill process on port 8000
lsof -ti:8000 | xargs kill -9  # Linux/Mac
```

## 📄 License

See LICENSE file for details.

## 🤝 Contributing

This is a microservice for the MedInsight system. For contribution guidelines, please refer to the main project documentation.
