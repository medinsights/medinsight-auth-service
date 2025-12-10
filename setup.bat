@echo off
REM Backend Setup Script for Windows

echo 🔧 Setting up MedInsight Auth Service...
echo.

REM Create virtual environment
echo Creating virtual environment...
python -m venv venv
if %errorlevel% neq 0 (
    echo Error: Python not found or venv creation failed
    echo Please ensure Python is installed and added to PATH
    pause
    exit /b 1
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -r requirements-dev.txt
if %errorlevel% neq 0 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)

REM Copy environment file
echo Setting up environment variables...
if not exist .env (
    copy .env.example .env
    echo ⚠️  Please edit .env file with your configuration
)

REM Generate RSA keys manually (using openssl if available)
echo Generating RSA keys for JWT...
if not exist src\keys mkdir src\keys

if not exist src\keys\private.pem (
    where openssl >nul 2>nul
    if %errorlevel% equ 0 (
        openssl genrsa -out src\keys\private.pem 2048
        openssl rsa -in src\keys\private.pem -pubout -out src\keys\public.pem
        echo ✓ RSA keys generated successfully in src\keys\
    ) else (
        echo.
        echo ⚠️  WARNING: OpenSSL not found!
        echo.
        echo Please install OpenSSL or generate keys manually:
        echo   1. Download OpenSSL from: https://slproweb.com/products/Win32OpenSSL.html
        echo   2. Or use Git Bash: bash setup.sh
        echo   3. Or install Python cryptography and run:
        echo      python -c "from cryptography.hazmat.primitives.asymmetric import rsa; from cryptography.hazmat.primitives import serialization; from cryptography.hazmat.backends import default_backend; key = rsa.generate_private_key(65537, 2048, default_backend()); open('src/keys/private.pem', 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); open('src/keys/public.pem', 'wb').write(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))"
        echo.
        pause
    )
) else (
    echo ✓ RSA keys already exist in src\keys\
)

REM Run migrations
echo Running database migrations...
python manage.py makemigrations
python manage.py migrate

REM Create superuser (optional)
echo.
set /p response="Would you like to create a superuser? (y/n): "
if /i "%response%"=="y" (
    python manage.py createsuperuser
)

echo.
echo ✅ Backend setup complete!
echo.
echo 📝 Next steps:
echo   1. Activate the virtual environment:
echo      venv\Scripts\activate.bat
echo.
echo   2. Start the server:
echo      python manage.py runserver
echo.
echo The API will be available at: http://127.0.0.1:8000/
echo.
pause
