#!/bin/bash
# Backend Setup Script

echo "🔧 Setting up MedInsight Auth Service..."

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    # Windows Git Bash
    source venv/Scripts/activate
else
    # Linux/Mac
    source venv/bin/activate
fi

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements-dev.txt

# Copy environment file
echo "Setting up environment variables..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "⚠️  Please edit .env file with your configuration"
fi

# Generate RSA keys manually (using openssl since generate_keys command may not exist)
echo "Generating RSA keys for JWT..."
mkdir -p src/keys
if [ ! -f src/keys/private.pem ]; then
    openssl genrsa -out src/keys/private.pem 2048
    openssl rsa -in src/keys/private.pem -pubout -out src/keys/public.pem
    chmod 600 src/keys/private.pem
    chmod 644 src/keys/public.pem
    echo "✓ RSA keys generated successfully in src/keys/"
else
    echo "✓ RSA keys already exist in src/keys/"
fi

# Run migrations
echo "Running database migrations..."
python3 manage.py makemigrations
python3 manage.py migrate

# Create superuser (optional)
echo ""
echo "Would you like to create a superuser? (y/n)"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    python3 manage.py createsuperuser
fi

echo ""
echo "✅ Backend setup complete!"
echo ""
echo "📝 Next steps:"
echo "  1. Activate the virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Start the server:"
echo "     python3 manage.py runserver"
echo ""
echo "The API will be available at: http://127.0.0.1:8000/"
echo ""
