# MedInsights Auth Service

Django-based JWT authentication microservice for the MedInsights platform.

## 🏗️ Architecture

- **Framework**: Django 5.0 + Django REST Framework
- **Authentication**: RS256 JWT tokens with refresh token rotation
- **Database**: PostgreSQL (isolated `auth_db`)
- **Port**: 8001
- **Containerization**: Docker + Docker Compose
- **Orchestration**: Kubernetes with Kustomize + ArgoCD

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for local development)
- PostgreSQL 16 (if running locally without Docker)

### 1. Local Development with Docker Compose

```bash
# Clone and navigate to directory
cd medinsight-auth-service

# Start services (PostgreSQL + Auth Service)
docker compose up --build

# Service will be available at http://localhost:8001
```

### 2. Test the Service

```bash
# Health check
curl http://localhost:8001/api/auth/health/

# Register a user
curl -X POST http://localhost:8001/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@medinsights.com",
    "password": "SecurePass123!",
    "first_name": "Test",
    "last_name": "User"
  }'

# Login
curl -X POST http://localhost:8001/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePass123!"
  }'
```

### 3. Stop Services

```bash
docker compose down
```

---

## 📁 Project Structure

```
medinsight-auth-service/
├── Dockerfile                  # Multi-stage production build
├── docker-compose.yml          # Local development setup
├── manage.py                   # Django management script
├── requirements.txt            # Python dependencies
├── .env                        # Environment variables (local)
├── .env.example                # Environment template
├── src/
│   ├── myproject/              # Django project settings
│   │   ├── settings.py         # Application configuration
│   │   ├── urls.py             # URL routing
│   │   └── wsgi.py             # WSGI entry point
│   └── authentication/         # Authentication app
│       ├── models.py            # User & Token models
│       ├── serializers.py       # API serializers
│       ├── views.py             # API endpoints
│       ├── jwt_utils.py         # JWT handling
│       ├── backends.py          # Custom authentication backend
│       └── urls.py              # Auth routes
├── infra/k8s/                  # Kubernetes manifests
│   ├── base/                   # Base configurations
│   │   ├── namespace.yaml
│   │   ├── configmap.yaml
│   │   ├── secret.yaml
│   │   ├── postgres-statefulset.yaml
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── kustomization.yaml
│   └── overlays/               # Environment overlays
│       ├── dev/
│       └── prod/
└── argocd/
    └── application.yaml        # ArgoCD app definition
```

---

## 🔑 Environment Configuration

### Required Environment Variables

```env
# Django
SECRET_KEY=your-secret-key
DEBUG=False
ALLOWED_HOSTS=localhost,auth-service

# Database
DATABASE_URL=postgresql://auth_user:auth_pass@postgres:5432/auth_db

# JWT
JWT_ALGORITHM=RS256
JWT_ACCESS_TOKEN_LIFETIME=900   # 15 minutes
JWT_REFRESH_TOKEN_LIFETIME=2592000  # 30 days
JWT_PRIVATE_KEY_PATH=keys/private.pem
JWT_PUBLIC_KEY_PATH=keys/public.pem

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://kong:8000
```

---

## 🔐 JWT Keys Setup

The service uses RS256 (asymmetric) JWT signing for production security.

### Generate Keys (Local Development)

```bash
# Generate RSA private key
openssl genrsa -out keys/private.pem 2048

# Generate public key
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

### Kubernetes Deployment

Keys will be mounted via Kubernetes secrets:

```bash
# Create JWT keys secret
kubectl create secret generic auth-jwt-keys \
  --from-file=private.pem=./keys/private.pem \
  --from-file=public.pem=./keys/public.pem \
  -n medinsights
```

---

## ☸️ Kubernetes Deployment

### Using Kustomize (Recommended)

#### Development Environment

```bash
# Apply base + dev overlays
kubectl apply -k infra/k8s/overlays/dev/

# Verify deployment
kubectl get pods -n medinsights
kubectl logs -f deployment/dev-auth-service -n medinsights
```

#### Production Environment

```bash
# Apply base + prod overlays
kubectl apply -k infra/k8s/overlays/prod/

# Scale replicas (if needed)
kubectl scale deployment/prod-auth-service --replicas=5 -n medinsights
```

### Using ArgoCD (GitOps)

```bash
# Install ArgoCD application
kubectl apply -f argocd/application.yaml

# Sync application
argocd app sync auth-service

# Check status
argocd app get auth-service
```

---

## 🔧 API Endpoints

### Public Endpoints (No Auth Required)

- `GET  /api/auth/health/` - Health check
- `POST /api/auth/register/` - User registration
- `POST /api/auth/login/` - User login
- `POST /api/auth/refresh/` - Refresh access token
- `POST /api/auth/verify-email/` - Email verification

### Protected Endpoints (JWT Required)

- `GET  /api/auth/me/` - Get current user profile
- `POST /api/auth/change-password/` - Change password
- `POST /api/auth/logout/` - Logout (revoke refresh token)
- `POST /api/auth/logout-all/` - Logout all sessions

---

## 🧪 Testing

### Run Django Tests

```bash
# Inside container
docker exec -it auth-service python manage.py test

# Or locally
python manage.py test authentication
```

### Database Console

```bash
# Connect to PostgreSQL
docker exec -it auth-service-db psql -U auth_user -d auth_db

# Django shell
docker exec -it auth-service python manage.py shell
```

---

## 🔄 Next Steps: Kong Gateway Integration

The auth service is ready to integrate with Kong API Gateway. Here's what needs to be done:

### 1. Kong Gateway Configuration

Create Kong services and routes in `medinsight-gateway/config/kong.yml`:

```yaml
services:
  - name: auth-service
    url: http://auth-service:8001
    routes:
      - name: auth-routes
        paths:
          - /auth
        strip_path: true
        
plugins:
  - name: jwt
    config:
      uri_param_names:
        - jwt
      secret_is_base64: false
      # Public key from auth-service will be configured here
```

### 2. Share Public Key with Kong

- Export public key: `kubectl get secret auth-jwt-keys -n medinsights -o jsonpath='{.data.public\.pem}' | base64 -d`
- Configure Kong JWT plugin with this public key
- Kong will validate JWTs issued by auth-service

### 3. Frontend Integration

Update frontend to:
- Point auth requests to Kong gateway: `http://kong:8000/auth/*`
- Store JWT access token in memory/sessionStorage
- Include token in Authorization header: `Bearer <access_token>`
- Handle 401 responses with token refresh logic

### 4. Patient Service Integration

Configure patient-service to:
- Trust Kong's JWT validation (no need to validate again)
- Read user claims from headers injected by Kong:
  - `X-User-Id`
  - `X-User-Roles`
  - `X-Consumer-Username`

---

## 📊 Monitoring & Logs

```bash
# View logs
docker logs -f auth-service

# Kubernetes logs
kubectl logs -f deployment/auth-service -n medinsights

# Database logs
docker logs -f auth-service-db
```

---

## 🛠️ Troubleshooting

### Issue: Container won't start

```bash
# Check logs
docker logs auth-service

# Verify DATABASE_URL
docker exec -it auth-service env | grep DATABASE_URL
```

### Issue: Cannot connect to database

```bash
# Test PostgreSQL connectivity
docker exec -it auth-service-db pg_isready -U auth_user -d auth_db

# Check network
docker network inspect medinsight-auth-service_auth-network
```

### Issue: JWT signature verification failed

```bash
# Verify keys exist
docker exec -it auth-service ls -la /app/keys/

# Check key permissions
docker exec -it auth-service cat /app/keys/public.pem
```

---

## 📝 Migration from PDS Monorepo

This service replaces `Pds/backend/Django` with key improvements:

✅ **Isolated Database**: Own PostgreSQL instance (`auth_db`)  
✅ **Containerized**: Docker + Kubernetes ready  
✅ **RS256 JWT**: Production-grade asymmetric signing  
✅ **Health Checks**: Kubernetes liveness/readiness probes  
✅ **GitOps Ready**: ArgoCD application manifest  
✅ **Environment Separation**: Dev/Prod overlays with Kustomize  

---

## 🤝 Contributing

1. Make changes in feature branch
2. Test locally with docker compose
3. Update K8s manifests if needed
4. Commit and push (ArgoCD will auto-sync if enabled)

---

## 📄 License

See [LICENSE](LICENSE) file.

---

## 🔗 Related Services

- **Patient Service**: [medinsight-patient-service](../medinsight-patient-service)
- **Kong Gateway**: [medinsight-gateway](../medinsight-gateway)
- **Frontend**: [medinsight-frontend](../medinsight-frontend)
