# 🚀 Enterprise FastAPI Security Backend Template

A production-ready, enterprise-grade FastAPI backend template with comprehensive security features designed for government contracting and high-security applications.

## 🔒 Security Features

### ✅ **Authentication & Authorization**
- **JWT Token Authentication** with configurable expiration
- **Password Hashing** using BCrypt with configurable rounds
- **API Key Authentication** for service-to-service communication
- **Role-Based Access Control** (Government vs Regular users)
- **Session Management** with timeout controls

### 🛡️ **Security Headers**
- **X-Content-Type-Options**: `nosniff`
- **X-Frame-Options**: `DENY` 
- **X-XSS-Protection**: `1; mode=block`
- **Strict-Transport-Security**: HSTS with long max-age
- **Content-Security-Policy**: Restrictive CSP
- **Referrer-Policy**: `strict-origin-when-cross-origin`
- **Permissions-Policy**: Blocks dangerous APIs

### ⚡ **Rate Limiting**
- **Configurable rate limits** per endpoint type
- **IP-based tracking** with automatic reset
- **Custom retry-after headers** on limit exceeded
- **Different limits** for different security levels:
  - General: 100/minute
  - Registration: 5/minute
  - Login: 10/minute
  - Government: 50/minute

### 🔐 **Brute Force Protection**
- **Failed login attempt tracking**
- **Account lockout** after configurable max attempts
- **Automatic unlock** after lockout period
- **Real-time monitoring** per user email

### ��️ **Government/Enterprise Features**
- **Government-only endpoints** with enhanced security
- **Access logging** for audit trails
- **Classified data protection**
- **Compliance-ready architecture**

### 🚨 **Additional Security**
- **CORS protection** with configurable origins
- **Input validation** using Pydantic models
- **Environment-based configuration**
- **Secure error handling** (no information leakage)

## 🚀 Quick Start

### 1. Clone and Setup
```bash
git clone <your-repo-url>
cd enterprise-backend
pip install -r requirements.txt
```

### 2. Environment Configuration
Create a `.env` file with the following variables:

```env
# Application Settings
DEBUG=False
ENVIRONMENT=production
PORT=8080

# Security Keys (GENERATE NEW ONES!)
JWT_SECRET_KEY=your-super-secret-jwt-key-here
API_KEY_SECRET=your-api-key-secret-here
ENCRYPTION_KEY=your-encryption-key-here

# Authentication Configuration
JWT_EXPIRATION_HOURS=24
SESSION_TIMEOUT_MINUTES=30
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15

# Security Features
SECURITY_HEADERS=true
RATE_LIMIT_PER_MINUTE=100

# Google Cloud (Optional)
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_CLOUD_REGION=us-central1

# Database (Configure your preferred database)
SUPABASE_URL=your-database-url
SUPABASE_ANON_KEY=your-database-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
```

### 3. Generate Secure Keys
```python
# Use this Python script to generate secure keys
import secrets

print("JWT_SECRET_KEY=" + secrets.token_urlsafe(64))
print("API_KEY_SECRET=" + secrets.token_urlsafe(32))
print("ENCRYPTION_KEY=" + secrets.token_urlsafe(32))
```

### 4. Run Locally
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

### 5. Test the API
```bash
# Health check
curl http://localhost:8080/health

# View security configuration
curl http://localhost:8080/config

# Register a user
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"securepass123","is_government":true}'

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"securepass123"}'
```

## 📚 API Documentation

Once running, view the interactive API documentation at:
- **Swagger UI**: `http://localhost:8080/docs`
- **ReDoc**: `http://localhost:8080/redoc`

## 🔧 Configuration Options

### Security Configuration
```env
# Enable/disable security headers
SECURITY_HEADERS=true

# Rate limiting (requests per minute)
RATE_LIMIT_PER_MINUTE=100

# Login protection
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15

# Session management
JWT_EXPIRATION_HOURS=24
SESSION_TIMEOUT_MINUTES=30
```

### Authentication Methods
1. **JWT Tokens**: For user sessions
2. **API Keys**: For service-to-service auth via `X-API-Key` header
3. **Password Auth**: With BCrypt hashing

## 🏗️ Architecture

```
app/
├── main.py                 # FastAPI application with security middleware
├── core/                   # Core security modules (placeholder)
├── api/                    # API endpoints (placeholder)
├── models/                 # Database models (placeholder)
└── schemas/                # Pydantic schemas
    └── user.py            # User data models
```

## 🚀 Deployment

### Docker
```bash
docker build -t enterprise-backend .
docker run -p 8080:8080 --env-file .env enterprise-backend
```

### Google Cloud Run
```bash
gcloud run deploy enterprise-backend \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars="$(cat .env | tr '\n' ',')"
```

### Environment Variables for Production
Ensure these are set in your production environment:
- `SECURITY_HEADERS=true`
- `DEBUG=false`
- `ENVIRONMENT=production`
- All security keys properly generated

## 🛡️ Security Best Practices

### 1. **Key Management**
- Generate unique secrets for each environment
- Use environment variables, never hardcode secrets
- Rotate keys regularly
- Use a key management service in production

### 2. **Database Security**
- Use connection pooling
- Enable SSL/TLS for database connections
- Implement proper backup encryption
- Use least-privilege database users

### 3. **Network Security**
- Use HTTPS in production (TLS 1.2+)
- Implement proper firewall rules
- Use private networks when possible
- Enable DDoS protection

### 4. **Monitoring**
- Enable access logging
- Monitor failed login attempts
- Set up security alerts
- Implement audit trails

## 📋 Endpoints

### Public Endpoints
- `GET /` - Service information
- `GET /health` - Health check
- `GET /config` - Security configuration overview

### Authentication
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `GET /api/v1/auth/me` - Current user info

### Protected Endpoints
- `GET /api/v1/protected/dashboard` - User dashboard
- `GET /api/v1/protected/government-only` - Government users only
- `GET /api/v1/protected/security-status` - Security status

## 🔄 Customization

### Adding New Endpoints
1. Create new router in `app/api/v1/`
2. Add authentication decorators as needed
3. Include router in `main.py`

### Custom Security Rules
1. Modify rate limits in `app/main.py`
2. Add custom middleware in `security_middleware()`
3. Extend user models in `schemas/user.py`

### Database Integration
1. Configure your preferred database in `.env`
2. Update database models as needed
3. Implement proper migrations

## 🚨 Security Compliance

This template is designed to meet:
- **Government contracting security standards**
- **Enterprise-grade security requirements**
- **OWASP security best practices**
- **Industry-standard authentication protocols**

## 📞 Support

This is a template designed for enterprise and government contracting use cases. Customize according to your specific security requirements and compliance needs.

## ⚠️ Important Notes

1. **Generate new secrets** for each deployment
2. **Test security features** in your environment
3. **Review and customize** rate limits for your use case
4. **Implement proper logging** and monitoring
5. **Regular security audits** and updates

---

**🔒 Security is not a feature, it's a foundation. This template provides that foundation.**
