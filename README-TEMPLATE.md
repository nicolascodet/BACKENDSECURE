# 🔒 Enterprise Security Backend Template

A production-ready, enterprise-grade FastAPI backend template with comprehensive security features, designed for government contracting and high-security applications.

## 🛡️ Security Features

### Multi-Layer Security Architecture
- **Cloud Run Authentication** - Infrastructure-level security
- **Application JWT** - User authentication and session management  
- **API Key Authentication** - Service-to-service communication
- **Rate Limiting** - Application-level DDoS protection
- **CORS Protection** - Configurable allowed origins
- **Security Headers** - HSTS, CSP, X-Frame-Options, etc.

### Enterprise Security Controls
- ✅ BCrypt password hashing with configurable rounds
- ✅ Brute force protection with account lockouts
- ✅ Role-based access control (Government vs Regular users)
- ✅ Comprehensive audit logging for compliance
- ✅ Input validation with Pydantic
- ✅ No hardcoded secrets (environment variables only)
- ✅ Non-root Docker container execution

## 🚀 Quick Start

### 1. Clone and Setup
```bash
git clone https://github.com/nicolascodet/BACKENDSECURE.git
cd BACKENDSECURE
cp .env.example .env
# Edit .env with your values
```

### 2. Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
uvicorn app.main:app --reload

# Test endpoints
curl http://localhost:8000/health
curl http://localhost:8000/config
```

### 3. Production Deployment
```bash
# Deploy to Google Cloud Run
./deploy-enterprise.sh
```

## 🏗️ Architecture

### Database Schema
Complete PostgreSQL schema included for:
- **Users** - Authentication and profile management
- **Refresh Tokens** - Secure session management
- **Audit Logs** - Compliance and security monitoring
- **API Keys** - Service authentication
- **Email Accounts** - Email monitoring (ready for customization)
- **Contract Opportunities** - Government contracting features

### API Structure
```
app/
├── api/v1/
│   ├── auth.py          # Authentication endpoints
│   └── protected.py     # Secured endpoints
├── core/
│   ├── auth.py          # Authentication logic
│   ├── database.py      # Database operations
│   ├── security.py      # Security utilities
│   └── middleware.py    # Custom middleware
├── models/              # Database models
└── schemas/             # Pydantic schemas
```

## 🔧 Configuration

### Environment Variables
```env
# Database
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-key

# Security (generate new secrets!)
JWT_SECRET_KEY=your-64-char-secret
API_KEY_SECRET=your-32-char-secret

# CORS (pipe-separated for Cloud Run)
ALLOWED_ORIGINS=https://yourdomain.com|https://app.yourdomain.com

# Optional: OAuth, Email, Monitoring
GOOGLE_CLIENT_ID=your-oauth-client-id
SENDGRID_API_KEY=your-sendgrid-key
```

### Generate Secure Secrets
```bash
python3 -c "
import secrets
print('JWT_SECRET_KEY=' + secrets.token_urlsafe(64))
print('API_KEY_SECRET=' + secrets.token_urlsafe(32))
"
```

## 📊 API Endpoints

### Public Endpoints
- `GET /health` - Health check
- `GET /config` - Security configuration overview
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login

### Authenticated Endpoints
- `GET /api/v1/auth/me` - Current user profile
- `POST /api/v1/auth/refresh-token` - Token refresh
- `POST /api/v1/auth/logout` - User logout
- `GET /api/v1/protected/dashboard` - User dashboard
- `GET /api/v1/protected/government-only` - Government users only

### Security Features
- Rate limiting: 100/min general, 5/min registration, 10/min login
- Government endpoints: Enhanced logging and 50/min limit
- Failed login protection: Account lockout after 5 attempts
- JWT expiration: Configurable (default 24 hours)

## 🏢 Enterprise Production Setup

### 1. Supabase Database
```bash
# Create project at supabase.com
psql -h db.xxxxx.supabase.co -U postgres -d postgres < database-schema.sql
```

### 2. Google Cloud Secret Manager
```bash
gcloud services enable secretmanager.googleapis.com
echo -n "your-jwt-secret" | gcloud secrets create jwt-secret --data-file=-
echo -n "your-api-secret" | gcloud secrets create api-key-secret --data-file=-
```

### 3. Production Deployment
```bash
# Use enterprise deployment script
./deploy-enterprise.sh
```

### 4. Monitoring & Alerting
```bash
gcloud services enable monitoring.googleapis.com
gcloud monitoring uptime create relevant-backend \
  --display-name="Backend Health Check" \
  --resource-type="uptime-url" \
  --host="your-domain.com" \
  --path="/health"
```

## 🎯 Customization for Your Project

### 1. Add Your API Routes
```python
# app/api/v1/your_feature.py
from fastapi import APIRouter, Depends
from app.core.auth import get_current_user

router = APIRouter()

@router.get("/your-endpoint")
async def your_endpoint(current_user: dict = Depends(get_current_user)):
    # Your business logic here
    return {"message": "Your feature"}
```

### 2. Update Main App
```python
# app/main.py
from app.api.v1 import your_feature

app.include_router(your_feature.router, prefix="/api/v1/your-feature", tags=["your-feature"])
```

### 3. Custom Database Models
Extend the existing schema in `database-schema.sql` or add new tables for your specific needs.

## 🔒 Security Best Practices Implemented

- **No hardcoded secrets** - All sensitive data in environment variables
- **Secure password storage** - BCrypt with salt rounds
- **JWT security** - Short-lived tokens with refresh mechanism
- **Input validation** - Pydantic models for all endpoints
- **Rate limiting** - Per-endpoint limits to prevent abuse
- **Audit logging** - All security events logged
- **CORS protection** - Configured allowed origins only
- **Security headers** - Full complement of security headers
- **Container security** - Non-root user execution

## 📈 Scalability Features

- **Auto-scaling** - 1-100 instances based on load
- **Load balancing** - Cloud Run automatic load distribution
- **Connection pooling** - Efficient database connections
- **Caching ready** - Structure supports Redis integration
- **CDN ready** - Static assets can be served via CDN

## 🏛️ Government/Enterprise Features

- **Government user roles** - Special access controls
- **Audit compliance** - Comprehensive logging
- **Contract monitoring** - Database schema ready
- **Email monitoring** - Framework for email scanning
- **API key management** - Service-to-service auth
- **Session management** - Configurable timeouts

## 💰 Value Proposition

This template provides:
- **$100k+ worth of enterprise development** - Pre-built security infrastructure
- **Months of security engineering** - Production-ready from day one
- **Government compliance ready** - Audit logging and access controls
- **Scalable architecture** - Handles startup to enterprise loads
- **Security best practices** - Following OWASP and cloud security standards

## 📞 Support & Customization

This template is designed to be:
1. **Cloned** for new projects
2. **Customized** for specific business needs
3. **Extended** with additional features
4. **Deployed** to production immediately

Perfect foundation for:
- Government contracting applications
- Enterprise SaaS platforms
- High-security internal tools
- API-first applications
- Multi-tenant systems

---

## 🚀 Ready to Build Your Next Secure Application?

1. Clone this repository
2. Follow the setup steps
3. Customize for your needs
4. Deploy to production
5. Scale with confidence

**Built with enterprise security from the ground up.** 🔒