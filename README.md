# Medication App Backend

A bulletproof, enterprise-grade Node.js Express backend for the Flutter medication recording application. Built with security-first principles and comprehensive error handling.

## 🏗️ Architecture Overview

This backend implements a layered architecture with:
- **Security Layer**: Multi-layer authentication, rate limiting, input sanitization
- **API Layer**: RESTful endpoints with comprehensive validation
- **Business Logic Layer**: Domain-specific operations and data processing
- **Data Access Layer**: MongoDB with Mongoose ODM
- **Caching Layer**: Redis for session management and performance
- **Storage Layer**: AWS S3 for secure file storage

## 🔒 Security Features

### Authentication & Authorization
- JWT-based authentication with refresh tokens
- Role-based access control (RBAC)
- Password hashing with bcrypt (12 salt rounds)
- Token blacklisting for secure logout
- Session management with Redis

### Data Protection
- Input validation with Joi schemas
- NoSQL injection prevention
- XSS protection with helmet
- CORS configuration
- Rate limiting and DDoS protection
- Parameter pollution prevention
- Request size limits

### File Security
- Secure file uploads to AWS S3
- Presigned URLs for controlled access
- File type validation
- Size restrictions
- Virus scanning ready integration

## 🚀 Getting Started

### Prerequisites
- Node.js 18+
- MongoDB 4.4+
- Redis 6.0+
- AWS Account (for S3)

### Installation

1. **Clone and setup:**
```bash
git clone <repository-url>
cd backend
npm install
```

2. **Environment configuration:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Required environment variables:**
```env
# Server Configuration
NODE_ENV=development
PORT=3000
API_VERSION=v1

# Database
MONGODB_URI=mongodb://localhost:27017/medication_app
MONGODB_TEST_URI=mongodb://localhost:27017/medication_app_test

# Redis
REDIS_URL=redis://localhost:6379

# JWT Secrets (Use strong, unique secrets in production)
JWT_SECRET=your_jwt_secret_here_minimum_32_characters
JWT_REFRESH_SECRET=your_jwt_refresh_secret_here_minimum_32_characters
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# AWS Configuration
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-east-1
AWS_S3_BUCKET=your-s3-bucket-name

# Security
BCRYPT_SALT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Email (Optional - for password reset)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
FROM_EMAIL=noreply@yourapp.com
FROM_NAME=Medication App
```

4. **Start the application:**
```bash
# Development
npm run dev

# Production
npm start
```

## 📋 API Documentation

### Base URL
```
Development: http://localhost:3000/api/v1
Production: https://your-domain.com/api/v1
```

### Authentication Endpoints

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
  "name": "Dr. John Smith",
  "email": "dr.smith@hospital.com",
  "password": "SecurePass123!",
  "specialty": "Cardiology",
  "licenseNumber": "MD123456"
}
```

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "dr.smith@hospital.com",
  "password": "SecurePass123!",
  "rememberMe": false
}
```

#### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "your_refresh_token_here"
}
```

### Patient Management

#### Create Patient
```http
POST /patients
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "John Doe",
  "age": 35,
  "sex": "male",
  "address": "123 Main St, City, State 12345",
  "phone": "+1234567890",
  "email": "john.doe@email.com",
  "medicalHistory": "No significant history",
  "allergies": ["Penicillin"],
  "medications": ["Aspirin 81mg daily"]
}
```

#### Get Patients
```http
GET /patients?page=1&limit=10&search=john&age_min=18&age_max=65
Authorization: Bearer <token>
```

### Session Management

#### Create Recording Session
```http
POST /sessions
Authorization: Bearer <token>
Content-Type: application/json

{
  "patientId": "patient_id_here",
  "notes": "Regular consultation",
  "sessionType": "consultation",
  "priority": "normal"
}
```

#### Upload Audio Chunk
```http
POST /sessions/{sessionId}/chunks
Authorization: Bearer <token>
Content-Type: application/json

{
  "chunkId": "unique_chunk_id",
  "chunkIndex": 0,
  "duration": 30,
  "fileSize": 1048576,
  "mimeType": "audio/wav"
}
```

### File Upload

#### Get Presigned Upload URL
```http
POST /uploads/presigned-url
Authorization: Bearer <token>
Content-Type: application/json

{
  "fileName": "audio_chunk_001.wav",
  "fileType": "audio",
  "fileSize": 1048576,
  "sessionId": "session_id_here",
  "chunkId": "chunk_id_here",
  "contentType": "audio/wav"
}
```

### Health Monitoring

#### Basic Health Check
```http
GET /health
```

#### Detailed Health Check
```http
GET /health/detailed
Authorization: Bearer <token>
```

## 🧪 Testing

### Run Tests
```bash
# All tests
npm test

# Specific test suites
npm run test:auth
npm run test:patients
npm run test:health

# Watch mode
npm run test:watch

# Coverage report
npm run test:coverage
```

### Test Structure
```
tests/
├── setup.js          # Test configuration and helpers
├── auth.test.js       # Authentication tests
├── patients.test.js   # Patient management tests
├── health.test.js     # Health monitoring tests
└── ...
```

## 📊 Database Schema

### User Model
```javascript
{
  name: String,           // Doctor's full name
  email: String,          // Unique email address
  password: String,       // Hashed password
  role: String,           // 'doctor' | 'admin'
  specialty: String,      // Medical specialty
  licenseNumber: String,  // Medical license number
  isEmailVerified: Boolean,
  isActive: Boolean,
  lastLogin: Date,
  refreshTokens: [String]
}
```

### Patient Model
```javascript
{
  name: String,
  age: Number,
  sex: String,           // 'male' | 'female' | 'other'
  address: String,
  phone: String,
  email: String,
  doctorId: ObjectId,    // Reference to User
  medicalHistory: String,
  allergies: [String],
  medications: [String],
  isActive: Boolean
}
```

### Session Model
```javascript
{
  doctorId: ObjectId,
  patientId: ObjectId,
  status: String,        // 'idle' | 'recording' | 'completed' | etc.
  sessionNotes: String,
  transcript: String,
  chunks: [{
    chunkId: String,
    s3Key: String,
    uploadStatus: String,
    duration: Number,
    fileSize: Number
  }],
  patientConsent: {
    recording: Boolean,
    transcription: Boolean,
    storage: Boolean
  }
}
```

## 🔧 Configuration

### Security Configuration
- **Rate Limiting**: 100 requests per 15 minutes per IP
- **File Upload Limits**: 100MB per audio file, 50MB per document
- **Password Requirements**: Minimum 8 characters, mixed case, numbers, symbols
- **JWT Expiration**: 15 minutes for access tokens, 7 days for refresh tokens

### Database Configuration
- **Connection Pooling**: Maximum 10 connections
- **Auto-reconnection**: Enabled with exponential backoff
- **Indexes**: Optimized for common queries

### AWS S3 Configuration
- **Bucket Structure**: `uploads/{userId}/{fileType}/{sessionId}/`
- **Presigned URL Expiration**: 1 hour
- **File Retention**: Configurable (default: permanent)

## 🚀 Deployment

### Docker Deployment
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Environment-Specific Configurations

#### Development
- Debug logging enabled
- CORS allows all origins
- Detailed error messages

#### Production
- Security headers enforced
- Error details hidden
- Performance optimizations
- Health check endpoints

### Monitoring & Logging
- **Winston Logger**: Structured logging with multiple transports
- **Health Checks**: Kubernetes-compatible liveness/readiness probes
- **Metrics**: Application and system metrics collection
- **Error Tracking**: Comprehensive error logging and alerting

## 📈 Performance Optimizations

### Caching Strategy
- **Redis Caching**: Session data, frequent queries
- **Application-Level Caching**: User permissions, lookup tables
- **HTTP Caching**: Static resources, API responses

### Database Optimizations
- **Indexes**: On frequently queried fields
- **Aggregation Pipelines**: For complex analytics
- **Connection Pooling**: Efficient database connections

### API Optimizations
- **Compression**: Gzip compression for responses
- **Pagination**: All list endpoints support pagination
- **Field Selection**: Reduce payload size with field filtering

## 🔍 Monitoring & Observability

### Health Endpoints
- `GET /health` - Basic health status
- `GET /health/detailed` - Comprehensive system check
- `GET /health/liveness` - Kubernetes liveness probe
- `GET /health/readiness` - Kubernetes readiness probe
- `GET /health/metrics` - Application metrics

### Logging
- **Structured Logging**: JSON format for log aggregation
- **Log Levels**: Error, Warn, Info, Debug
- **Request Logging**: All API requests logged
- **Audit Trail**: User actions and data changes

## 🛡️ Security Best Practices

### Input Validation
- All inputs validated with Joi schemas
- SQL injection prevention
- XSS attack prevention
- File upload validation

### Authentication Security
- JWT tokens with short expiration
- Refresh token rotation
- Password complexity requirements
- Account lockout after failed attempts

### Data Protection
- Sensitive data encryption at rest
- TLS/SSL for data in transit
- Regular security audits
- Dependency vulnerability scanning

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Follow the coding standards
4. Add comprehensive tests
5. Submit a pull request

### Code Standards
- ESLint configuration provided
- Prettier for code formatting
- JSDoc comments for functions
- Comprehensive error handling

### Testing Requirements
- Unit tests for all business logic
- Integration tests for API endpoints
- Minimum 80% code coverage
- Security vulnerability tests

## 📞 Support

For technical support or questions:
- Create an issue in the repository
- Review the API documentation
- Check the health endpoints for system status
- Review logs for error details

## 📄 License

This project is licensed under the MIT License. See LICENSE file for details.

---

**Built with ❤️ for healthcare professionals**

*This backend provides enterprise-grade security, scalability, and reliability for healthcare data management while maintaining compliance with healthcare data protection standards.*