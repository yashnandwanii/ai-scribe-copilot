const request = require('supertest');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = require('../src/app');
const User = require('../src/models/User');
const Patient = require('../src/models/Patient');
const Session = require('../src/models/Session');

// Test database connection
const MONGODB_TEST_URI = process.env.MONGODB_TEST_URI || 'mongodb://localhost:27017/medication_app_test';

// Test helper functions
class TestHelper {
  static async setupTestDB() {
    await mongoose.connect(MONGODB_TEST_URI);
    await this.clearDatabase();
  }

  static async clearDatabase() {
    const collections = mongoose.connection.collections;
    for (const key in collections) {
      const collection = collections[key];
      await collection.deleteMany({});
    }
  }

  static async closeDatabase() {
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
  }

  static async createTestUser(userData = {}) {
    const defaultUser = {
      name: 'Test Doctor',
      email: 'test@example.com',
      password: 'Test123!@#',
      role: 'doctor',
      specialty: 'General Medicine',
      licenseNumber: 'MD123456',
      isEmailVerified: true,
      isActive: true,
    };

    const user = new User({ ...defaultUser, ...userData });
    await user.save();
    return user;
  }

  static async createTestPatient(doctorId, patientData = {}) {
    const defaultPatient = {
      name: 'Test Patient',
      age: 30,
      sex: 'male',
      address: '123 Test Street, Test City, 12345',
      phone: '+1234567890',
      email: 'patient@example.com',
      doctorId,
      medicalHistory: 'No significant history',
      allergies: ['Penicillin'],
      medications: ['Aspirin'],
      isActive: true,
    };

    const patient = new Patient({ ...defaultPatient, ...patientData });
    await patient.save();
    return patient;
  }

  static async createTestSession(doctorId, patientId, sessionData = {}) {
    const defaultSession = {
      doctorId,
      patientId,
      sessionNotes: 'Test session notes',
      status: 'idle',
      sessionType: 'consultation',
      priority: 'normal',
      patientConsent: {
        recording: true,
        transcription: true,
        storage: true,
        sharing: false,
        consentTimestamp: new Date(),
      },
      createdBy: doctorId,
    };

    const session = new Session({ ...defaultSession, ...sessionData });
    await session.save();
    return session;
  }

  static generateAuthToken(userId, role = 'doctor') {
    return jwt.sign(
      { userId, role },
      process.env.JWT_SECRET || 'test_secret',
      { expiresIn: '1h' }
    );
  }

  static async loginUser(app, credentials = {}) {
    const defaultCredentials = {
      email: 'test@example.com',
      password: 'Test123!@#',
    };

    const response = await request(app)
      .post('/api/v1/auth/login')
      .send({ ...defaultCredentials, ...credentials })
      .expect(200);

    return response.body.data;
  }

  static getAuthHeader(token) {
    return { Authorization: `Bearer ${token}` };
  }

  // Mock data generators
  static generateMockPatientData(overrides = {}) {
    return {
      name: 'John Doe',
      age: Math.floor(Math.random() * 80) + 18,
      sex: Math.random() > 0.5 ? 'male' : 'female',
      address: '123 Main St, City, State 12345',
      phone: '+1234567890',
      email: `patient${Date.now()}@example.com`,
      medicalHistory: 'No significant medical history',
      allergies: ['None'],
      medications: ['Multivitamin'],
      ...overrides,
    };
  }

  static generateMockSessionData(overrides = {}) {
    return {
      sessionNotes: 'Test consultation notes',
      sessionType: 'consultation',
      priority: 'normal',
      ...overrides,
    };
  }

  static generateMockChunkData(overrides = {}) {
    return {
      chunkId: `chunk_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      chunkIndex: 0,
      duration: 30,
      fileSize: 1024 * 1024, // 1MB
      mimeType: 'audio/wav',
      ...overrides,
    };
  }

  // Assertion helpers
  static expectValidationError(response, field) {
    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(response.body.message).toContain('validation');
    if (field) {
      expect(response.body.message.toLowerCase()).toContain(field.toLowerCase());
    }
  }

  static expectAuthError(response) {
    expect(response.status).toBe(401);
    expect(response.body.success).toBe(false);
    expect(response.body.message).toContain('auth');
  }

  static expectNotFoundError(response) {
    expect(response.status).toBe(404);
    expect(response.body.success).toBe(false);
  }

  static expectSuccessResponse(response, statusCode = 200) {
    expect(response.status).toBe(statusCode);
    expect(response.body.success).toBe(true);
    expect(response.body.data).toBeDefined();
  }

  // Database state validators
  static async expectUserExists(email) {
    const user = await User.findOne({ email });
    expect(user).toBeTruthy();
    return user;
  }

  static async expectPatientExists(patientId) {
    const patient = await Patient.findById(patientId);
    expect(patient).toBeTruthy();
    return patient;
  }

  static async expectSessionExists(sessionId) {
    const session = await Session.findById(sessionId);
    expect(session).toBeTruthy();
    return session;
  }

  // Test data cleanup
  static async cleanupTestData() {
    await Promise.all([
      User.deleteMany({ email: /test|mock/ }),
      Patient.deleteMany({ name: /test|mock/i }),
      Session.deleteMany({}),
    ]);
  }
}

// Global test setup and teardown
beforeAll(async () => {
  await TestHelper.setupTestDB();
});

afterAll(async () => {
  await TestHelper.closeDatabase();
});

beforeEach(async () => {
  // Clean up before each test to ensure isolation
  await TestHelper.clearDatabase();
});

// Common test fixtures
const testFixtures = {
  validUserData: {
    name: 'Dr. John Smith',
    email: 'dr.smith@hospital.com',
    password: 'SecurePass123!',
    specialty: 'Cardiology',
    licenseNumber: 'MD789012',
    hospitalAffiliation: 'City General Hospital',
  },

  validPatientData: {
    name: 'Jane Patient',
    age: 35,
    sex: 'female',
    address: '456 Oak Avenue, Springfield, IL 62701',
    phone: '+19876543210',
    email: 'jane.patient@email.com',
    emergencyContact: {
      name: 'John Patient',
      phone: '+19876543211',
      relationship: 'spouse',
    },
    medicalHistory: 'Hypertension, managed with medication',
    allergies: ['Sulfa drugs', 'Shellfish'],
    medications: ['Lisinopril 10mg daily', 'Aspirin 81mg daily'],
  },

  validSessionData: {
    sessionNotes: 'Regular checkup - patient reports feeling well',
    sessionType: 'consultation',
    priority: 'normal',
  },

  invalidData: {
    invalidEmail: 'not-an-email',
    shortPassword: '123',
    longString: 'a'.repeat(1001),
    invalidPhone: '123',
    invalidAge: -5,
    invalidObjectId: 'not-an-object-id',
  },
};

// Export everything for use in test files
module.exports = {
  TestHelper,
  testFixtures,
  app,
  request,
  mongoose,
  jwt,
  bcrypt,
};