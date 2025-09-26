const { TestHelper, testFixtures, app, request } = require('../setup');

describe('Authentication Routes', () => {
  describe('POST /api/v1/auth/register', () => {
    it('should register a new user with valid data', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(testFixtures.validUserData)
        .expect(201);

      TestHelper.expectSuccessResponse(response, 201);
      expect(response.body.data.user).toBeDefined();
      expect(response.body.data.user.email).toBe(testFixtures.validUserData.email);
      expect(response.body.data.user.password).toBeUndefined();
      expect(response.body.data.tokens).toBeDefined();
      expect(response.body.data.tokens.accessToken).toBeDefined();

      // Verify user was created in database
      await TestHelper.expectUserExists(testFixtures.validUserData.email);
    });

    it('should reject registration with invalid email', async () => {
      const invalidData = {
        ...testFixtures.validUserData,
        email: testFixtures.invalidData.invalidEmail,
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(invalidData);

      TestHelper.expectValidationError(response, 'email');
    });

    it('should reject registration with weak password', async () => {
      const invalidData = {
        ...testFixtures.validUserData,
        password: testFixtures.invalidData.shortPassword,
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(invalidData);

      TestHelper.expectValidationError(response, 'password');
    });

    it('should reject duplicate email registration', async () => {
      // First registration
      await request(app)
        .post('/api/v1/auth/register')
        .send(testFixtures.validUserData)
        .expect(201);

      // Duplicate registration
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(testFixtures.validUserData);

      expect(response.status).toBe(409);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('already exists');
    });

    it('should reject registration without required fields', async () => {
      const incompleteData = {
        email: testFixtures.validUserData.email,
        // Missing name and password
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(incompleteData);

      TestHelper.expectValidationError(response);
    });
  });

  describe('POST /api/v1/auth/login', () => {
    let testUser;

    beforeEach(async () => {
      testUser = await TestHelper.createTestUser();
    });

    it('should login with valid credentials', async () => {
      const loginData = {
        email: testUser.email,
        password: 'Test123!@#', // Default password from TestHelper
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData)
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.user).toBeDefined();
      expect(response.body.data.tokens).toBeDefined();
      expect(response.body.data.tokens.accessToken).toBeDefined();
      expect(response.body.data.tokens.refreshToken).toBeDefined();
    });

    it('should reject login with invalid email', async () => {
      const invalidLogin = {
        email: 'nonexistent@example.com',
        password: 'Test123!@#',
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(invalidLogin);

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid credentials');
    });

    it('should reject login with wrong password', async () => {
      const invalidLogin = {
        email: testUser.email,
        password: 'WrongPassword123!',
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(invalidLogin);

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid credentials');
    });

    it('should reject login for inactive user', async () => {
      // Deactivate user
      testUser.isActive = false;
      await testUser.save();

      const loginData = {
        email: testUser.email,
        password: 'Test123!@#',
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData);

      expect(response.status).toBe(401);
      expect(response.body.message).toContain('account');
    });

    it('should update lastLogin timestamp', async () => {
      const originalLastLogin = testUser.lastLogin;

      await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: 'Test123!@#',
        })
        .expect(200);

      // Refresh user from database
      await testUser.reload();
      expect(testUser.lastLogin).not.toEqual(originalLastLogin);
    });
  });

  describe('POST /api/v1/auth/refresh', () => {
    let testUser, refreshToken;

    beforeEach(async () => {
      testUser = await TestHelper.createTestUser();
      const loginResponse = await TestHelper.loginUser(app);
      refreshToken = loginResponse.tokens.refreshToken;
    });

    it('should refresh tokens with valid refresh token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken })
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.tokens).toBeDefined();
      expect(response.body.data.tokens.accessToken).toBeDefined();
      expect(response.body.data.tokens.refreshToken).toBeDefined();
    });

    it('should reject invalid refresh token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: 'invalid-token' });

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });

    it('should reject missing refresh token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({});

      TestHelper.expectValidationError(response, 'refreshToken');
    });
  });

  describe('POST /api/v1/auth/logout', () => {
    let testUser, accessToken, refreshToken;

    beforeEach(async () => {
      testUser = await TestHelper.createTestUser();
      const loginResponse = await TestHelper.loginUser(app);
      accessToken = loginResponse.tokens.accessToken;
      refreshToken = loginResponse.tokens.refreshToken;
    });

    it('should logout successfully with valid token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .set(TestHelper.getAuthHeader(accessToken))
        .send({ refreshToken })
        .expect(200);

      TestHelper.expectSuccessResponse(response);
    });

    it('should logout all devices', async () => {
      const response = await request(app)
        .post('/api/v1/auth/logout-all')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
    });

    it('should require authentication for logout', async () => {
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .send({ refreshToken });

      TestHelper.expectAuthError(response);
    });
  });

  describe('GET /api/v1/auth/profile', () => {
    let testUser, accessToken;

    beforeEach(async () => {
      testUser = await TestHelper.createTestUser();
      const loginResponse = await TestHelper.loginUser(app);
      accessToken = loginResponse.tokens.accessToken;
    });

    it('should get user profile with valid token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/profile')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.user).toBeDefined();
      expect(response.body.data.user.email).toBe(testUser.email);
      expect(response.body.data.user.password).toBeUndefined();
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .get('/api/v1/auth/profile');

      TestHelper.expectAuthError(response);
    });

    it('should reject invalid token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/profile')
        .set(TestHelper.getAuthHeader('invalid-token'));

      TestHelper.expectAuthError(response);
    });
  });

  describe('PUT /api/v1/auth/profile', () => {
    let testUser, accessToken;

    beforeEach(async () => {
      testUser = await TestHelper.createTestUser();
      const loginResponse = await TestHelper.loginUser(app);
      accessToken = loginResponse.tokens.accessToken;
    });

    it('should update profile with valid data', async () => {
      const updateData = {
        name: 'Updated Doctor Name',
        specialty: 'Updated Specialty',
        phone: '+1987654321',
      };

      const response = await request(app)
        .put('/api/v1/auth/profile')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(updateData)
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.user.name).toBe(updateData.name);
      expect(response.body.data.user.specialty).toBe(updateData.specialty);
    });

    it('should reject invalid phone number', async () => {
      const updateData = {
        phone: testFixtures.invalidData.invalidPhone,
      };

      const response = await request(app)
        .put('/api/v1/auth/profile')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(updateData);

      TestHelper.expectValidationError(response, 'phone');
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .put('/api/v1/auth/profile')
        .send({ name: 'New Name' });

      TestHelper.expectAuthError(response);
    });
  });

  describe('POST /api/v1/auth/change-password', () => {
    let testUser, accessToken;

    beforeEach(async () => {
      testUser = await TestHelper.createTestUser();
      const loginResponse = await TestHelper.loginUser(app);
      accessToken = loginResponse.tokens.accessToken;
    });

    it('should change password with valid data', async () => {
      const passwordData = {
        currentPassword: 'Test123!@#',
        newPassword: 'NewSecure123!@#',
        confirmPassword: 'NewSecure123!@#',
      };

      const response = await request(app)
        .post('/api/v1/auth/change-password')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(passwordData)
        .expect(200);

      TestHelper.expectSuccessResponse(response);

      // Verify new password works
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: passwordData.newPassword,
        })
        .expect(200);

      expect(loginResponse.body.success).toBe(true);
    });

    it('should reject wrong current password', async () => {
      const passwordData = {
        currentPassword: 'WrongPassword123!',
        newPassword: 'NewSecure123!@#',
        confirmPassword: 'NewSecure123!@#',
      };

      const response = await request(app)
        .post('/api/v1/auth/change-password')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(passwordData);

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('current password');
    });

    it('should reject mismatched passwords', async () => {
      const passwordData = {
        currentPassword: 'Test123!@#',
        newPassword: 'NewSecure123!@#',
        confirmPassword: 'DifferentPassword123!@#',
      };

      const response = await request(app)
        .post('/api/v1/auth/change-password')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(passwordData);

      TestHelper.expectValidationError(response, 'password');
    });
  });

  describe('Password Reset Flow', () => {
    let testUser;

    beforeEach(async () => {
      testUser = await TestHelper.createTestUser();
    });

    it('should initiate password reset with valid email', async () => {
      const response = await request(app)
        .post('/api/v1/auth/forgot-password')
        .send({ email: testUser.email })
        .expect(200);

      TestHelper.expectSuccessResponse(response);
    });

    it('should handle non-existent email gracefully', async () => {
      const response = await request(app)
        .post('/api/v1/auth/forgot-password')
        .send({ email: 'nonexistent@example.com' })
        .expect(200);

      // Should still return success for security reasons
      TestHelper.expectSuccessResponse(response);
    });

    it('should reject invalid email format', async () => {
      const response = await request(app)
        .post('/api/v1/auth/forgot-password')
        .send({ email: testFixtures.invalidData.invalidEmail });

      TestHelper.expectValidationError(response, 'email');
    });
  });
});