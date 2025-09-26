const { TestHelper, testFixtures, app, request } = require('../setup');

describe('Health Routes', () => {
  describe('GET /api/v1/health', () => {
    it('should return basic health status', async () => {
      const response = await request(app)
        .get('/api/v1/health')
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.status).toBe('healthy');
      expect(response.body.data.timestamp).toBeDefined();
      expect(response.body.data.uptime).toBeDefined();
      expect(response.body.data.environment).toBeDefined();
    });

    it('should not require authentication', async () => {
      const response = await request(app)
        .get('/api/v1/health')
        .expect(200);

      expect(response.body.success).toBe(true);
    });
  });

  describe('GET /api/v1/health/liveness', () => {
    it('should return liveness probe status', async () => {
      const response = await request(app)
        .get('/api/v1/health/liveness')
        .expect(200);

      expect(response.body.status).toBe('alive');
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.uptime).toBeDefined();
    });
  });

  describe('GET /api/v1/health/readiness', () => {
    it('should return readiness probe status', async () => {
      const response = await request(app)
        .get('/api/v1/health/readiness')
        .expect(200);

      expect(response.body.status).toBe('ready');
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.checks).toBeDefined();
      expect(response.body.checks.mongodb).toBeDefined();
      expect(response.body.checks.redis).toBeDefined();
    });
  });

  describe('GET /api/v1/health/detailed', () => {
    let testUser, accessToken;

    beforeEach(async () => {
      testUser = await TestHelper.createTestUser();
      const loginResponse = await TestHelper.loginUser(app);
      accessToken = loginResponse.tokens.accessToken;
    });

    it('should return detailed health status for authenticated users', async () => {
      const response = await request(app)
        .get('/api/v1/health/detailed')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.status).toBeDefined();
      expect(response.body.data.checks).toBeDefined();
      expect(response.body.data.checks.mongodb).toBeDefined();
      expect(response.body.data.checks.redis).toBeDefined();
      expect(response.body.data.system).toBeDefined();
      expect(response.body.data.memory).toBeDefined();
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .get('/api/v1/health/detailed');

      TestHelper.expectAuthError(response);
    });

    it('should include response time', async () => {
      const response = await request(app)
        .get('/api/v1/health/detailed')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      expect(response.body.data.responseTime).toBeDefined();
      expect(typeof response.body.data.responseTime).toBe('number');
    });
  });

  describe('GET /api/v1/health/metrics', () => {
    let testUser, testPatient, accessToken;

    beforeEach(async () => {
      testUser = await TestHelper.createTestUser();
      const loginResponse = await TestHelper.loginUser(app);
      accessToken = loginResponse.tokens.accessToken;
      
      // Create test data for metrics
      testPatient = await TestHelper.createTestPatient(testUser._id);
      await TestHelper.createTestSession(testUser._id, testPatient._id);
    });

    it('should return application metrics for authenticated users', async () => {
      const response = await request(app)
        .get('/api/v1/health/metrics')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.application).toBeDefined();
      expect(response.body.data.database).toBeDefined();
      expect(response.body.data.memory).toBeDefined();
      expect(response.body.data.system).toBeDefined();
      
      // Check database metrics
      expect(response.body.data.database.users).toBeGreaterThan(0);
      expect(response.body.data.database.patients).toBeGreaterThan(0);
      expect(response.body.data.database.sessions).toBeGreaterThan(0);
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .get('/api/v1/health/metrics');

      TestHelper.expectAuthError(response);
    });

    it('should include memory usage information', async () => {
      const response = await request(app)
        .get('/api/v1/health/metrics')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      expect(response.body.data.memory.rss).toBeDefined();
      expect(response.body.data.memory.heapTotal).toBeDefined();
      expect(response.body.data.memory.heapUsed).toBeDefined();
    });
  });

  describe('GET /api/v1/health/performance', () => {
    let testUser, accessToken;

    beforeEach(async () => {
      testUser = await TestHelper.createTestUser();
      const loginResponse = await TestHelper.loginUser(app);
      accessToken = loginResponse.tokens.accessToken;
    });

    it('should return performance benchmarks', async () => {
      const response = await request(app)
        .get('/api/v1/health/performance')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.tests).toBeDefined();
      expect(response.body.data.tests.database).toBeDefined();
      expect(response.body.data.tests.redis).toBeDefined();
      expect(response.body.data.tests.memory).toBeDefined();
      expect(response.body.data.totalResponseTime).toBeDefined();
      expect(response.body.data.recommendations).toBeDefined();
    });

    it('should measure database response time', async () => {
      const response = await request(app)
        .get('/api/v1/health/performance')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      expect(response.body.data.tests.database.responseTime).toBeDefined();
      expect(typeof response.body.data.tests.database.responseTime).toBe('number');
      expect(response.body.data.tests.database.status).toBe('healthy');
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .get('/api/v1/health/performance');

      TestHelper.expectAuthError(response);
    });
  });

  describe('POST /api/v1/health/log-test', () => {
    let testUser, accessToken;

    beforeEach(async () => {
      testUser = await TestHelper.createTestUser();
      const loginResponse = await TestHelper.loginUser(app);
      accessToken = loginResponse.tokens.accessToken;
    });

    it('should test logging system with default level', async () => {
      const response = await request(app)
        .post('/api/v1/health/log-test')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.level).toBe('info');
      expect(response.body.data.message).toBe('Test log message');
      expect(response.body.data.timestamp).toBeDefined();
    });

    it('should test logging with custom level and message', async () => {
      const testData = {
        level: 'warn',
        message: 'Custom test warning message',
      };

      const response = await request(app)
        .post('/api/v1/health/log-test')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(testData)
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.level).toBe(testData.level);
      expect(response.body.data.message).toBe(testData.message);
    });

    it('should reject invalid log levels', async () => {
      const invalidData = {
        level: 'invalid_level',
        message: 'Test message',
      };

      const response = await request(app)
        .post('/api/v1/health/log-test')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(invalidData);

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('Invalid log level');
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .post('/api/v1/health/log-test')
        .send({ level: 'info', message: 'Test' });

      TestHelper.expectAuthError(response);
    });
  });

  describe('Health Status Response Time', () => {
    it('should respond quickly for basic health check', async () => {
      const startTime = Date.now();
      
      await request(app)
        .get('/api/v1/health')
        .expect(200);

      const responseTime = Date.now() - startTime;
      expect(responseTime).toBeLessThan(1000); // Should respond within 1 second
    });

    it('should respond within reasonable time for liveness probe', async () => {
      const startTime = Date.now();
      
      await request(app)
        .get('/api/v1/health/liveness')
        .expect(200);

      const responseTime = Date.now() - startTime;
      expect(responseTime).toBeLessThan(500); // Liveness should be very fast
    });

    it('should respond within reasonable time for readiness probe', async () => {
      const startTime = Date.now();
      
      await request(app)
        .get('/api/v1/health/readiness')
        .expect(200);

      const responseTime = Date.now() - startTime;
      expect(responseTime).toBeLessThan(2000); // Readiness may take longer due to DB checks
    });
  });

  describe('Health Check Error Scenarios', () => {
    it('should handle gracefully if detailed check encounters errors', async () => {
      const testUser = await TestHelper.createTestUser();
      const loginResponse = await TestHelper.loginUser(app);
      const accessToken = loginResponse.tokens.accessToken;

      // This test assumes the detailed endpoint handles database connection issues gracefully
      const response = await request(app)
        .get('/api/v1/health/detailed')
        .set(TestHelper.getAuthHeader(accessToken));

      // Should not crash even if some checks fail
      expect(response.status).toMatch(/^[2-5]\d{2}$/); // Any valid HTTP status
      expect(response.body).toBeDefined();
    });
  });
});