const { TestHelper, testFixtures, app, request } = require('../setup');

describe('Patient Routes', () => {
  let testUser, testPatient, accessToken;

  beforeEach(async () => {
    testUser = await TestHelper.createTestUser();
    const loginResponse = await TestHelper.loginUser(app);
    accessToken = loginResponse.tokens.accessToken;
    testPatient = await TestHelper.createTestPatient(testUser._id);
  });

  describe('POST /api/v1/patients', () => {
    it('should create a new patient with valid data', async () => {
      const patientData = TestHelper.generateMockPatientData();

      const response = await request(app)
        .post('/api/v1/patients')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(patientData)
        .expect(201);

      TestHelper.expectSuccessResponse(response, 201);
      expect(response.body.data.patient).toBeDefined();
      expect(response.body.data.patient.name).toBe(patientData.name);
      expect(response.body.data.patient.doctorId).toBe(testUser._id.toString());

      // Verify patient was created in database
      await TestHelper.expectPatientExists(response.body.data.patient._id);
    });

    it('should require authentication', async () => {
      const patientData = TestHelper.generateMockPatientData();

      const response = await request(app)
        .post('/api/v1/patients')
        .send(patientData);

      TestHelper.expectAuthError(response);
    });

    it('should reject invalid age', async () => {
      const patientData = TestHelper.generateMockPatientData({
        age: testFixtures.invalidData.invalidAge,
      });

      const response = await request(app)
        .post('/api/v1/patients')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(patientData);

      TestHelper.expectValidationError(response, 'age');
    });

    it('should reject invalid email format', async () => {
      const patientData = TestHelper.generateMockPatientData({
        email: testFixtures.invalidData.invalidEmail,
      });

      const response = await request(app)
        .post('/api/v1/patients')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(patientData);

      TestHelper.expectValidationError(response, 'email');
    });

    it('should reject missing required fields', async () => {
      const incompleteData = {
        name: 'Test Patient',
        // Missing age, sex, address
      };

      const response = await request(app)
        .post('/api/v1/patients')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(incompleteData);

      TestHelper.expectValidationError(response);
    });

    it('should handle emergency contact validation', async () => {
      const patientData = TestHelper.generateMockPatientData({
        emergencyContact: {
          name: 'Emergency Contact',
          phone: testFixtures.invalidData.invalidPhone, // Invalid phone
          relationship: 'spouse',
        },
      });

      const response = await request(app)
        .post('/api/v1/patients')
        .set(TestHelper.getAuthHeader(accessToken))
        .send(patientData);

      TestHelper.expectValidationError(response, 'phone');
    });
  });

  describe('GET /api/v1/patients', () => {
    beforeEach(async () => {
      // Create additional test patients
      await TestHelper.createTestPatient(testUser._id, { name: 'Alice Patient', age: 25 });
      await TestHelper.createTestPatient(testUser._id, { name: 'Bob Patient', age: 45 });
    });

    it('should get all patients for authenticated doctor', async () => {
      const response = await request(app)
        .get('/api/v1/patients')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.patients).toBeDefined();
      expect(Array.isArray(response.body.data.patients)).toBe(true);
      expect(response.body.data.patients.length).toBe(3); // Original + 2 new
      expect(response.body.data.pagination).toBeDefined();
    });

    it('should support pagination', async () => {
      const response = await request(app)
        .get('/api/v1/patients?page=1&limit=2')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.patients.length).toBe(2);
      expect(response.body.data.pagination.page).toBe(1);
      expect(response.body.data.pagination.limit).toBe(2);
    });

    it('should support search by name', async () => {
      const response = await request(app)
        .get('/api/v1/patients?search=Alice')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.patients.length).toBe(1);
      expect(response.body.data.patients[0].name).toContain('Alice');
    });

    it('should support age filtering', async () => {
      const response = await request(app)
        .get('/api/v1/patients?age_min=30&age_max=50')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      response.body.data.patients.forEach(patient => {
        expect(patient.age).toBeGreaterThanOrEqual(30);
        expect(patient.age).toBeLessThanOrEqual(50);
      });
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .get('/api/v1/patients');

      TestHelper.expectAuthError(response);
    });

    it('should only return patients belonging to the doctor', async () => {
      // Create another doctor and patient
      const otherUser = await TestHelper.createTestUser({ email: 'other@example.com' });
      await TestHelper.createTestPatient(otherUser._id, { name: 'Other Doctor Patient' });

      const response = await request(app)
        .get('/api/v1/patients')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      // Should not include the other doctor's patient
      const patientNames = response.body.data.patients.map(p => p.name);
      expect(patientNames).not.toContain('Other Doctor Patient');
    });
  });

  describe('GET /api/v1/patients/:id', () => {
    it('should get patient by ID', async () => {
      const response = await request(app)
        .get(`/api/v1/patients/${testPatient._id}`)
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.patient).toBeDefined();
      expect(response.body.data.patient._id).toBe(testPatient._id.toString());
      expect(response.body.data.patient.name).toBe(testPatient.name);
    });

    it('should return 404 for non-existent patient', async () => {
      const fakeId = '507f1f77bcf86cd799439011';
      const response = await request(app)
        .get(`/api/v1/patients/${fakeId}`)
        .set(TestHelper.getAuthHeader(accessToken));

      TestHelper.expectNotFoundError(response);
    });

    it('should return 400 for invalid patient ID', async () => {
      const response = await request(app)
        .get('/api/v1/patients/invalid-id')
        .set(TestHelper.getAuthHeader(accessToken));

      expect(response.status).toBe(400);
    });

    it('should not allow access to other doctor\'s patients', async () => {
      // Create another doctor and patient
      const otherUser = await TestHelper.createTestUser({ email: 'other@example.com' });
      const otherPatient = await TestHelper.createTestPatient(otherUser._id);

      const response = await request(app)
        .get(`/api/v1/patients/${otherPatient._id}`)
        .set(TestHelper.getAuthHeader(accessToken));

      TestHelper.expectNotFoundError(response);
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .get(`/api/v1/patients/${testPatient._id}`);

      TestHelper.expectAuthError(response);
    });
  });

  describe('PUT /api/v1/patients/:id', () => {
    it('should update patient with valid data', async () => {
      const updateData = {
        name: 'Updated Patient Name',
        age: 35,
        phone: '+1987654321',
      };

      const response = await request(app)
        .put(`/api/v1/patients/${testPatient._id}`)
        .set(TestHelper.getAuthHeader(accessToken))
        .send(updateData)
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.patient.name).toBe(updateData.name);
      expect(response.body.data.patient.age).toBe(updateData.age);
      expect(response.body.data.patient.phone).toBe(updateData.phone);
    });

    it('should reject invalid data', async () => {
      const updateData = {
        age: testFixtures.invalidData.invalidAge,
      };

      const response = await request(app)
        .put(`/api/v1/patients/${testPatient._id}`)
        .set(TestHelper.getAuthHeader(accessToken))
        .send(updateData);

      TestHelper.expectValidationError(response, 'age');
    });

    it('should return 404 for non-existent patient', async () => {
      const fakeId = '507f1f77bcf86cd799439011';
      const response = await request(app)
        .put(`/api/v1/patients/${fakeId}`)
        .set(TestHelper.getAuthHeader(accessToken))
        .send({ name: 'Updated Name' });

      TestHelper.expectNotFoundError(response);
    });

    it('should not allow updating other doctor\'s patients', async () => {
      const otherUser = await TestHelper.createTestUser({ email: 'other@example.com' });
      const otherPatient = await TestHelper.createTestPatient(otherUser._id);

      const response = await request(app)
        .put(`/api/v1/patients/${otherPatient._id}`)
        .set(TestHelper.getAuthHeader(accessToken))
        .send({ name: 'Unauthorized Update' });

      TestHelper.expectNotFoundError(response);
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .put(`/api/v1/patients/${testPatient._id}`)
        .send({ name: 'Updated Name' });

      TestHelper.expectAuthError(response);
    });
  });

  describe('DELETE /api/v1/patients/:id', () => {
    it('should archive patient (soft delete)', async () => {
      const response = await request(app)
        .delete(`/api/v1/patients/${testPatient._id}`)
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);

      // Verify patient is archived, not deleted
      const archivedPatient = await TestHelper.expectPatientExists(testPatient._id);
      expect(archivedPatient.isActive).toBe(false);
    });

    it('should return 404 for non-existent patient', async () => {
      const fakeId = '507f1f77bcf86cd799439011';
      const response = await request(app)
        .delete(`/api/v1/patients/${fakeId}`)
        .set(TestHelper.getAuthHeader(accessToken));

      TestHelper.expectNotFoundError(response);
    });

    it('should not allow deleting other doctor\'s patients', async () => {
      const otherUser = await TestHelper.createTestUser({ email: 'other@example.com' });
      const otherPatient = await TestHelper.createTestPatient(otherUser._id);

      const response = await request(app)
        .delete(`/api/v1/patients/${otherPatient._id}`)
        .set(TestHelper.getAuthHeader(accessToken));

      TestHelper.expectNotFoundError(response);
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .delete(`/api/v1/patients/${testPatient._id}`);

      TestHelper.expectAuthError(response);
    });
  });

  describe('Patient Statistics', () => {
    beforeEach(async () => {
      // Create patients with various demographics
      await TestHelper.createTestPatient(testUser._id, { 
        name: 'Young Male', 
        age: 25, 
        sex: 'male' 
      });
      await TestHelper.createTestPatient(testUser._id, { 
        name: 'Middle Aged Female', 
        age: 45, 
        sex: 'female' 
      });
      await TestHelper.createTestPatient(testUser._id, { 
        name: 'Senior Male', 
        age: 70, 
        sex: 'male' 
      });
    });

    it('should get patient statistics', async () => {
      const response = await request(app)
        .get('/api/v1/patients/stats/overview')
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.totalPatients).toBe(4); // Original + 3 new
      expect(response.body.data.demographics).toBeDefined();
      expect(response.body.data.ageGroups).toBeDefined();
    });

    it('should require authentication for statistics', async () => {
      const response = await request(app)
        .get('/api/v1/patients/stats/overview');

      TestHelper.expectAuthError(response);
    });
  });

  describe('Patient Medications and Allergies', () => {
    it('should add medication to patient', async () => {
      const medicationData = {
        medication: 'Aspirin 81mg daily',
      };

      const response = await request(app)
        .post(`/api/v1/patients/${testPatient._id}/medications`)
        .set(TestHelper.getAuthHeader(accessToken))
        .send(medicationData)
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.patient.medications).toContain(medicationData.medication);
    });

    it('should remove medication from patient', async () => {
      // First add a medication
      testPatient.medications.push('Test Medication');
      await testPatient.save();

      const response = await request(app)
        .delete(`/api/v1/patients/${testPatient._id}/medications`)
        .set(TestHelper.getAuthHeader(accessToken))
        .send({ medication: 'Test Medication' })
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.patient.medications).not.toContain('Test Medication');
    });

    it('should add allergy to patient', async () => {
      const allergyData = {
        allergy: 'Shellfish',
      };

      const response = await request(app)
        .post(`/api/v1/patients/${testPatient._id}/allergies`)
        .set(TestHelper.getAuthHeader(accessToken))
        .send(allergyData)
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.patient.allergies).toContain(allergyData.allergy);
    });

    it('should remove allergy from patient', async () => {
      // First add an allergy
      testPatient.allergies.push('Test Allergy');
      await testPatient.save();

      const response = await request(app)
        .delete(`/api/v1/patients/${testPatient._id}/allergies`)
        .set(TestHelper.getAuthHeader(accessToken))
        .send({ allergy: 'Test Allergy' })
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.patient.allergies).not.toContain('Test Allergy');
    });
  });

  describe('Patient Sessions', () => {
    let testSession;

    beforeEach(async () => {
      testSession = await TestHelper.createTestSession(testUser._id, testPatient._id);
    });

    it('should get patient sessions', async () => {
      const response = await request(app)
        .get(`/api/v1/patients/${testPatient._id}/sessions`)
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.sessions).toBeDefined();
      expect(Array.isArray(response.body.data.sessions)).toBe(true);
      expect(response.body.data.sessions.length).toBe(1);
      expect(response.body.data.sessions[0]._id).toBe(testSession._id.toString());
    });

    it('should support session filtering', async () => {
      // Create another session with different status
      await TestHelper.createTestSession(testUser._id, testPatient._id, {
        status: 'completed',
      });

      const response = await request(app)
        .get(`/api/v1/patients/${testPatient._id}/sessions?status=completed`)
        .set(TestHelper.getAuthHeader(accessToken))
        .expect(200);

      TestHelper.expectSuccessResponse(response);
      expect(response.body.data.sessions.length).toBe(1);
      expect(response.body.data.sessions[0].status).toBe('completed');
    });
  });
});