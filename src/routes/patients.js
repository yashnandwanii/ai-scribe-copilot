const express = require('express');
const { authenticate, authorize, checkOwnership } = require('../middleware/auth');
const { validate, patientValidation } = require('../utils/validation');
const ResponseUtils = require('../utils/response');
const logger = require('../utils/logger');
const Patient = require('../models/Patient');
const { asyncErrorHandler } = require('../middleware/errorHandler');

const router = express.Router();

/**
 * @route   GET /api/v1/patients
 * @desc    Get all patients for authenticated doctor
 * @access  Private (Doctor, Admin)
 */
router.get('/',
  authenticate,
  validate(patientValidation.list, 'query'),
  asyncErrorHandler(async (req, res) => {
    const {
      page = 1,
      limit = 10,
      sort = '-createdAt',
      search = '',
      age_min,
      age_max,
      sex,
      priority
    } = req.query;

    const doctorId = req.user.role === 'admin' ? req.query.doctorId : req.user._id;
    
    if (!doctorId) {
      return ResponseUtils.error(res, 'Doctor ID is required for admin users', 400);
    }

    try {
      // Build query
      const query = { doctorId, isActive: true };
      
      // Add search functionality
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: 'i' } },
          { 'emergencyContact.name': { $regex: search, $options: 'i' } },
          { address: { $regex: search, $options: 'i' } }
        ];
      }
      
      // Add filters
      if (age_min || age_max) {
        query.age = {};
        if (age_min) query.age.$gte = parseInt(age_min);
        if (age_max) query.age.$lte = parseInt(age_max);
      }
      
      if (sex) query.sex = sex;
      if (priority) query.priority = priority;

      // Get total count for pagination
      const total = await Patient.countDocuments(query);
      
      // Calculate pagination
      const totalPages = Math.ceil(total / limit);
      const skip = (page - 1) * limit;

      // Fetch patients
      const patients = await Patient.find(query)
        .populate('doctorId', 'name email specialty')
        .populate('createdBy', 'name email')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit))
        .lean();

      // Add virtual fields manually for lean queries
      const patientsWithVirtuals = patients.map(patient => ({
        ...patient,
        id: patient._id,
        contactInfo: {
          phone: patient.phone,
          email: patient.email,
          address: patient.address,
          emergencyContact: patient.emergencyContact
        }
      }));

      logger.info(`Retrieved ${patients.length} patients for doctor ${doctorId}`);

      ResponseUtils.paginated(
        res,
        patientsWithVirtuals,
        parseInt(page),
        parseInt(limit),
        total,
        'Patients retrieved successfully'
      );
    } catch (error) {
      logger.error('Error retrieving patients:', error);
      ResponseUtils.error(res, 'Failed to retrieve patients');
    }
  })
);

/**
 * @route   GET /api/v1/patients/:id
 * @desc    Get patient by ID
 * @access  Private (Doctor, Admin)
 */
router.get('/:id',
  authenticate,
  checkOwnership(Patient, 'id', 'doctorId'),
  asyncErrorHandler(async (req, res) => {
    const patient = req.resource; // Set by checkOwnership middleware

    await patient.populate([
      { path: 'doctorId', select: 'name email specialty' },
      { path: 'createdBy', select: 'name email' },
      { path: 'updatedBy', select: 'name email' }
    ]);

    logger.info(`Retrieved patient ${patient._id} by user ${req.user._id}`);

    ResponseUtils.success(res, patient.toSafeObject(), 'Patient retrieved successfully');
  })
);

/**
 * @route   POST /api/v1/patients
 * @desc    Create new patient
 * @access  Private (Doctor, Admin)
 */
router.post('/',
  authenticate,
  authorize('doctor', 'admin'),
  validate(patientValidation.create),
  asyncErrorHandler(async (req, res) => {
    const patientData = {
      ...req.body,
      doctorId: req.user._id,
      createdBy: req.user._id
    };

    // Check for duplicate patient (same name, age, and doctor)
    const existingPatient = await Patient.findOne({
      name: patientData.name,
      age: patientData.age,
      doctorId: patientData.doctorId,
      isActive: true
    });

    if (existingPatient) {
      return ResponseUtils.error(
        res, 
        'A patient with the same name and age already exists', 
        409
      );
    }

    const patient = new Patient(patientData);
    await patient.save();

    await patient.populate([
      { path: 'doctorId', select: 'name email specialty' },
      { path: 'createdBy', select: 'name email' }
    ]);

    logger.info(`Created new patient ${patient._id} by user ${req.user._id}`);

    ResponseUtils.created(res, patient.toSafeObject(), 'Patient created successfully');
  })
);

/**
 * @route   PUT /api/v1/patients/:id
 * @desc    Update patient
 * @access  Private (Doctor, Admin)
 */
router.put('/:id',
  authenticate,
  checkOwnership(Patient, 'id', 'doctorId'),
  validate(patientValidation.update),
  asyncErrorHandler(async (req, res) => {
    const patient = req.resource; // Set by checkOwnership middleware
    
    // Fields that can be updated
    const allowedUpdates = [
      'name', 'age', 'sex', 'dateOfBirth', 'address', 'phone', 'email',
      'emergencyContact', 'bloodType', 'allergies', 'medications',
      'medicalHistory', 'priority', 'tags', 'consentForTreatment',
      'consentForRecording', 'consentForDataSharing', 'privacySettings',
      'notes'
    ];

    const updates = {};
    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    updates.updatedBy = req.user._id;

    // Check for duplicate if name or age is being updated
    if (updates.name || updates.age) {
      const duplicateQuery = {
        name: updates.name || patient.name,
        age: updates.age || patient.age,
        doctorId: patient.doctorId,
        isActive: true,
        _id: { $ne: patient._id }
      };

      const duplicate = await Patient.findOne(duplicateQuery);
      if (duplicate) {
        return ResponseUtils.error(
          res,
          'A patient with the same name and age already exists',
          409
        );
      }
    }

    // Update patient
    Object.assign(patient, updates);
    await patient.save();

    await patient.populate([
      { path: 'doctorId', select: 'name email specialty' },
      { path: 'updatedBy', select: 'name email' }
    ]);

    logger.info(`Updated patient ${patient._id} by user ${req.user._id}`, {
      updatedFields: Object.keys(updates)
    });

    ResponseUtils.updated(res, patient.toSafeObject(), 'Patient updated successfully');
  })
);

/**
 * @route   DELETE /api/v1/patients/:id
 * @desc    Delete patient (soft delete)
 * @access  Private (Doctor, Admin)
 */
router.delete('/:id',
  authenticate,
  checkOwnership(Patient, 'id', 'doctorId'),
  asyncErrorHandler(async (req, res) => {
    const patient = req.resource; // Set by checkOwnership middleware

    // Soft delete - set isActive to false
    patient.isActive = false;
    patient.updatedBy = req.user._id;
    await patient.save();

    logger.info(`Soft deleted patient ${patient._id} by user ${req.user._id}`);

    ResponseUtils.deleted(res, 'Patient deleted successfully');
  })
);

/**
 * @route   POST /api/v1/patients/:id/restore
 * @desc    Restore soft-deleted patient
 * @access  Private (Doctor, Admin)
 */
router.post('/:id/restore',
  authenticate,
  authorize('doctor', 'admin'),
  asyncErrorHandler(async (req, res) => {
    const patient = await Patient.findOne({
      _id: req.params.id,
      isActive: false
    });

    if (!patient) {
      return ResponseUtils.notFound(res, 'Deleted patient not found');
    }

    // Check ownership
    if (req.user.role !== 'admin' && patient.doctorId.toString() !== req.user._id.toString()) {
      return ResponseUtils.forbidden(res, 'Access denied to this patient');
    }

    patient.isActive = true;
    patient.updatedBy = req.user._id;
    await patient.save();

    logger.info(`Restored patient ${patient._id} by user ${req.user._id}`);

    ResponseUtils.success(res, patient.toSafeObject(), 'Patient restored successfully');
  })
);

/**
 * @route   POST /api/v1/patients/:id/medications
 * @desc    Add medication to patient
 * @access  Private (Doctor, Admin)
 */
router.post('/:id/medications',
  authenticate,
  checkOwnership(Patient, 'id', 'doctorId'),
  asyncErrorHandler(async (req, res) => {
    const patient = req.resource;
    const { name, dosage, frequency, prescribedBy, startDate, endDate, notes } = req.body;

    if (!name) {
      return ResponseUtils.error(res, 'Medication name is required', 400);
    }

    const medication = {
      name,
      dosage,
      frequency,
      prescribedBy: prescribedBy || req.user.name,
      startDate: startDate || new Date(),
      endDate,
      notes
    };

    try {
      await patient.addMedication(medication);
      
      logger.info(`Added medication ${name} to patient ${patient._id} by user ${req.user._id}`);
      
      ResponseUtils.success(res, patient.medications, 'Medication added successfully');
    } catch (error) {
      ResponseUtils.error(res, error.message, 400);
    }
  })
);

/**
 * @route   POST /api/v1/patients/:id/allergies
 * @desc    Add allergy to patient
 * @access  Private (Doctor, Admin)
 */
router.post('/:id/allergies',
  authenticate,
  checkOwnership(Patient, 'id', 'doctorId'),
  asyncErrorHandler(async (req, res) => {
    const patient = req.resource;
    const { allergen, severity, reaction, notes } = req.body;

    if (!allergen) {
      return ResponseUtils.error(res, 'Allergen is required', 400);
    }

    const allergy = {
      allergen,
      severity: severity || 'unknown',
      reaction,
      notes
    };

    try {
      await patient.addAllergy(allergy);
      
      logger.info(`Added allergy ${allergen} to patient ${patient._id} by user ${req.user._id}`);
      
      ResponseUtils.success(res, patient.allergies, 'Allergy added successfully');
    } catch (error) {
      ResponseUtils.error(res, error.message, 400);
    }
  })
);

/**
 * @route   GET /api/v1/patients/:id/sessions
 * @desc    Get all sessions for a patient
 * @access  Private (Doctor, Admin)
 */
router.get('/:id/sessions',
  authenticate,
  checkOwnership(Patient, 'id', 'doctorId'),
  asyncErrorHandler(async (req, res) => {
    const Session = require('../models/Session');
    const patient = req.resource;
    
    const {
      page = 1,
      limit = 10,
      sort = '-createdAt',
      status,
      dateFrom,
      dateTo
    } = req.query;

    const query = { patientId: patient._id };
    
    if (status) query.status = status;
    
    if (dateFrom || dateTo) {
      query.createdAt = {};
      if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
      if (dateTo) query.createdAt.$lte = new Date(dateTo);
    }

    const total = await Session.countDocuments(query);
    const skip = (page - 1) * limit;

    const sessions = await Session.find(query)
      .populate('doctorId', 'name email specialty')
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit))
      .select('-chunks.presignedUploadUrl -encryptionKey')
      .lean();

    ResponseUtils.paginated(
      res,
      sessions,
      parseInt(page),
      parseInt(limit),
      total,
      'Patient sessions retrieved successfully'
    );
  })
);

/**
 * @route   GET /api/v1/patients/statistics
 * @desc    Get patient statistics for doctor
 * @access  Private (Doctor, Admin)
 */
router.get('/stats/overview',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const doctorId = req.user.role === 'admin' 
      ? req.query.doctorId 
      : req.user._id;

    if (!doctorId) {
      return ResponseUtils.error(res, 'Doctor ID is required for admin users', 400);
    }

    try {
      const stats = await Patient.getStatistics(doctorId);
      
      const overview = stats[0] || {
        total: 0,
        maleCount: 0,
        femaleCount: 0,
        averageAge: 0,
        priorityHigh: 0,
        priorityUrgent: 0
      };

      ResponseUtils.success(res, overview, 'Patient statistics retrieved successfully');
    } catch (error) {
      logger.error('Error retrieving patient statistics:', error);
      ResponseUtils.error(res, 'Failed to retrieve statistics');
    }
  })
);

/**
 * @route   GET /api/v1/patients/search
 * @desc    Search patients by various criteria
 * @access  Private (Doctor, Admin)
 */
router.get('/search/advanced',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const {
      q, // General search query
      name,
      age,
      sex,
      priority,
      bloodType,
      hasAllergies,
      hasMedications,
      tags,
      page = 1,
      limit = 10,
      sort = '-createdAt'
    } = req.query;

    const doctorId = req.user.role === 'admin' ? req.query.doctorId : req.user._id;
    
    if (!doctorId) {
      return ResponseUtils.error(res, 'Doctor ID is required for admin users', 400);
    }

    const query = { doctorId, isActive: true };

    // General text search
    if (q) {
      query.$text = { $search: q };
    }

    // Specific field searches
    if (name) query.name = { $regex: name, $options: 'i' };
    if (age) query.age = parseInt(age);
    if (sex) query.sex = sex;
    if (priority) query.priority = priority;
    if (bloodType) query.bloodType = bloodType;
    if (tags) query.tags = { $in: Array.isArray(tags) ? tags : [tags] };

    // Complex queries
    if (hasAllergies === 'true') {
      query['allergies.0'] = { $exists: true };
    } else if (hasAllergies === 'false') {
      query.allergies = { $size: 0 };
    }

    if (hasMedications === 'true') {
      query['medications.0'] = { $exists: true };
    } else if (hasMedications === 'false') {
      query.medications = { $size: 0 };
    }

    const total = await Patient.countDocuments(query);
    const skip = (page - 1) * limit;

    const patients = await Patient.find(query)
      .populate('doctorId', 'name email specialty')
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    ResponseUtils.paginated(
      res,
      patients,
      parseInt(page),
      parseInt(limit),
      total,
      'Search results retrieved successfully'
    );
  })
);

module.exports = router;