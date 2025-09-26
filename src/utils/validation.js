const Joi = require('joi');

// Custom validation messages
const customMessages = {
  'string.empty': '{#label} cannot be empty',
  'string.min': '{#label} must be at least {#limit} characters long',
  'string.max': '{#label} must be less than {#limit} characters long',
  'string.email': '{#label} must be a valid email',
  'number.base': '{#label} must be a number',
  'number.min': '{#label} must be at least {#limit}',
  'number.max': '{#label} must be less than or equal to {#limit}',
  'date.base': '{#label} must be a valid date',
  'any.required': '{#label} is required',
  'array.base': '{#label} must be an array',
  'object.unknown': '{#label} is not allowed',
};

// Common validation schemas
const commonSchemas = {
  // MongoDB ObjectId validation
  objectId: Joi.string().regex(/^[0-9a-fA-F]{24}$/).messages({
    'string.pattern.base': 'Invalid ID format'
  }),

  // UUID validation
  uuid: Joi.string().uuid().messages({
    'string.guid': 'Invalid UUID format'
  }),

  // Email validation
  email: Joi.string().email().lowercase().trim().messages(customMessages),

  // Password validation
  password: Joi.string().min(8).max(128).pattern(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/
  ).messages({
    ...customMessages,
    'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
  }),

  // Phone number validation
  phone: Joi.string().pattern(/^\+?[\d\s\-\(\)]{10,15}$/).messages({
    'string.pattern.base': 'Invalid phone number format'
  }),

  // Name validation
  name: Joi.string().min(2).max(50).pattern(/^[a-zA-Z\s'-]+$/).trim().messages({
    ...customMessages,
    'string.pattern.base': 'Name can only contain letters, spaces, hyphens, and apostrophes'
  }),

  // Age validation
  age: Joi.number().integer().min(0).max(150).messages(customMessages),

  // Gender validation
  gender: Joi.string().valid('male', 'female', 'other').messages({
    ...customMessages,
    'any.only': 'Gender must be male, female, or other'
  }),

  // Date validation
  date: Joi.date().iso().messages(customMessages),

  // URL validation
  url: Joi.string().uri().messages({
    'string.uri': 'Invalid URL format'
  }),

  // Pagination validation
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(10),
  sort: Joi.string().pattern(/^[a-zA-Z_]+(:(asc|desc))?$/),

  // File validation
  mimeType: Joi.string().valid(
    'image/jpeg', 'image/png', 'image/webp',
    'audio/wav', 'audio/mp3', 'audio/mpeg', 'audio/ogg', 'audio/webm'
  ),
};

// Validation schemas for different entities

// User/Doctor validation
const userValidation = {
  register: Joi.object({
    name: commonSchemas.name.required(),
    email: commonSchemas.email.required(),
    password: commonSchemas.password.required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required().messages({
      'any.only': 'Passwords do not match'
    }),
    phone: commonSchemas.phone.optional(),
    specialty: Joi.string().min(2).max(100).optional(),
    licenseNumber: Joi.string().min(5).max(50).optional(),
    hospitalAffiliation: Joi.string().min(2).max(100).optional(),
  }).messages(customMessages),

  login: Joi.object({
    email: commonSchemas.email.required(),
    password: Joi.string().required().messages(customMessages),
    rememberMe: Joi.boolean().default(false),
  }).messages(customMessages),

  updateProfile: Joi.object({
    name: commonSchemas.name.optional(),
    phone: commonSchemas.phone.optional(),
    specialty: Joi.string().min(2).max(100).optional(),
    licenseNumber: Joi.string().min(5).max(50).optional(),
    hospitalAffiliation: Joi.string().min(2).max(100).optional(),
  }).messages(customMessages),

  changePassword: Joi.object({
    currentPassword: Joi.string().required().messages(customMessages),
    newPassword: commonSchemas.password.required(),
    confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required().messages({
      'any.only': 'Passwords do not match'
    }),
  }).messages(customMessages),

  forgotPassword: Joi.object({
    email: commonSchemas.email.required(),
  }).messages(customMessages),

  resetPassword: Joi.object({
    token: Joi.string().required().messages(customMessages),
    password: commonSchemas.password.required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required().messages({
      'any.only': 'Passwords do not match'
    }),
  }).messages(customMessages),
};

// Patient validation
const patientValidation = {
  create: Joi.object({
    name: commonSchemas.name.required(),
    age: commonSchemas.age.required(),
    sex: commonSchemas.gender.required(),
    address: Joi.string().min(10).max(200).required().messages(customMessages),
    phone: commonSchemas.phone.optional(),
    email: commonSchemas.email.optional(),
    emergencyContact: Joi.object({
      name: commonSchemas.name.required(),
      phone: commonSchemas.phone.required(),
      relationship: Joi.string().min(2).max(50).required(),
    }).optional(),
    medicalHistory: Joi.string().max(1000).optional(),
    allergies: Joi.array().items(Joi.string().max(100)).optional(),
    medications: Joi.array().items(Joi.string().max(100)).optional(),
  }).messages(customMessages),

  update: Joi.object({
    name: commonSchemas.name.optional(),
    age: commonSchemas.age.optional(),
    sex: commonSchemas.gender.optional(),
    address: Joi.string().min(10).max(200).optional().messages(customMessages),
    phone: commonSchemas.phone.optional(),
    email: commonSchemas.email.optional(),
    emergencyContact: Joi.object({
      name: commonSchemas.name.optional(),
      phone: commonSchemas.phone.optional(),
      relationship: Joi.string().min(2).max(50).optional(),
    }).optional(),
    medicalHistory: Joi.string().max(1000).optional(),
    allergies: Joi.array().items(Joi.string().max(100)).optional(),
    medications: Joi.array().items(Joi.string().max(100)).optional(),
  }).messages(customMessages),

  list: Joi.object({
    page: commonSchemas.page,
    limit: commonSchemas.limit,
    sort: commonSchemas.sort.optional(),
    search: Joi.string().min(1).max(100).optional(),
    age_min: Joi.number().integer().min(0).optional(),
    age_max: Joi.number().integer().max(150).optional(),
    sex: commonSchemas.gender.optional(),
  }).messages(customMessages),
};

// Recording session validation - REMOVED (replaced with enhanced version below)

// Session validation
const sessionValidation = {
  create: Joi.object({
    patientId: commonSchemas.objectId.required(),
    notes: Joi.string().max(1000).optional(),
    sessionType: Joi.string().valid('consultation', 'followup', 'emergency', 'routine').default('consultation'),
    priority: Joi.string().valid('low', 'normal', 'high', 'urgent').default('normal'),
  }).messages(customMessages),

  update: Joi.object({
    status: Joi.string().valid('idle', 'recording', 'paused', 'completed', 'uploading', 'uploaded', 'failed').optional(),
    notes: Joi.string().max(1000).optional(),
    transcript: Joi.string().max(10000).optional(),
    sessionType: Joi.string().valid('consultation', 'followup', 'emergency', 'routine').optional(),
    priority: Joi.string().valid('low', 'normal', 'high', 'urgent').optional(),
    clinicalNotes: Joi.string().max(2000).optional(),
  }).messages(customMessages),

  uploadChunk: Joi.object({
    chunkId: commonSchemas.uuid.required(),
    chunkIndex: Joi.number().integer().min(0).required(),
    duration: Joi.number().min(0).max(3600).required(),
    fileSize: Joi.number().integer().min(1).max(104857600).required(),
    mimeType: Joi.string().valid('audio/wav', 'audio/mp3', 'audio/mpeg', 'audio/ogg', 'audio/webm', 'audio/m4a').required(),
    deviceInfo: Joi.object().optional(),
  }).messages(customMessages),

  list: Joi.object({
    page: commonSchemas.page,
    limit: commonSchemas.limit,
    sort: commonSchemas.sort.optional(),
    patientId: commonSchemas.objectId.optional(),
    status: Joi.string().valid('idle', 'recording', 'paused', 'completed', 'uploading', 'uploaded', 'failed').optional(),
    transcriptionStatus: Joi.string().valid('pending', 'processing', 'completed', 'failed').optional(),
    sessionType: Joi.string().valid('consultation', 'followup', 'emergency', 'routine').optional(),
    priority: Joi.string().valid('low', 'normal', 'high', 'urgent').optional(),
    date_from: commonSchemas.date.optional(),
    date_to: commonSchemas.date.optional(),
    isArchived: Joi.boolean().default(false),
    doctorId: commonSchemas.objectId.optional(), // For admin use
  }).messages(customMessages),
};

// File upload validation
const uploadValidation = {
  presignedUrl: Joi.object({
    fileName: Joi.string().min(1).max(255).required(),
    fileType: Joi.string().valid('audio', 'document', 'image').required(),
    fileSize: Joi.number().integer().min(1).max(104857600).required(), // 100MB max
    sessionId: commonSchemas.objectId.optional(),
    chunkId: commonSchemas.uuid.optional(),
    contentType: Joi.string().required(),
  }).messages(customMessages),

  directUpload: Joi.object({
    fileType: Joi.string().valid('audio', 'document', 'image').required(),
    sessionId: commonSchemas.objectId.optional(),
    chunkId: commonSchemas.uuid.optional(),
  }).messages(customMessages),

  batchDelete: Joi.object({
    s3Keys: Joi.array().items(Joi.string().min(1)).min(1).max(100).required(),
  }).messages(customMessages),

  audio: Joi.object({
    sessionId: commonSchemas.objectId.required(),
    chunkId: commonSchemas.uuid.required(),
    duration: Joi.number().min(0).max(3600).required(),
    fileSize: Joi.number().integer().min(1).max(104857600).required(),
    mimeType: Joi.string().valid('audio/wav', 'audio/mp3', 'audio/mpeg', 'audio/ogg', 'audio/webm', 'audio/m4a').required(),
  }).messages(customMessages),

  image: Joi.object({
    patientId: commonSchemas.objectId.optional(),
    fileSize: Joi.number().integer().min(1).max(10485760).required(), // Max 10MB for images
    mimeType: Joi.string().valid('image/jpeg', 'image/png', 'image/webp').required(),
  }).messages(customMessages),
};

// Query parameter validation
const queryValidation = {
  pagination: Joi.object({
    page: commonSchemas.page,
    limit: commonSchemas.limit,
  }),

  search: Joi.object({
    q: Joi.string().min(1).max(100).optional(),
    sort: commonSchemas.sort.optional(),
    order: Joi.string().valid('asc', 'desc').default('asc'),
  }),

  dateRange: Joi.object({
    start_date: commonSchemas.date.optional(),
    end_date: commonSchemas.date.optional(),
  }),
};

// Validation middleware factory
const validate = (schema, property = 'body') => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[property], {
      abortEarly: false,
      allowUnknown: false,
      stripUnknown: true,
    });

    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value,
      }));

      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors,
        timestamp: new Date().toISOString(),
      });
    }

    // Replace the original property with validated and sanitized data
    req[property] = value;
    next();
  };
};

// Custom validators
const customValidators = {
  // Validate file upload
  fileUpload: (allowedTypes, maxSize) => {
    return (req, res, next) => {
      if (!req.file && !req.files) {
        return res.status(400).json({
          success: false,
          message: 'No file uploaded',
          timestamp: new Date().toISOString(),
        });
      }

      const file = req.file || req.files[0];
      
      if (!allowedTypes.includes(file.mimetype)) {
        return res.status(400).json({
          success: false,
          message: `Invalid file type. Allowed types: ${allowedTypes.join(', ')}`,
          timestamp: new Date().toISOString(),
        });
      }

      if (file.size > maxSize) {
        return res.status(400).json({
          success: false,
          message: `File size exceeds limit of ${maxSize} bytes`,
          timestamp: new Date().toISOString(),
        });
      }

      next();
    };
  },

  // Validate array of IDs
  validateIds: (fieldName, maxCount = 100) => {
    const schema = Joi.object({
      [fieldName]: Joi.array().items(commonSchemas.objectId).max(maxCount).required(),
    });

    return validate(schema);
  },
};

module.exports = {
  validate,
  userValidation,
  patientValidation,
  sessionValidation,
  uploadValidation,
  queryValidation,
  customValidators,
  commonSchemas,
};