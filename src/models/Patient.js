const mongoose = require('mongoose');

const patientSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: [true, 'Patient name is required'],
    trim: true,
    minlength: [2, 'Name must be at least 2 characters long'],
    maxlength: [100, 'Name must be less than 100 characters long'],
    match: [/^[a-zA-Z\s'-]+$/, 'Name can only contain letters, spaces, hyphens, and apostrophes']
  },
  
  age: {
    type: Number,
    required: [true, 'Patient age is required'],
    min: [0, 'Age cannot be negative'],
    max: [150, 'Age cannot exceed 150 years']
  },
  
  sex: {
    type: String,
    required: [true, 'Patient sex is required'],
    enum: {
      values: ['male', 'female', 'other'],
      message: 'Sex must be male, female, or other'
    }
  },
  
  dateOfBirth: {
    type: Date,
    validate: {
      validator: function(value) {
        return value <= new Date();
      },
      message: 'Date of birth cannot be in the future'
    }
  },
  
  // Contact Information
  address: {
    type: String,
    required: [true, 'Patient address is required'],
    trim: true,
    minlength: [10, 'Address must be at least 10 characters long'],
    maxlength: [500, 'Address must be less than 500 characters long']
  },
  
  phone: {
    type: String,
    trim: true,
    match: [/^\+?[\d\s\-\(\)]{10,15}$/, 'Please provide a valid phone number']
  },
  
  email: {
    type: String,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
  },
  
  // Emergency Contact
  emergencyContact: {
    name: {
      type: String,
      trim: true,
      maxlength: [100, 'Emergency contact name must be less than 100 characters']
    },
    phone: {
      type: String,
      trim: true,
      match: [/^\+?[\d\s\-\(\)]{10,15}$/, 'Please provide a valid emergency contact phone number']
    },
    relationship: {
      type: String,
      trim: true,
      maxlength: [50, 'Relationship must be less than 50 characters']
    },
    address: {
      type: String,
      trim: true,
      maxlength: [500, 'Emergency contact address must be less than 500 characters']
    }
  },
  
  // Medical Information
  bloodType: {
    type: String,
    enum: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'Unknown'],
    default: 'Unknown'
  },
  
  allergies: [{
    allergen: {
      type: String,
      required: true,
      trim: true,
      maxlength: [100, 'Allergen name must be less than 100 characters']
    },
    severity: {
      type: String,
      enum: ['mild', 'moderate', 'severe', 'unknown'],
      default: 'unknown'
    },
    reaction: {
      type: String,
      trim: true,
      maxlength: [200, 'Reaction description must be less than 200 characters']
    },
    notes: {
      type: String,
      trim: true,
      maxlength: [500, 'Allergy notes must be less than 500 characters']
    }
  }],
  
  medications: [{
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: [100, 'Medication name must be less than 100 characters']
    },
    dosage: {
      type: String,
      trim: true,
      maxlength: [50, 'Dosage must be less than 50 characters']
    },
    frequency: {
      type: String,
      trim: true,
      maxlength: [50, 'Frequency must be less than 50 characters']
    },
    prescribedBy: {
      type: String,
      trim: true,
      maxlength: [100, 'Prescribing doctor name must be less than 100 characters']
    },
    startDate: {
      type: Date,
      default: Date.now
    },
    endDate: {
      type: Date,
      validate: {
        validator: function(value) {
          return !value || value > this.startDate;
        },
        message: 'End date must be after start date'
      }
    },
    notes: {
      type: String,
      trim: true,
      maxlength: [500, 'Medication notes must be less than 500 characters']
    }
  }],
  
  medicalHistory: {
    conditions: [{
      condition: {
        type: String,
        required: true,
        trim: true,
        maxlength: [100, 'Condition name must be less than 100 characters']
      },
      diagnosedDate: {
        type: Date,
        validate: {
          validator: function(value) {
            return value <= new Date();
          },
          message: 'Diagnosis date cannot be in the future'
        }
      },
      status: {
        type: String,
        enum: ['active', 'resolved', 'chronic', 'unknown'],
        default: 'unknown'
      },
      notes: {
        type: String,
        trim: true,
        maxlength: [1000, 'Condition notes must be less than 1000 characters']
      }
    }],
    
    surgeries: [{
      procedure: {
        type: String,
        required: true,
        trim: true,
        maxlength: [200, 'Procedure name must be less than 200 characters']
      },
      date: {
        type: Date,
        validate: {
          validator: function(value) {
            return value <= new Date();
          },
          message: 'Surgery date cannot be in the future'
        }
      },
      hospital: {
        type: String,
        trim: true,
        maxlength: [100, 'Hospital name must be less than 100 characters']
      },
      surgeon: {
        type: String,
        trim: true,
        maxlength: [100, 'Surgeon name must be less than 100 characters']
      },
      notes: {
        type: String,
        trim: true,
        maxlength: [1000, 'Surgery notes must be less than 1000 characters']
      }
    }],
    
    familyHistory: {
      type: String,
      trim: true,
      maxlength: [2000, 'Family history must be less than 2000 characters']
    },
    
    socialHistory: {
      smoking: {
        status: { type: String, enum: ['never', 'former', 'current', 'unknown'], default: 'unknown' },
        details: { type: String, maxlength: [200, 'Smoking details must be less than 200 characters'] }
      },
      alcohol: {
        status: { type: String, enum: ['never', 'occasional', 'regular', 'heavy', 'unknown'], default: 'unknown' },
        details: { type: String, maxlength: [200, 'Alcohol details must be less than 200 characters'] }
      },
      drugs: {
        status: { type: String, enum: ['never', 'former', 'current', 'unknown'], default: 'unknown' },
        details: { type: String, maxlength: [200, 'Drug use details must be less than 200 characters'] }
      },
      occupation: { type: String, maxlength: [100, 'Occupation must be less than 100 characters'] },
      exercise: { type: String, maxlength: [200, 'Exercise details must be less than 200 characters'] }
    }
  },
  
  // Files and Media
  photoPath: {
    type: String, // URL or file path to patient photo
    default: null
  },
  
  documents: [{
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: [100, 'Document name must be less than 100 characters']
    },
    type: {
      type: String,
      enum: ['insurance', 'id', 'medical_record', 'lab_result', 'image', 'other'],
      required: true
    },
    url: {
      type: String,
      required: true
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    },
    size: {
      type: Number, // File size in bytes
      min: [0, 'File size cannot be negative']
    },
    mimeType: {
      type: String,
      trim: true
    }
  }],
  
  // Relationship to Doctor
  doctorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Doctor ID is required'],
    index: true
  },
  
  // Status and Flags
  isActive: {
    type: Boolean,
    default: true
  },
  
  priority: {
    type: String,
    enum: ['low', 'normal', 'high', 'urgent'],
    default: 'normal'
  },
  
  tags: [{
    type: String,
    trim: true,
    maxlength: [30, 'Tag must be less than 30 characters']
  }],
  
  // Privacy and Consent
  consentForTreatment: {
    type: Boolean,
    default: false
  },
  
  consentForRecording: {
    type: Boolean,
    default: false
  },
  
  consentForDataSharing: {
    type: Boolean,
    default: false
  },
  
  privacySettings: {
    shareWithColleagues: { type: Boolean, default: false },
    shareForResearch: { type: Boolean, default: false },
    shareForEducation: { type: Boolean, default: false }
  },
  
  // Audit Fields
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  lastVisit: {
    type: Date,
    default: null
  },
  
  notes: {
    type: String,
    trim: true,
    maxlength: [2000, 'Notes must be less than 2000 characters']
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
patientSchema.index({ doctorId: 1, createdAt: -1 });
patientSchema.index({ doctorId: 1, isActive: 1 });
patientSchema.index({ name: 'text', 'emergencyContact.name': 'text' }); // Text search
patientSchema.index({ age: 1 });
patientSchema.index({ sex: 1 });
patientSchema.index({ priority: 1 });
patientSchema.index({ tags: 1 });

// Virtual for patient's current age (if dateOfBirth is provided)
patientSchema.virtual('currentAge').get(function() {
  if (this.dateOfBirth) {
    const today = new Date();
    const birthDate = new Date(this.dateOfBirth);
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }
    
    return age;
  }
  return this.age;
});

// Virtual for full contact information
patientSchema.virtual('contactInfo').get(function() {
  return {
    phone: this.phone,
    email: this.email,
    address: this.address,
    emergencyContact: this.emergencyContact
  };
});

// Virtual for active medications
patientSchema.virtual('activeMedications').get(function() {
  const now = new Date();
  return this.medications.filter(med => !med.endDate || med.endDate > now);
});

// Virtual for active conditions
patientSchema.virtual('activeConditions').get(function() {
  return this.medicalHistory.conditions.filter(condition => 
    condition.status === 'active' || condition.status === 'chronic'
  );
});

// Pre-save middleware to update age based on date of birth
patientSchema.pre('save', function(next) {
  if (this.dateOfBirth && (!this.age || this.isModified('dateOfBirth'))) {
    const today = new Date();
    const birthDate = new Date(this.dateOfBirth);
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }
    
    this.age = age;
  }
  next();
});

// Pre-save middleware to validate emergency contact
patientSchema.pre('save', function(next) {
  if (this.emergencyContact && this.emergencyContact.name) {
    if (!this.emergencyContact.phone) {
      return next(new Error('Emergency contact phone number is required when emergency contact is provided'));
    }
  }
  next();
});

// Instance method to get safe patient data (excluding sensitive information)
patientSchema.methods.toSafeObject = function() {
  const patientObject = this.toObject();
  
  // Remove sensitive medical details for certain users
  // (This can be expanded based on role-based access control)
  delete patientObject.__v;
  
  return patientObject;
};

// Instance method to check if patient has specific allergy
patientSchema.methods.hasAllergy = function(allergen) {
  return this.allergies.some(allergy => 
    allergy.allergen.toLowerCase().includes(allergen.toLowerCase())
  );
};

// Instance method to get current medications
patientSchema.methods.getCurrentMedications = function() {
  const now = new Date();
  return this.medications.filter(med => !med.endDate || med.endDate > now);
};

// Instance method to add medication
patientSchema.methods.addMedication = function(medicationData) {
  this.medications.push(medicationData);
  return this.save();
};

// Instance method to add allergy
patientSchema.methods.addAllergy = function(allergyData) {
  // Check if allergy already exists
  const existingAllergy = this.allergies.find(allergy => 
    allergy.allergen.toLowerCase() === allergyData.allergen.toLowerCase()
  );
  
  if (existingAllergy) {
    throw new Error('This allergy already exists for the patient');
  }
  
  this.allergies.push(allergyData);
  return this.save();
};

// Static method to find patients by doctor with pagination
patientSchema.statics.findByDoctor = function(doctorId, options = {}) {
  const {
    page = 1,
    limit = 10,
    sort = '-createdAt',
    search = '',
    isActive = true,
    priority = null,
    age_min = null,
    age_max = null,
    sex = null
  } = options;
  
  const query = { doctorId, isActive };
  
  // Add search functionality
  if (search) {
    query.$text = { $search: search };
  }
  
  // Add filters
  if (priority) query.priority = priority;
  if (age_min) query.age = { ...query.age, $gte: age_min };
  if (age_max) query.age = { ...query.age, $lte: age_max };
  if (sex) query.sex = sex;
  
  const skip = (page - 1) * limit;
  
  return this.find(query)
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .populate('doctorId', 'name email specialty')
    .exec();
};

// Static method to get patient statistics
patientSchema.statics.getStatistics = function(doctorId) {
  return this.aggregate([
    { $match: { doctorId: mongoose.Types.ObjectId(doctorId), isActive: true } },
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        maleCount: { $sum: { $cond: [{ $eq: ['$sex', 'male'] }, 1, 0] } },
        femaleCount: { $sum: { $cond: [{ $eq: ['$sex', 'female'] }, 1, 0] } },
        averageAge: { $avg: '$age' },
        priorityHigh: { $sum: { $cond: [{ $eq: ['$priority', 'high'] }, 1, 0] } },
        priorityUrgent: { $sum: { $cond: [{ $eq: ['$priority', 'urgent'] }, 1, 0] } }
      }
    }
  ]);
};

module.exports = mongoose.model('Patient', patientSchema);