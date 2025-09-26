const mongoose = require('mongoose');

const audioChunkSchema = new mongoose.Schema({
  chunkId: {
    type: String,
    required: [true, 'Chunk ID is required'],
    unique: true,
    index: true
  },
  
  chunkIndex: {
    type: Number,
    required: [true, 'Chunk index is required'],
    min: [0, 'Chunk index cannot be negative']
  },
  
  duration: {
    type: Number,
    required: [true, 'Chunk duration is required'],
    min: [0, 'Duration cannot be negative'],
    max: [3600, 'Chunk duration cannot exceed 1 hour'] // 1 hour max per chunk
  },
  
  fileSize: {
    type: Number,
    required: [true, 'File size is required'],
    min: [1, 'File size must be positive'],
    max: [104857600, 'File size cannot exceed 100MB'] // 100MB max
  },
  
  mimeType: {
    type: String,
    required: [true, 'MIME type is required'],
    enum: {
      values: ['audio/wav', 'audio/mp3', 'audio/mpeg', 'audio/ogg', 'audio/webm'],
      message: 'Invalid audio file type'
    }
  },
  
  // S3 Storage Information
  s3Key: {
    type: String,
    required: [true, 'S3 key is required'],
    index: true
  },
  
  s3Url: {
    type: String,
    required: function() {
      return this.uploadStatus === 'completed';
    }
  },
  
  presignedUploadUrl: {
    type: String,
    default: null
  },
  
  presignedUrlExpires: {
    type: Date,
    default: null
  },
  
  // Upload Status
  uploadStatus: {
    type: String,
    enum: ['pending', 'uploading', 'completed', 'failed'],
    default: 'pending'
  },
  
  uploadStartedAt: {
    type: Date,
    default: null
  },
  
  uploadCompletedAt: {
    type: Date,
    default: null
  },
  
  uploadError: {
    type: String,
    default: null
  },
  
  // Metadata
  metadata: {
    originalFilename: String,
    uploadedFrom: {
      type: String,
      enum: ['mobile', 'web', 'api'],
      default: 'mobile'
    },
    deviceInfo: {
      platform: String,
      version: String,
      model: String
    }
  }
}, {
  timestamps: true
});

const sessionSchema = new mongoose.Schema({
  // Basic Information
  patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Patient',
    required: [true, 'Patient ID is required'],
    index: true
  },
  
  doctorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Doctor ID is required'],
    index: true
  },
  
  // Session Status
  status: {
    type: String,
    enum: {
      values: ['idle', 'recording', 'paused', 'completed', 'uploading', 'uploaded', 'failed', 'archived'],
      message: 'Invalid session status'
    },
    default: 'idle',
    index: true
  },
  
  // Timing Information
  startTime: {
    type: Date,
    default: Date.now,
    index: true
  },
  
  endTime: {
    type: Date,
    default: null,
    validate: {
      validator: function(value) {
        return !value || value > this.startTime;
      },
      message: 'End time must be after start time'
    }
  },
  
  duration: {
    type: Number, // Duration in seconds
    default: 0,
    min: [0, 'Duration cannot be negative']
  },
  
  pausedDuration: {
    type: Number, // Total paused time in seconds
    default: 0,
    min: [0, 'Paused duration cannot be negative']
  },
  
  // Audio Chunks
  chunks: [audioChunkSchema],
  
  totalChunks: {
    type: Number,
    default: 0,
    min: [0, 'Total chunks cannot be negative']
  },
  
  uploadedChunks: {
    type: Number,
    default: 0,
    min: [0, 'Uploaded chunks cannot be negative']
  },
  
  // File Information
  totalFileSize: {
    type: Number,
    default: 0,
    min: [0, 'File size cannot be negative']
  },
  
  // Transcription
  transcript: {
    type: String,
    maxlength: [50000, 'Transcript must be less than 50,000 characters'],
    default: null
  },
  
  transcriptionStatus: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed', 'not_requested'],
    default: 'not_requested'
  },
  
  transcriptionProvider: {
    type: String,
    enum: ['aws', 'google', 'azure', 'openai', 'custom'],
    default: null
  },
  
  transcriptionJobId: {
    type: String,
    default: null
  },
  
  transcriptionError: {
    type: String,
    default: null
  },
  
  transcriptionStartedAt: {
    type: Date,
    default: null
  },
  
  transcriptionCompletedAt: {
    type: Date,
    default: null
  },
  
  // Session Notes and Metadata
  sessionNotes: {
    type: String,
    maxlength: [5000, 'Session notes must be less than 5,000 characters'],
    trim: true
  },
  
  clinicalNotes: {
    type: String,
    maxlength: [10000, 'Clinical notes must be less than 10,000 characters'],
    trim: true
  },
  
  tags: [{
    type: String,
    trim: true,
    maxlength: [30, 'Tag must be less than 30 characters']
  }],
  
  sessionType: {
    type: String,
    enum: ['consultation', 'follow_up', 'emergency', 'routine_check', 'procedure', 'other'],
    default: 'consultation'
  },
  
  priority: {
    type: String,
    enum: ['low', 'normal', 'high', 'urgent'],
    default: 'normal'
  },
  
  // Quality and Technical Information
  audioQuality: {
    type: String,
    enum: ['poor', 'fair', 'good', 'excellent'],
    default: null
  },
  
  technicalIssues: [{
    type: {
      type: String,
      enum: ['connection', 'audio', 'sync', 'upload', 'other'],
      required: true
    },
    description: {
      type: String,
      required: true,
      maxlength: [500, 'Issue description must be less than 500 characters']
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    resolved: {
      type: Boolean,
      default: false
    }
  }],
  
  // Privacy and Consent
  patientConsent: {
    recording: {
      type: Boolean,
      default: false
    },
    transcription: {
      type: Boolean,
      default: false
    },
    storage: {
      type: Boolean,
      default: false
    },
    sharing: {
      type: Boolean,
      default: false
    },
    consentTimestamp: {
      type: Date,
      default: null
    }
  },
  
  // Security and Encryption
  encryptionKey: {
    type: String,
    select: false // Never include in queries by default
  },
  
  isEncrypted: {
    type: Boolean,
    default: false
  },
  
  // Archive and Retention
  retentionPeriod: {
    type: Number, // Days
    default: 2555, // ~7 years default
    min: [1, 'Retention period must be at least 1 day']
  },
  
  scheduledDeletion: {
    type: Date,
    default: function() {
      return new Date(Date.now() + (this.retentionPeriod * 24 * 60 * 60 * 1000));
    }
  },
  
  isArchived: {
    type: Boolean,
    default: false,
    index: true
  },
  
  archivedAt: {
    type: Date,
    default: null
  },
  
  // Sharing and Collaboration
  sharedWith: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    permission: {
      type: String,
      enum: ['view', 'edit', 'full'],
      default: 'view'
    },
    sharedAt: {
      type: Date,
      default: Date.now
    },
    sharedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    }
  }],
  
  // Device and Session Information
  deviceInfo: {
    platform: String, // iOS, Android, Web
    appVersion: String,
    osVersion: String,
    deviceModel: String,
    batteryLevel: Number,
    networkType: String,
    locationEnabled: Boolean
  },
  
  // Analytics and Performance
  performanceMetrics: {
    averageUploadSpeed: Number, // KB/s
    networkInterruptions: Number,
    chunkFailures: Number,
    retryAttempts: Number,
    totalPauseCount: Number
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
  
  lastAccessedAt: {
    type: Date,
    default: Date.now
  },
  
  accessHistory: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    action: {
      type: String,
      enum: ['view', 'edit', 'download', 'share', 'delete'],
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    details: String
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
sessionSchema.index({ patientId: 1, createdAt: -1 });
sessionSchema.index({ doctorId: 1, status: 1 });
sessionSchema.index({ status: 1, createdAt: -1 });
sessionSchema.index({ transcriptionStatus: 1 });
sessionSchema.index({ scheduledDeletion: 1 });
sessionSchema.index({ isArchived: 1, archivedAt: -1 });
sessionSchema.index({ 'chunks.uploadStatus': 1 });
sessionSchema.index({ sessionType: 1, priority: 1 });

// Compound indexes
sessionSchema.index({ doctorId: 1, patientId: 1, createdAt: -1 });
sessionSchema.index({ status: 1, priority: 1, createdAt: -1 });

// Virtual for upload progress percentage
sessionSchema.virtual('uploadProgress').get(function() {
  if (this.totalChunks === 0) return 0;
  return Math.round((this.uploadedChunks / this.totalChunks) * 100);
});

// Virtual for session duration in human readable format
sessionSchema.virtual('formattedDuration').get(function() {
  const duration = this.duration;
  const hours = Math.floor(duration / 3600);
  const minutes = Math.floor((duration % 3600) / 60);
  const seconds = duration % 60;
  
  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  } else {
    return `${seconds}s`;
  }
});

// Virtual for completed chunks
sessionSchema.virtual('completedChunks').get(function() {
  return this.chunks.filter(chunk => chunk.uploadStatus === 'completed');
});

// Virtual for failed chunks
sessionSchema.virtual('failedChunks').get(function() {
  return this.chunks.filter(chunk => chunk.uploadStatus === 'failed');
});

// Virtual for pending chunks
sessionSchema.virtual('pendingChunks').get(function() {
  return this.chunks.filter(chunk => 
    chunk.uploadStatus === 'pending' || chunk.uploadStatus === 'uploading'
  );
});

// Pre-save middleware to update computed fields
sessionSchema.pre('save', function(next) {
  // Update total chunks and uploaded chunks
  this.totalChunks = this.chunks.length;
  this.uploadedChunks = this.chunks.filter(chunk => 
    chunk.uploadStatus === 'completed'
  ).length;
  
  // Update total file size
  this.totalFileSize = this.chunks.reduce((total, chunk) => 
    total + (chunk.fileSize || 0), 0
  );
  
  // Update session status based on chunk status
  if (this.totalChunks > 0) {
    const completedChunks = this.uploadedChunks;
    const failedChunks = this.chunks.filter(chunk => 
      chunk.uploadStatus === 'failed'
    ).length;
    
    if (completedChunks === this.totalChunks) {
      this.status = 'uploaded';
    } else if (failedChunks > 0) {
      this.status = 'failed';
    } else if (completedChunks > 0) {
      this.status = 'uploading';
    }
  }
  
  next();
});

// Pre-save middleware to handle scheduled deletion
sessionSchema.pre('save', function(next) {
  if (this.isModified('retentionPeriod') || this.isNew) {
    this.scheduledDeletion = new Date(Date.now() + (this.retentionPeriod * 24 * 60 * 60 * 1000));
  }
  next();
});

// Instance method to add chunk
sessionSchema.methods.addChunk = function(chunkData) {
  // Validate chunk data
  if (!chunkData.chunkId || !chunkData.s3Key) {
    throw new Error('Chunk ID and S3 key are required');
  }
  
  // Check for duplicate chunk
  const existingChunk = this.chunks.find(chunk => chunk.chunkId === chunkData.chunkId);
  if (existingChunk) {
    throw new Error('Chunk with this ID already exists');
  }
  
  this.chunks.push(chunkData);
  return this.save();
};

// Instance method to update chunk status
sessionSchema.methods.updateChunkStatus = function(chunkId, status, additionalData = {}) {
  const chunk = this.chunks.find(chunk => chunk.chunkId === chunkId);
  if (!chunk) {
    throw new Error('Chunk not found');
  }
  
  chunk.uploadStatus = status;
  
  if (status === 'uploading') {
    chunk.uploadStartedAt = new Date();
  } else if (status === 'completed') {
    chunk.uploadCompletedAt = new Date();
    if (additionalData.s3Url) {
      chunk.s3Url = additionalData.s3Url;
    }
  } else if (status === 'failed') {
    chunk.uploadError = additionalData.error || 'Upload failed';
  }
  
  return this.save();
};

// Instance method to get session summary
sessionSchema.methods.getSummary = function() {
  return {
    id: this._id,
    patientId: this.patientId,
    status: this.status,
    duration: this.duration,
    formattedDuration: this.formattedDuration,
    uploadProgress: this.uploadProgress,
    totalChunks: this.totalChunks,
    uploadedChunks: this.uploadedChunks,
    transcriptionStatus: this.transcriptionStatus,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt
  };
};

// Instance method to check if session can be deleted
sessionSchema.methods.canBeDeleted = function() {
  return this.scheduledDeletion <= new Date() || this.status === 'failed';
};

// Instance method to archive session
sessionSchema.methods.archive = function() {
  this.isArchived = true;
  this.archivedAt = new Date();
  return this.save();
};

// Instance method to add access log
sessionSchema.methods.logAccess = function(userId, action, details = '') {
  this.accessHistory.push({
    userId,
    action,
    details,
    timestamp: new Date()
  });
  
  this.lastAccessedAt = new Date();
  
  // Keep only last 100 access logs
  if (this.accessHistory.length > 100) {
    this.accessHistory = this.accessHistory.slice(-100);
  }
  
  return this.save();
};

// Static method to find sessions with filters
sessionSchema.statics.findWithFilters = function(filters = {}) {
  const {
    doctorId,
    patientId,
    status,
    transcriptionStatus,
    sessionType,
    priority,
    dateFrom,
    dateTo,
    isArchived = false,
    page = 1,
    limit = 10,
    sort = '-createdAt'
  } = filters;
  
  const query = { isArchived };
  
  if (doctorId) query.doctorId = doctorId;
  if (patientId) query.patientId = patientId;
  if (status) query.status = status;
  if (transcriptionStatus) query.transcriptionStatus = transcriptionStatus;
  if (sessionType) query.sessionType = sessionType;
  if (priority) query.priority = priority;
  
  if (dateFrom || dateTo) {
    query.createdAt = {};
    if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
    if (dateTo) query.createdAt.$lte = new Date(dateTo);
  }
  
  const skip = (page - 1) * limit;
  
  return this.find(query)
    .populate('patientId', 'name age sex')
    .populate('doctorId', 'name email specialty')
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .exec();
};

// Static method to get session statistics
sessionSchema.statics.getStatistics = function(doctorId, dateRange = {}) {
  const matchQuery = { doctorId: mongoose.Types.ObjectId(doctorId) };
  
  if (dateRange.start || dateRange.end) {
    matchQuery.createdAt = {};
    if (dateRange.start) matchQuery.createdAt.$gte = new Date(dateRange.start);
    if (dateRange.end) matchQuery.createdAt.$lte = new Date(dateRange.end);
  }
  
  return this.aggregate([
    { $match: matchQuery },
    {
      $group: {
        _id: null,
        totalSessions: { $sum: 1 },
        completedSessions: { $sum: { $cond: [{ $eq: ['$status', 'uploaded'] }, 1, 0] } },
        failedSessions: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } },
        totalDuration: { $sum: '$duration' },
        avgDuration: { $avg: '$duration' },
        totalFileSize: { $sum: '$totalFileSize' },
        transcribedSessions: { $sum: { $cond: [{ $eq: ['$transcriptionStatus', 'completed'] }, 1, 0] } }
      }
    }
  ]);
};

// Static method to cleanup old sessions
sessionSchema.statics.cleanupExpiredSessions = function() {
  const now = new Date();
  return this.find({
    scheduledDeletion: { $lte: now },
    isArchived: false
  }).exec();
};

module.exports = mongoose.model('Session', sessionSchema);