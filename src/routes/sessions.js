const express = require('express');
const { authenticate, authorize, checkSessionOwnership } = require('../middleware/auth');
const { validate, sessionValidation } = require('../utils/validation');
const ResponseUtils = require('../utils/response');
const logger = require('../utils/logger');
const Session = require('../models/Session');
const Patient = require('../models/Patient');
const { asyncErrorHandler } = require('../middleware/errorHandler');

const router = express.Router();

/**
 * @route   GET /api/v1/sessions
 * @desc    Get all sessions for authenticated doctor
 * @access  Private (Doctor, Admin)
 */
router.get('/',
  authenticate,
  validate(sessionValidation.list, 'query'),
  asyncErrorHandler(async (req, res) => {
    const {
      page = 1,
      limit = 10,
      sort = '-createdAt',
      patientId,
      status,
      transcriptionStatus,
      sessionType,
      priority,
      date_from,
      date_to,
      isArchived = false
    } = req.query;

    const doctorId = req.user.role === 'admin' ? req.query.doctorId : req.user._id;
    
    if (!doctorId) {
      return ResponseUtils.error(res, 'Doctor ID is required for admin users', 400);
    }

    const filters = {
      doctorId,
      patientId,
      status,
      transcriptionStatus,
      sessionType,
      priority,
      dateFrom: date_from,
      dateTo: date_to,
      isArchived: isArchived === 'true',
      page: parseInt(page),
      limit: parseInt(limit),
      sort
    };

    try {
      const sessions = await Session.findWithFilters(filters);
      const total = await Session.countDocuments({
        doctorId,
        ...(patientId && { patientId }),
        ...(status && { status }),
        ...(transcriptionStatus && { transcriptionStatus }),
        ...(sessionType && { sessionType }),
        ...(priority && { priority }),
        ...(date_from || date_to) && {
          createdAt: {
            ...(date_from && { $gte: new Date(date_from) }),
            ...(date_to && { $lte: new Date(date_to) })
          }
        },
        isArchived: isArchived === 'true'
      });

      // Remove sensitive data from response
      const safeSessions = sessions.map(session => {
        const sessionObj = session.toObject();
        delete sessionObj.encryptionKey;
        sessionObj.chunks = sessionObj.chunks.map(chunk => {
          delete chunk.presignedUploadUrl;
          return chunk;
        });
        return sessionObj;
      });

      logger.info(`Retrieved ${sessions.length} sessions for doctor ${doctorId}`);

      ResponseUtils.paginated(
        res,
        safeSessions,
        parseInt(page),
        parseInt(limit),
        total,
        'Sessions retrieved successfully'
      );
    } catch (error) {
      logger.error('Error retrieving sessions:', error);
      ResponseUtils.error(res, 'Failed to retrieve sessions');
    }
  })
);

/**
 * @route   GET /api/v1/sessions/:id
 * @desc    Get session by ID
 * @access  Private (Doctor, Admin)
 */
router.get('/:id',
  authenticate,
  checkSessionOwnership,
  asyncErrorHandler(async (req, res) => {
    const session = req.session; // Set by checkSessionOwnership middleware

    // Remove sensitive data
    const safeSession = session.toObject();
    delete safeSession.encryptionKey;
    safeSession.chunks = safeSession.chunks.map(chunk => {
      delete chunk.presignedUploadUrl;
      return chunk;
    });

    // Log access
    await session.logAccess(req.user._id, 'view');

    logger.info(`Retrieved session ${session._id} by user ${req.user._id}`);

    ResponseUtils.success(res, safeSession, 'Session retrieved successfully');
  })
);

/**
 * @route   POST /api/v1/sessions
 * @desc    Create new recording session
 * @access  Private (Doctor, Admin)
 */
router.post('/',
  authenticate,
  authorize('doctor', 'admin'),
  validate(sessionValidation.create),
  asyncErrorHandler(async (req, res) => {
    const { patientId, notes, sessionType, priority } = req.body;

    // Verify patient exists and belongs to doctor
    const patient = await Patient.findOne({
      _id: patientId,
      doctorId: req.user._id,
      isActive: true
    });

    if (!patient) {
      return ResponseUtils.notFound(res, 'Patient not found or access denied');
    }

    // Check patient consent for recording
    if (!patient.consentForRecording) {
      return ResponseUtils.error(
        res,
        'Patient has not provided consent for recording',
        403
      );
    }

    const sessionData = {
      patientId,
      doctorId: req.user._id,
      sessionNotes: notes,
      sessionType: sessionType || 'consultation',
      priority: priority || 'normal',
      status: 'idle',
      patientConsent: {
        recording: patient.consentForRecording,
        transcription: patient.consentForDataSharing,
        storage: patient.consentForTreatment,
        sharing: patient.privacySettings?.shareWithColleagues || false,
        consentTimestamp: new Date()
      },
      createdBy: req.user._id
    };

    const session = new Session(sessionData);
    await session.save();

    await session.populate([
      { path: 'patientId', select: 'name age sex' },
      { path: 'doctorId', select: 'name email specialty' }
    ]);

    // Emit real-time event
    req.io.to(`user_${req.user._id}`).emit('session_created', {
      sessionId: session._id,
      patientName: patient.name,
      status: session.status
    });

    logger.info(`Created new session ${session._id} for patient ${patientId} by user ${req.user._id}`);

    ResponseUtils.created(res, session.getSummary(), 'Session created successfully');
  })
);

/**
 * @route   PUT /api/v1/sessions/:id
 * @desc    Update session
 * @access  Private (Doctor, Admin)
 */
router.put('/:id',
  authenticate,
  checkSessionOwnership,
  validate(sessionValidation.update),
  asyncErrorHandler(async (req, res) => {
    const session = req.session;
    const { status, notes, transcript, sessionType, priority, clinicalNotes } = req.body;

    const allowedUpdates = {
      ...(status && { status }),
      ...(notes && { sessionNotes: notes }),
      ...(transcript && { transcript }),
      ...(sessionType && { sessionType }),
      ...(priority && { priority }),
      ...(clinicalNotes && { clinicalNotes }),
      updatedBy: req.user._id
    };

    // Handle status changes with validation
    if (status && status !== session.status) {
      const validTransitions = {
        'idle': ['recording', 'completed'],
        'recording': ['paused', 'completed'],
        'paused': ['recording', 'completed'],
        'completed': ['uploading'],
        'uploading': ['uploaded', 'failed'],
        'failed': ['uploading', 'completed']
      };

      if (!validTransitions[session.status]?.includes(status)) {
        return ResponseUtils.error(
          res,
          `Cannot transition from ${session.status} to ${status}`,
          400
        );
      }

      // Set end time when completing
      if (status === 'completed' && !session.endTime) {
        allowedUpdates.endTime = new Date();
        allowedUpdates.duration = Math.floor((new Date() - session.startTime) / 1000);
      }
    }

    // Update transcript status if transcript is provided
    if (transcript && !session.transcript) {
      allowedUpdates.transcriptionStatus = 'completed';
      allowedUpdates.transcriptionCompletedAt = new Date();
    }

    Object.assign(session, allowedUpdates);
    await session.save();

    // Log access
    await session.logAccess(req.user._id, 'edit', `Updated fields: ${Object.keys(allowedUpdates).join(', ')}`);

    // Emit real-time event
    req.io.to(`user_${req.user._id}`).emit('session_updated', {
      sessionId: session._id,
      status: session.status,
      uploadProgress: session.uploadProgress
    });

    logger.info(`Updated session ${session._id} by user ${req.user._id}`, {
      updatedFields: Object.keys(allowedUpdates)
    });

    ResponseUtils.updated(res, session.getSummary(), 'Session updated successfully');
  })
);

/**
 * @route   DELETE /api/v1/sessions/:id
 * @desc    Delete session (archive)
 * @access  Private (Doctor, Admin)
 */
router.delete('/:id',
  authenticate,
  checkSessionOwnership,
  asyncErrorHandler(async (req, res) => {
    const session = req.session;

    // Archive instead of hard delete
    await session.archive();

    // Log access
    await session.logAccess(req.user._id, 'delete', 'Session archived');

    logger.info(`Archived session ${session._id} by user ${req.user._id}`);

    ResponseUtils.deleted(res, 'Session archived successfully');
  })
);

/**
 * @route   POST /api/v1/sessions/:id/chunks
 * @desc    Add audio chunk to session
 * @access  Private (Doctor, Admin)
 */
router.post('/:id/chunks',
  authenticate,
  checkSessionOwnership,
  validate(sessionValidation.uploadChunk),
  asyncErrorHandler(async (req, res) => {
    const session = req.session;
    const { chunkId, chunkIndex, duration, fileSize, mimeType } = req.body;

    // Validate session status
    if (!['recording', 'paused', 'completed'].includes(session.status)) {
      return ResponseUtils.error(
        res,
        'Cannot add chunks to session in current status',
        400
      );
    }

    // Check if chunk already exists
    const existingChunk = session.chunks.find(chunk => chunk.chunkId === chunkId);
    if (existingChunk) {
      return ResponseUtils.error(res, 'Chunk with this ID already exists', 409);
    }

    // Generate S3 key
    const s3Service = require('../config/aws');
    const s3Key = s3Service.generateAudioKey(
      session.doctorId.toString(),
      session._id.toString(),
      chunkId,
      mimeType.split('/')[1]
    );

    const chunkData = {
      chunkId,
      chunkIndex,
      duration,
      fileSize,
      mimeType,
      s3Key,
      uploadStatus: 'pending',
      metadata: {
        uploadedFrom: 'mobile',
        deviceInfo: req.body.deviceInfo || {}
      }
    };

    try {
      await session.addChunk(chunkData);

      logger.info(`Added chunk ${chunkId} to session ${session._id}`);

      ResponseUtils.created(res, {
        chunkId,
        s3Key,
        uploadStatus: 'pending'
      }, 'Chunk added successfully');
    } catch (error) {
      ResponseUtils.error(res, error.message, 400);
    }
  })
);

/**
 * @route   PUT /api/v1/sessions/:id/chunks/:chunkId
 * @desc    Update chunk status
 * @access  Private (Doctor, Admin)
 */
router.put('/:id/chunks/:chunkId',
  authenticate,
  checkSessionOwnership,
  asyncErrorHandler(async (req, res) => {
    const session = req.session;
    const { chunkId } = req.params;
    const { status, error: uploadError, s3Url } = req.body;

    const validStatuses = ['pending', 'uploading', 'completed', 'failed'];
    if (!validStatuses.includes(status)) {
      return ResponseUtils.error(res, 'Invalid chunk status', 400);
    }

    try {
      await session.updateChunkStatus(chunkId, status, {
        error: uploadError,
        s3Url
      });

      // Emit real-time progress update
      req.io.to(`user_${session.doctorId}`).emit('upload_progress', {
        sessionId: session._id,
        chunkId,
        status,
        uploadProgress: session.uploadProgress
      });

      logger.info(`Updated chunk ${chunkId} status to ${status} in session ${session._id}`);

      ResponseUtils.success(res, {
        chunkId,
        status,
        uploadProgress: session.uploadProgress
      }, 'Chunk status updated successfully');
    } catch (error) {
      ResponseUtils.error(res, error.message, 400);
    }
  })
);

/**
 * @route   GET /api/v1/sessions/:id/transcript
 * @desc    Get session transcript
 * @access  Private (Doctor, Admin)
 */
router.get('/:id/transcript',
  authenticate,
  checkSessionOwnership,
  asyncErrorHandler(async (req, res) => {
    const session = req.session;

    if (session.transcriptionStatus !== 'completed' || !session.transcript) {
      return ResponseUtils.error(res, 'Transcript not available', 404);
    }

    // Log access
    await session.logAccess(req.user._id, 'view', 'Viewed transcript');

    ResponseUtils.success(res, {
      transcript: session.transcript,
      transcriptionStatus: session.transcriptionStatus,
      transcriptionProvider: session.transcriptionProvider,
      transcriptionCompletedAt: session.transcriptionCompletedAt
    }, 'Transcript retrieved successfully');
  })
);

/**
 * @route   POST /api/v1/sessions/:id/transcribe
 * @desc    Start transcription process
 * @access  Private (Doctor, Admin)
 */
router.post('/:id/transcribe',
  authenticate,
  checkSessionOwnership,
  asyncErrorHandler(async (req, res) => {
    const session = req.session;

    // Validate session status
    if (session.status !== 'uploaded') {
      return ResponseUtils.error(
        res,
        'Session must be fully uploaded before transcription',
        400
      );
    }

    // Check if already transcribed
    if (session.transcriptionStatus === 'completed') {
      return ResponseUtils.error(res, 'Session is already transcribed', 400);
    }

    // Check patient consent
    if (!session.patientConsent.transcription) {
      return ResponseUtils.error(
        res,
        'Patient has not provided consent for transcription',
        403
      );
    }

    // Update transcription status
    session.transcriptionStatus = 'processing';
    session.transcriptionStartedAt = new Date();
    session.transcriptionProvider = 'openai'; // or other provider
    await session.save();

    // TODO: Implement actual transcription service call
    // For now, we'll just simulate the process
    setTimeout(async () => {
      try {
        // Simulate transcription completion
        session.transcriptionStatus = 'completed';
        session.transcriptionCompletedAt = new Date();
        session.transcript = 'This is a simulated transcript. In production, this would be generated by the transcription service.';
        await session.save();

        // Emit real-time event
        req.io.to(`user_${session.doctorId}`).emit('transcription_completed', {
          sessionId: session._id,
          status: 'completed'
        });
      } catch (error) {
        logger.error('Transcription simulation error:', error);
      }
    }, 5000); // 5 second delay for simulation

    logger.info(`Started transcription for session ${session._id}`);

    ResponseUtils.success(res, {
      transcriptionStatus: session.transcriptionStatus,
      estimatedCompletionTime: '2-5 minutes'
    }, 'Transcription started successfully');
  })
);

/**
 * @route   GET /api/v1/sessions/statistics
 * @desc    Get session statistics for doctor
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

    const { startDate, endDate } = req.query;
    const dateRange = {};
    
    if (startDate) dateRange.start = startDate;
    if (endDate) dateRange.end = endDate;

    try {
      const stats = await Session.getStatistics(doctorId, dateRange);
      
      const overview = stats[0] || {
        totalSessions: 0,
        completedSessions: 0,
        failedSessions: 0,
        totalDuration: 0,
        avgDuration: 0,
        totalFileSize: 0,
        transcribedSessions: 0
      };

      // Add calculated fields
      overview.successRate = overview.totalSessions > 0 
        ? Math.round((overview.completedSessions / overview.totalSessions) * 100)
        : 0;
      
      overview.transcriptionRate = overview.totalSessions > 0
        ? Math.round((overview.transcribedSessions / overview.totalSessions) * 100)
        : 0;

      overview.avgDurationFormatted = overview.avgDuration 
        ? `${Math.floor(overview.avgDuration / 60)}m ${Math.floor(overview.avgDuration % 60)}s`
        : '0s';

      overview.totalFileSizeFormatted = overview.totalFileSize
        ? `${(overview.totalFileSize / (1024 * 1024)).toFixed(2)} MB`
        : '0 MB';

      ResponseUtils.success(res, overview, 'Session statistics retrieved successfully');
    } catch (error) {
      logger.error('Error retrieving session statistics:', error);
      ResponseUtils.error(res, 'Failed to retrieve statistics');
    }
  })
);

/**
 * @route   POST /api/v1/sessions/:id/share
 * @desc    Share session with another user
 * @access  Private (Doctor, Admin)
 */
router.post('/:id/share',
  authenticate,
  checkSessionOwnership,
  asyncErrorHandler(async (req, res) => {
    const session = req.session;
    const { userId, permission = 'view' } = req.body;

    if (!userId) {
      return ResponseUtils.error(res, 'User ID is required', 400);
    }

    const validPermissions = ['view', 'edit', 'full'];
    if (!validPermissions.includes(permission)) {
      return ResponseUtils.error(res, 'Invalid permission level', 400);
    }

    // Check if already shared with this user
    const existingShare = session.sharedWith.find(
      share => share.userId.toString() === userId
    );

    if (existingShare) {
      existingShare.permission = permission;
      existingShare.sharedAt = new Date();
    } else {
      session.sharedWith.push({
        userId,
        permission,
        sharedBy: req.user._id
      });
    }

    await session.save();

    // Log access
    await session.logAccess(req.user._id, 'share', `Shared with user ${userId} with ${permission} permission`);

    logger.info(`Shared session ${session._id} with user ${userId} by ${req.user._id}`);

    ResponseUtils.success(res, null, 'Session shared successfully');
  })
);

module.exports = router;