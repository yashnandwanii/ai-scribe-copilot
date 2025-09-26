const express = require('express');
const multer = require('multer');
const { authenticate, authorize } = require('../middleware/auth');
const { validate, uploadValidation } = require('../utils/validation');
const ResponseUtils = require('../utils/response');
const logger = require('../utils/logger');
const { asyncErrorHandler } = require('../middleware/errorHandler');

const router = express.Router();

// Configure multer for memory storage with file size limits
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB per file
    files: 5 // Maximum 5 files per upload
  },
  fileFilter: (req, file, cb) => {
    const allowedMimeTypes = {
      audio: [
        'audio/mp3',
        'audio/mp4',
        'audio/mpeg',
        'audio/wav',
        'audio/x-wav',
        'audio/aac',
        'audio/ogg',
        'audio/webm',
        'audio/m4a'
      ],
      document: [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain',
        'image/jpeg',
        'image/png',
        'image/tiff'
      ]
    };

    const fileType = req.body.fileType || 'audio';
    const allowedTypes = allowedMimeTypes[fileType] || allowedMimeTypes.audio;

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type. Allowed types: ${allowedTypes.join(', ')}`));
    }
  }
});

/**
 * @route   POST /api/v1/uploads/presigned-url
 * @desc    Generate presigned URL for direct S3 upload
 * @access  Private (Doctor, Admin)
 */
router.post('/presigned-url',
  authenticate,
  authorize('doctor', 'admin'),
  validate(uploadValidation.presignedUrl),
  asyncErrorHandler(async (req, res) => {
    const {
      fileName,
      fileType,
      fileSize,
      sessionId,
      chunkId,
      contentType
    } = req.body;

    // Validate file size limits
    const maxSizes = {
      audio: 100 * 1024 * 1024, // 100MB
      document: 50 * 1024 * 1024, // 50MB
      image: 10 * 1024 * 1024 // 10MB
    };

    const maxSize = maxSizes[fileType] || maxSizes.audio;
    if (fileSize > maxSize) {
      return ResponseUtils.error(
        res,
        `File size exceeds limit of ${maxSize / (1024 * 1024)}MB`,
        400
      );
    }

    // Generate S3 key based on file type
    let s3Key;
    switch (fileType) {
      case 'audio':
        if (!sessionId || !chunkId) {
          return ResponseUtils.error(
            res,
            'sessionId and chunkId are required for audio files',
            400
          );
        }
        s3Key = s3Service.generateAudioKey(
          req.user._id.toString(),
          sessionId,
          chunkId,
          fileName.split('.').pop()
        );
        break;
      
      case 'document':
        s3Key = s3Service.generateDocumentKey(
          req.user._id.toString(),
          fileName
        );
        break;
      
      case 'image':
        s3Key = s3Service.generateImageKey(
          req.user._id.toString(),
          fileName
        );
        break;
      
      default:
        return ResponseUtils.error(res, 'Invalid file type', 400);
    }

    try {
      const presignedData = await s3Service.generatePresignedUploadUrl(
        s3Key,
        contentType,
        fileSize,
        {
          userId: req.user._id.toString(),
          sessionId,
          chunkId,
          uploadedAt: new Date().toISOString()
        }
      );

      // Log the upload initiation
      logger.info(`Generated presigned URL for ${fileType} upload`, {
        userId: req.user._id,
        fileName,
        fileType,
        fileSize,
        s3Key,
        sessionId,
        chunkId
      });

      ResponseUtils.success(res, {
        uploadUrl: presignedData.uploadUrl,
        fields: presignedData.fields,
        s3Key,
        expiresIn: 3600, // 1 hour
        maxFileSize: maxSize
      }, 'Presigned URL generated successfully');

    } catch (error) {
      logger.error('Error generating presigned URL:', error);
      ResponseUtils.error(res, 'Failed to generate upload URL');
    }
  })
);

/**
 * @route   POST /api/v1/uploads/direct
 * @desc    Direct file upload to server (fallback option)
 * @access  Private (Doctor, Admin)
 */
router.post('/direct',
  authenticate,
  authorize('doctor', 'admin'),
  upload.array('files', 5),
  validate(uploadValidation.directUpload),
  asyncErrorHandler(async (req, res) => {
    if (!req.files || req.files.length === 0) {
      return ResponseUtils.error(res, 'No files uploaded', 400);
    }

    const { fileType, sessionId, chunkId } = req.body;
    const uploadResults = [];

    try {
      for (const file of req.files) {
        // Generate S3 key
        let s3Key;
        switch (fileType) {
          case 'audio':
            if (!sessionId || !chunkId) {
              throw new Error('sessionId and chunkId are required for audio files');
            }
            s3Key = s3Service.generateAudioKey(
              req.user._id.toString(),
              sessionId,
              chunkId,
              file.originalname.split('.').pop()
            );
            break;
          
          case 'document':
            s3Key = s3Service.generateDocumentKey(
              req.user._id.toString(),
              file.originalname
            );
            break;
          
          case 'image':
            s3Key = s3Service.generateImageKey(
              req.user._id.toString(),
              file.originalname
            );
            break;
          
          default:
            throw new Error('Invalid file type');
        }

        // Upload to S3
        const uploadResult = await s3Service.uploadFile(
          s3Key,
          file.buffer,
          file.mimetype,
          {
            userId: req.user._id.toString(),
            sessionId,
            chunkId,
            originalName: file.originalname,
            uploadedAt: new Date().toISOString()
          }
        );

        uploadResults.push({
          originalName: file.originalname,
          s3Key,
          s3Url: uploadResult.Location,
          fileSize: file.size,
          mimeType: file.mimetype,
          uploadedAt: new Date()
        });

        logger.info(`Successfully uploaded file ${file.originalname}`, {
          userId: req.user._id,
          s3Key,
          fileSize: file.size,
          sessionId,
          chunkId
        });
      }

      ResponseUtils.success(res, {
        uploads: uploadResults,
        totalFiles: uploadResults.length
      }, 'Files uploaded successfully');

    } catch (error) {
      logger.error('Error uploading files:', error);
      
      // Clean up any partially uploaded files
      for (const result of uploadResults) {
        try {
          await s3Service.deleteFile(result.s3Key);
        } catch (cleanupError) {
          logger.error('Error cleaning up failed upload:', cleanupError);
        }
      }

      ResponseUtils.error(res, error.message || 'Failed to upload files');
    }
  })
);

/**
 * @route   DELETE /api/v1/uploads/:s3Key
 * @desc    Delete uploaded file
 * @access  Private (Doctor, Admin)
 */
router.delete('/:s3Key(*)',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const { s3Key } = req.params;

    if (!s3Key) {
      return ResponseUtils.error(res, 'S3 key is required', 400);
    }

    // Extract user ID from S3 key to verify ownership
    const keyParts = s3Key.split('/');
    const keyUserId = keyParts[1]; // Format: uploads/userId/...

    if (req.user.role !== 'admin' && keyUserId !== req.user._id.toString()) {
      return ResponseUtils.error(res, 'Access denied', 403);
    }

    try {
      await s3Service.deleteFile(s3Key);

      logger.info(`Deleted file from S3`, {
        userId: req.user._id,
        s3Key
      });

      ResponseUtils.success(res, null, 'File deleted successfully');

    } catch (error) {
      if (error.code === 'NoSuchKey') {
        return ResponseUtils.notFound(res, 'File not found');
      }

      logger.error('Error deleting file:', error);
      ResponseUtils.error(res, 'Failed to delete file');
    }
  })
);

/**
 * @route   GET /api/v1/uploads/download/:s3Key
 * @desc    Generate presigned URL for file download
 * @access  Private (Doctor, Admin)
 */
router.get('/download/:s3Key(*)',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const { s3Key } = req.params;
    const { inline = false } = req.query;

    if (!s3Key) {
      return ResponseUtils.error(res, 'S3 key is required', 400);
    }

    // Extract user ID from S3 key to verify ownership
    const keyParts = s3Key.split('/');
    const keyUserId = keyParts[1]; // Format: uploads/userId/...

    if (req.user.role !== 'admin' && keyUserId !== req.user._id.toString()) {
      return ResponseUtils.error(res, 'Access denied', 403);
    }

    try {
      // Check if file exists
      const fileExists = await s3Service.fileExists(s3Key);
      if (!fileExists) {
        return ResponseUtils.notFound(res, 'File not found');
      }

      // Generate presigned download URL
      const downloadUrl = await s3Service.generatePresignedDownloadUrl(
        s3Key,
        3600, // 1 hour expiration
        inline
      );

      logger.info(`Generated download URL for file`, {
        userId: req.user._id,
        s3Key,
        inline
      });

      ResponseUtils.success(res, {
        downloadUrl,
        expiresIn: 3600,
        s3Key
      }, 'Download URL generated successfully');

    } catch (error) {
      logger.error('Error generating download URL:', error);
      ResponseUtils.error(res, 'Failed to generate download URL');
    }
  })
);

/**
 * @route   GET /api/v1/uploads/list
 * @desc    List uploaded files for user
 * @access  Private (Doctor, Admin)
 */
router.get('/list',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const {
      fileType,
      sessionId,
      page = 1,
      limit = 20,
      sortBy = 'uploadedAt',
      sortOrder = 'desc'
    } = req.query;

    const userId = req.user.role === 'admin' 
      ? req.query.userId || req.user._id 
      : req.user._id;

    try {
      const prefix = `uploads/${userId}/`;
      const files = await s3Service.listFiles(
        prefix,
        {
          fileType,
          sessionId,
          page: parseInt(page),
          limit: parseInt(limit),
          sortBy,
          sortOrder
        }
      );

      // Filter files based on query parameters
      let filteredFiles = files;
      
      if (fileType) {
        const typeMap = {
          audio: 'audio/',
          document: 'documents/',
          image: 'images/'
        };
        const typePrefix = typeMap[fileType];
        if (typePrefix) {
          filteredFiles = files.filter(file => 
            file.key.includes(typePrefix)
          );
        }
      }

      if (sessionId) {
        filteredFiles = filteredFiles.filter(file =>
          file.key.includes(`/sessions/${sessionId}/`)
        );
      }

      // Add download URLs for recent files
      const filesWithUrls = await Promise.all(
        filteredFiles.slice(0, 10).map(async (file) => {
          try {
            const downloadUrl = await s3Service.generatePresignedDownloadUrl(
              file.key,
              3600 // 1 hour
            );
            return {
              ...file,
              downloadUrl
            };
          } catch (error) {
            logger.warn(`Failed to generate download URL for ${file.key}:`, error);
            return file;
          }
        })
      );

      logger.info(`Listed ${filteredFiles.length} files for user ${userId}`);

      ResponseUtils.success(res, {
        files: filesWithUrls,
        total: filteredFiles.length,
        page: parseInt(page),
        limit: parseInt(limit)
      }, 'Files listed successfully');

    } catch (error) {
      logger.error('Error listing files:', error);
      ResponseUtils.error(res, 'Failed to list files');
    }
  })
);

/**
 * @route   POST /api/v1/uploads/batch-delete
 * @desc    Delete multiple files
 * @access  Private (Doctor, Admin)
 */
router.post('/batch-delete',
  authenticate,
  validate(uploadValidation.batchDelete),
  asyncErrorHandler(async (req, res) => {
    const { s3Keys } = req.body;

    if (!Array.isArray(s3Keys) || s3Keys.length === 0) {
      return ResponseUtils.error(res, 'S3 keys array is required', 400);
    }

    if (s3Keys.length > 100) {
      return ResponseUtils.error(res, 'Maximum 100 files can be deleted at once', 400);
    }

    // Verify ownership of all files
    for (const s3Key of s3Keys) {
      const keyParts = s3Key.split('/');
      const keyUserId = keyParts[1];

      if (req.user.role !== 'admin' && keyUserId !== req.user._id.toString()) {
        return ResponseUtils.error(
          res,
          `Access denied for file: ${s3Key}`,
          403
        );
      }
    }

    try {
      const results = await s3Service.deleteMultipleFiles(s3Keys);

      const successCount = results.Deleted?.length || 0;
      const errorCount = results.Errors?.length || 0;

      logger.info(`Batch deleted ${successCount} files, ${errorCount} errors`, {
        userId: req.user._id,
        successCount,
        errorCount,
        errors: results.Errors
      });

      ResponseUtils.success(res, {
        successCount,
        errorCount,
        errors: results.Errors || []
      }, `Successfully deleted ${successCount} files`);

    } catch (error) {
      logger.error('Error in batch delete:', error);
      ResponseUtils.error(res, 'Failed to delete files');
    }
  })
);

/**
 * @route   GET /api/v1/uploads/storage-stats
 * @desc    Get storage usage statistics
 * @access  Private (Doctor, Admin)
 */
router.get('/storage-stats',
  authenticate,
  asyncErrorHandler(async (req, res) => {
    const userId = req.user.role === 'admin' 
      ? req.query.userId || req.user._id 
      : req.user._id;

    try {
      const stats = await s3Service.getStorageStats(userId.toString());

      ResponseUtils.success(res, {
        totalFiles: stats.totalFiles,
        totalSize: stats.totalSize,
        totalSizeFormatted: `${(stats.totalSize / (1024 * 1024)).toFixed(2)} MB`,
        byFileType: stats.byFileType,
        storageLimit: 1024 * 1024 * 1024, // 1GB limit
        usagePercentage: Math.round((stats.totalSize / (1024 * 1024 * 1024)) * 100)
      }, 'Storage statistics retrieved successfully');

    } catch (error) {
      logger.error('Error retrieving storage stats:', error);
      ResponseUtils.error(res, 'Failed to retrieve storage statistics');
    }
  })
);

// Handle multer errors
router.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return ResponseUtils.error(res, 'File size too large', 400);
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
      return ResponseUtils.error(res, 'Too many files', 400);
    }
  }
  
  if (error.message && error.message.includes('Invalid file type')) {
    return ResponseUtils.error(res, error.message, 400);
  }

  next(error);
});

module.exports = router;