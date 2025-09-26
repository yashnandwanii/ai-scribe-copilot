const { S3Client } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const logger = require('../utils/logger');

// Configure AWS S3 client
const s3Client = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const bucket = process.env.AWS_S3_BUCKET;

class S3Service {
  constructor() {
    this.client = s3Client;
    this.bucket = bucket;
  }

  /**
   * Generate a presigned URL for uploading files
   * @param {string} key - S3 object key
   * @param {number} expiresIn - URL expiration time in seconds
   * @param {string} contentType - MIME type of the file
   * @returns {Promise<string>} Presigned URL
   */
  async getPresignedUploadUrl(key, expiresIn = 3600, contentType = 'audio/wav') {
    try {
      const command = new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        ContentType: contentType,
        ServerSideEncryption: 'AES256',
        Metadata: {
          uploadedAt: new Date().toISOString(),
        },
      });

      const presignedUrl = await getSignedUrl(this.client, command, {
        expiresIn,
      });

      logger.info(`Generated presigned upload URL for key: ${key}`);
      return presignedUrl;
    } catch (error) {
      logger.error('Error generating presigned upload URL:', error);
      throw new Error('Failed to generate upload URL');
    }
  }

  /**
   * Generate a presigned URL for downloading files
   * @param {string} key - S3 object key
   * @param {number} expiresIn - URL expiration time in seconds
   * @returns {Promise<string>} Presigned URL
   */
  async getPresignedDownloadUrl(key, expiresIn = 3600) {
    try {
      const command = new GetObjectCommand({
        Bucket: this.bucket,
        Key: key,
      });

      const presignedUrl = await getSignedUrl(this.client, command, {
        expiresIn,
      });

      logger.info(`Generated presigned download URL for key: ${key}`);
      return presignedUrl;
    } catch (error) {
      logger.error('Error generating presigned download URL:', error);
      throw new Error('Failed to generate download URL');
    }
  }

  /**
   * Delete an object from S3
   * @param {string} key - S3 object key
   * @returns {Promise<boolean>} Success status
   */
  async deleteObject(key) {
    try {
      const command = new DeleteObjectCommand({
        Bucket: this.bucket,
        Key: key,
      });

      await this.client.send(command);
      logger.info(`Deleted object with key: ${key}`);
      return true;
    } catch (error) {
      logger.error('Error deleting object:', error);
      throw new Error('Failed to delete file');
    }
  }

  /**
   * Generate S3 key for audio files
   * @param {string} userId - User ID
   * @param {string} sessionId - Session ID
   * @param {string} chunkId - Chunk ID
   * @param {string} extension - File extension
   * @returns {string} S3 key
   */
  generateAudioKey(userId, sessionId, chunkId, extension = 'wav') {
    const timestamp = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    return `audio/${userId}/${timestamp}/${sessionId}/${chunkId}.${extension}`;
  }

  /**
   * Generate S3 key for patient photos
   * @param {string} userId - User ID
   * @param {string} patientId - Patient ID
   * @param {string} extension - File extension
   * @returns {string} S3 key
   */
  generatePhotoKey(userId, patientId, extension = 'jpg') {
    return `photos/${userId}/${patientId}/profile.${extension}`;
  }

  /**
   * Validate file size and type
   * @param {number} fileSize - File size in bytes
   * @param {string} mimeType - MIME type
   * @param {string} fileType - Expected file type ('audio' or 'image')
   * @returns {boolean} Validation result
   */
  validateFile(fileSize, mimeType, fileType) {
    const maxFileSize = parseInt(process.env.MAX_FILE_SIZE) || 104857600; // 100MB
    
    if (fileSize > maxFileSize) {
      throw new Error(`File size exceeds limit of ${maxFileSize} bytes`);
    }

    const allowedTypes = {
      audio: ['audio/wav', 'audio/mp3', 'audio/mpeg', 'audio/ogg', 'audio/webm'],
      image: ['image/jpeg', 'image/png', 'image/webp'],
    };

    if (!allowedTypes[fileType]?.includes(mimeType)) {
      throw new Error(`Invalid file type. Allowed types: ${allowedTypes[fileType].join(', ')}`);
    }

    return true;
  }
}

module.exports = new S3Service();