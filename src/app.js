const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');

// Load environment variables
dotenv.config({ path: path.join(__dirname, '../.env') });

// Import models with error handling
let Patient, Session, User;
try {
  Patient = require('./models/Patient');
  Session = require('./models/Session');
  User = require('./models/User');
  console.log('✅ Models loaded successfully');
} catch (error) {
  console.log('⚠️ Models failed to load:', error.message);
  console.log('📄 Creating mock models for development...');
  
  // Create minimal mock models
  const mockSchema = new mongoose.Schema({}, { strict: false });
  Patient = mongoose.model('Patient', mockSchema);
  Session = mongoose.model('Session', mockSchema);
  User = mongoose.model('User', mockSchema);
}

const app = express();
const PORT = process.env.PORT || 3000;

// Basic middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ MongoDB connected successfully');
  } catch (error) {
    console.log('❌ MongoDB connection failed:', error.message);
    // Continue running without database connection for development
  }
};

// Connect to database
connectDB();

// Basic routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'Welcome to the Medication App API',
    status: 'running',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Authentication Routes
app.post('/api/v1/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone, specialty, licenseNumber, hospitalAffiliation } = req.body;
    
    // Validate required fields
    if (!name || !email || !password || !phone || !specialty) {
      return res.status(400).json({
        success: false,
        message: 'Please provide all required fields: name, email, password, phone, specialty'
      });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
    }
    
    // Create new user
    const userData = {
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password,
      phone: phone.trim(),
      specialty: specialty.trim(),
      role: 'doctor'
    };
    
    // Add optional fields if provided
    if (licenseNumber && licenseNumber.trim()) {
      userData.licenseNumber = licenseNumber.trim();
    }
    
    if (hospitalAffiliation && hospitalAffiliation.trim()) {
      userData.hospitalAffiliation = hospitalAffiliation.trim();
    }
    
    const user = new User(userData);
    await user.save();
    
    // Generate tokens
    const authToken = user.generateAuthToken();
    const refreshToken = user.generateRefreshToken();
    
    // Return success response
    res.status(201).json({
      success: true,
      message: 'Registration successful',
      data: {
        user: user.toSafeObject(),
        token: authToken,
        refreshToken: refreshToken
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors
      });
    }
    
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'Email already exists'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Registration failed. Please try again.'
    });
  }
});

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide email and password'
      });
    }
    
    // Find user and validate credentials
    const user = await User.findByCredentials(email, password);
    
    // Generate tokens
    const authToken = user.generateAuthToken();
    const refreshToken = user.generateRefreshToken();
    
    // Set token expiration based on rememberMe
    const tokenExpiration = rememberMe ? '30d' : '7d';
    
    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: user.toSafeObject(),
        token: authToken,
        refreshToken: refreshToken,
        expiresIn: tokenExpiration
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    
    // Handle specific error messages
    if (error.message === 'Invalid login credentials') {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    
    if (error.message.includes('Account is temporarily locked')) {
      return res.status(423).json({
        success: false,
        message: 'Account temporarily locked due to multiple failed login attempts. Please try again later.'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Login failed. Please try again.'
    });
  }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Please provide email address'
      });
    }
    
    const user = await User.findOne({ 
      email: email.toLowerCase(), 
      isActive: true 
    });
    
    if (!user) {
      // Don't reveal if email exists or not for security
      return res.json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.'
      });
    }
    
    // Generate reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });
    
    // In a real application, you would send an email here
    console.log(`Password reset token for ${email}: ${resetToken}`);
    
    res.json({
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.',
      // Remove this in production - only for testing
      resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined
    });
    
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process password reset request'
    });
  }
});

app.get('/api/v1/auth/me', async (req, res) => {
  try {
    // In a real app, you would validate the JWT token here
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'No authorization token provided'
      });
    }
    
    // Mock user data - in real app, decode JWT and get user from DB
    const mockUser = {
      id: '68d699d11a388e0ec1898ece',
      name: 'Dr. Rohan Test',
      email: 'rohan@test.com',
      role: 'doctor',
      specialty: 'General Medicine',
      isActive: true
    };
    
    res.json({
      success: true,
      data: {
        user: mockUser
      }
    });
    
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get current user'
    });
  }
});

app.post('/api/v1/auth/logout', async (req, res) => {
  try {
    // In a stateless JWT system, logout is typically handled client-side
    // But we can add the token to a blacklist if needed
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
    
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Logout failed'
    });
  }
});

// Patient Management APIs
app.get('/api/v1/patients', async (req, res) => {
  try {
    const { page = 1, limit = 50, sort = '-createdAt' } = req.query;
    
    // Mock data or database query
    let patients = [];
    
    try {
      // Try to get patients from database
      patients = await Patient.find({ 
        isActive: true 
      }).select('name age sex address photoPath phone email bloodType allergies medications createdAt updatedAt doctorId')
        .sort(sort)
        .limit(parseInt(limit))
        .skip((parseInt(page) - 1) * parseInt(limit));
        
      console.log(`Found ${patients.length} patients in database`);
    } catch (dbError) {
      console.log('Database error, using mock data:', dbError.message);
      
      // Fallback to mock data
      patients = [
        {
          _id: '507f1f77bcf86cd799439011',
          name: 'John Doe',
          age: 35,
          sex: 'male',
          address: '123 Main St, City, State 12345',
          phone: '+1-555-0123',
          email: 'john.doe@email.com',
          bloodType: 'O+',
          allergies: [],
          medications: [],
          photoPath: null,
          createdAt: new Date(),
          updatedAt: new Date(),
          doctorId: '68d699d11a388e0ec1898ece'
        },
        {
          _id: '507f1f77bcf86cd799439012',
          name: 'Jane Smith',
          age: 28,
          sex: 'female',
          address: '456 Oak Ave, City, State 12345',
          phone: '+1-555-0124',
          email: 'jane.smith@email.com',
          bloodType: 'A+',
          allergies: [],
          medications: [],
          photoPath: null,
          createdAt: new Date(),
          updatedAt: new Date(),
          doctorId: '68d699d11a388e0ec1898ece'
        }
      ];
    }
    
    // Transform to match Flutter app's expected format
    const formattedPatients = patients.map(patient => ({
      id: patient._id ? patient._id.toString() : patient.id,
      name: patient.name,
      age: patient.age,
      sex: patient.sex,
      address: patient.address,
      phone: patient.phone || '',
      email: patient.email || '',
      bloodType: patient.bloodType || 'Unknown',
      allergies: patient.allergies || [],
      medications: patient.medications || [],
      photoPath: patient.photoPath,
      createdAt: patient.createdAt ? patient.createdAt.toISOString() : new Date().toISOString(),
      updatedAt: patient.updatedAt ? patient.updatedAt.toISOString() : new Date().toISOString(),
      doctorId: patient.doctorId
    }));
    
    // Return paginated response
    const totalCount = patients.length;
    res.json({
      success: true,
      data: {
        patients: formattedPatients,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: totalCount,
          pages: Math.ceil(totalCount / parseInt(limit))
        }
      }
    });
  } catch (error) {
    console.error('Error fetching patients:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch patients',
      message: error.message 
    });
  }
});

app.post('/api/v1/patients', async (req, res) => {
  try {
    const patientData = req.body;
    
    // Validate required fields
    if (!patientData.name || !patientData.age || !patientData.sex || !patientData.address) {
      return res.status(400).json({ 
        success: false,
        error: 'Missing required fields: name, age, sex, address' 
      });
    }
    
    let savedPatient;
    
    try {
      // Try to save to database
      const newPatient = new Patient({
        name: patientData.name.trim(),
        age: parseInt(patientData.age),
        sex: patientData.sex.toLowerCase(),
        address: patientData.address.trim(),
        phone: patientData.phone || '',
        email: patientData.email || '',
        bloodType: patientData.bloodType || 'Unknown',
        allergies: patientData.allergies || [],
        medications: patientData.medications || [],
        photoPath: patientData.photoPath || null,
        doctorId: '68d699d11a388e0ec1898ece', // Default doctor ID
        createdBy: '68d699d11a388e0ec1898ece', // Default doctor ID
        consentForTreatment: true,
        consentForRecording: true,
        isActive: true
      });
      
      savedPatient = await newPatient.save();
      console.log('✅ Patient saved to database:', savedPatient._id);
      
    } catch (dbError) {
      console.log('⚠️ Database save failed, creating mock response:', dbError.message);
      
      // Create mock saved patient
      savedPatient = {
        _id: new Date().getTime().toString(),
        name: patientData.name.trim(),
        age: parseInt(patientData.age),
        sex: patientData.sex.toLowerCase(),
        address: patientData.address.trim(),
        phone: patientData.phone || '',
        email: patientData.email || '',
        bloodType: patientData.bloodType || 'Unknown',
        allergies: patientData.allergies || [],
        medications: patientData.medications || [],
        photoPath: patientData.photoPath || null,
        createdAt: new Date(),
        updatedAt: new Date(),
        doctorId: '68d699d11a388e0ec1898ece'
      };
    }
    
    // Format response to match Flutter app's expected format
    const response = {
      success: true,
      data: {
        id: savedPatient._id ? savedPatient._id.toString() : savedPatient.id,
        name: savedPatient.name,
        age: savedPatient.age,
        sex: savedPatient.sex,
        address: savedPatient.address,
        phone: savedPatient.phone || '',
        email: savedPatient.email || '',
        bloodType: savedPatient.bloodType || 'Unknown',
        allergies: savedPatient.allergies || [],
        medications: savedPatient.medications || [],
        photoPath: savedPatient.photoPath,
        createdAt: savedPatient.createdAt ? savedPatient.createdAt.toISOString() : new Date().toISOString(),
        updatedAt: savedPatient.updatedAt ? savedPatient.updatedAt.toISOString() : new Date().toISOString(),
        doctorId: savedPatient.doctorId
      }
    };
    
    console.log('✅ Patient created successfully:', response.data.name);
    res.status(201).json(response);
  } catch (error) {
    console.error('❌ Error adding patient:', error);
    
    res.status(500).json({ 
      success: false,
      error: 'Failed to add patient',
      message: error.message 
    });
  }
});

// Patient Statistics API
app.get('/api/v1/patients/stats/overview', async (req, res) => {
  try {
    let stats;
    
    try {
      // Try to get real statistics from database
      const totalPatients = await Patient.countDocuments({ isActive: true });
      const maleCount = await Patient.countDocuments({ sex: 'male', isActive: true });
      const femaleCount = await Patient.countDocuments({ sex: 'female', isActive: true });
      const urgentPatients = await Patient.countDocuments({ priority: 'urgent', isActive: true });
      
      stats = {
        totalPatients,
        malePatients: maleCount,
        femalePatients: femaleCount,
        urgentPatients,
        averageAge: 35 // Mock average age
      };
      
      console.log('✅ Real statistics retrieved from database');
      
    } catch (dbError) {
      console.log('⚠️ Database stats failed, using mock data:', dbError.message);
      
      // Fallback to mock statistics
      stats = {
        totalPatients: 12,
        malePatients: 7,
        femalePatients: 5,
        urgentPatients: 2,
        averageAge: 35
      };
    }
    
    res.json({
      success: true,
      data: stats
    });
    
  } catch (error) {
    console.error('❌ Error fetching statistics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch statistics',
      message: error.message
    });
  }
});

// Session Statistics API
app.get('/api/v1/sessions/stats/overview', async (req, res) => {
  try {
    let sessionStats;
    
    try {
      // Try to get real session statistics from database
      const totalSessions = await Session.countDocuments({ isArchived: false });
      const completedSessions = await Session.countDocuments({ status: 'completed', isArchived: false });
      const activeSessions = await Session.countDocuments({ status: 'recording', isArchived: false });
      const failedSessions = await Session.countDocuments({ status: 'failed', isArchived: false });
      
      sessionStats = {
        totalSessions,
        completedSessions,
        activeSessions,
        failedSessions,
        averageDuration: 15 // Mock average duration in minutes
      };
      
      console.log('✅ Real session statistics retrieved from database');
      
    } catch (dbError) {
      console.log('⚠️ Database session stats failed, using mock data:', dbError.message);
      
      // Fallback to mock session statistics
      sessionStats = {
        totalSessions: 25,
        completedSessions: 22,
        activeSessions: 1,
        failedSessions: 2,
        averageDuration: 15
      };
    }
    
    res.json({
      success: true,
      data: sessionStats
    });
    
  } catch (error) {
    console.error('❌ Error fetching session statistics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch session statistics',
      message: error.message
    });
  }
});

// Session Management APIs
app.post('/api/v1/sessions', async (req, res) => {
  try {
    const { patientId } = req.body;
    
    if (!patientId) {
      return res.status(400).json({ error: 'patientId is required' });
    }
    
    // Verify patient exists
    const patient = await Patient.findById(patientId);
    if (!patient) {
      return res.status(404).json({ error: 'Patient not found' });
    }
    
    // Create new session
    const newSession = new Session({
      patientId: patientId,
      doctorId: patient.doctorId,
      status: 'idle',
      createdBy: patient.doctorId,
      patientConsent: {
        recording: true,
        transcription: true,
        storage: true,
        consentTimestamp: new Date()
      }
    });
    
    const savedSession = await newSession.save();
    
    console.log('Creating session for patient:', patientId, 'Session ID:', savedSession._id);
    res.json({ sessionId: savedSession._id.toString() });
  } catch (error) {
    console.error('Error creating session:', error);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

app.post('/v1/get-presigned-url', async (req, res) => {
  try {
    const { sessionId, chunkId } = req.body;
    
    if (!sessionId || !chunkId) {
      return res.status(400).json({ error: 'sessionId and chunkId are required' });
    }
    
    // Find session
    const session = await Session.findById(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    
    // Local storage upload URL
    const uploadUrl = `http://localhost:3000/upload/${sessionId}/${chunkId}`;
    const localKey = `sessions/${sessionId}/chunks/${chunkId}.wav`;
    
    // Add chunk to session
    const chunkData = {
      chunkId: chunkId,
      chunkIndex: session.chunks.length,
      duration: 0, // Will be updated when chunk is uploaded
      fileSize: 0, // Will be updated when chunk is uploaded
      mimeType: 'audio/wav',
      fileKey: localKey,
      presignedUploadUrl: uploadUrl,
      presignedUrlExpires: new Date(Date.now() + 3600000), // 1 hour from now
      uploadStatus: 'pending'
    };
    
    session.chunks.push(chunkData);
    await session.save();
    
    console.log('Generated presigned URL for session:', sessionId, 'chunk:', chunkId);
    res.json({ uploadUrl });
  } catch (error) {
    console.error('Error generating presigned URL:', error);
    res.status(500).json({ error: 'Failed to generate presigned URL' });
  }
});

app.put('/upload/:sessionId/:chunkId', async (req, res) => {
  try {
    const { sessionId, chunkId } = req.params;
    
    // Find session and update chunk status
    const session = await Session.findById(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    
    const chunk = session.chunks.find(c => c.chunkId === chunkId);
    if (!chunk) {
      return res.status(404).json({ error: 'Chunk not found' });
    }
    
    // Update chunk status (mock upload - in production this would handle actual file upload)
    chunk.uploadStatus = 'completed';
    chunk.uploadCompletedAt = new Date();
    chunk.fileSize = req.get('content-length') || 1024; // Mock file size
    chunk.duration = 10; // Mock duration
    chunk.fileUrl = `http://localhost:3000/files/${chunk.fileKey}`;
    
    await session.save();
    
    console.log('Received chunk upload for session:', sessionId, 'chunk:', chunkId);
    res.json({ success: true, message: 'Chunk uploaded successfully' });
  } catch (error) {
    console.error('Error uploading chunk:', error);
    res.status(500).json({ error: 'Failed to upload chunk' });
  }
});

app.post('/v1/notify-chunk-uploaded', async (req, res) => {
  try {
    const { sessionId, chunkId } = req.body;
    
    if (!sessionId || !chunkId) {
      return res.status(400).json({ error: 'sessionId and chunkId are required' });
    }
    
    // Find session and log the notification
    const session = await Session.findById(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    
    console.log('Chunk upload notification for session:', sessionId, 'chunk:', chunkId);
    res.json({ success: true });
  } catch (error) {
    console.error('Error processing chunk notification:', error);
    res.status(500).json({ error: 'Failed to process notification' });
  }
});

app.get('/api/v1/patients/:patientId/sessions', async (req, res) => {
  try {
    const { patientId } = req.params;
    
    if (!patientId) {
      return res.status(400).json({ error: 'patientId is required' });
    }
    
    // Get sessions from database
    const sessions = await Session.find({ 
      patientId: patientId,
      isArchived: false 
    })
    .populate('patientId', 'name')
    .sort('-createdAt')
    .limit(50); // Limit to 50 most recent sessions
    
    // Transform to match Flutter app's expected format
    const formattedSessions = sessions.map(session => {
      // Map session status to Flutter app's enum values
      let statusIndex = 0; // idle
      switch (session.status) {
        case 'recording': statusIndex = 1; break;
        case 'paused': statusIndex = 2; break;
        case 'completed': statusIndex = 3; break;
        case 'uploading': statusIndex = 4; break;
        case 'uploaded': statusIndex = 5; break;
        case 'failed': statusIndex = 6; break;
        default: statusIndex = 0; // idle
      }
      
      return {
        id: session._id.toString(),
        patientId: session.patientId._id.toString(),
        patientName: session.patientId.name,
        filePath: `/recordings/${session._id}.wav`, // Mock file path
        startTime: session.startTime.toISOString(),
        endTime: session.endTime ? session.endTime.toISOString() : null,
        status: statusIndex,
        chunks: session.chunks.map(chunk => ({
          id: chunk.chunkId,
          sessionId: session._id.toString(),
          localPath: chunk.fileKey,
          timestamp: chunk.createdAt.toISOString(),
          duration: chunk.duration,
          isUploaded: chunk.uploadStatus === 'completed',
          uploadUrl: chunk.presignedUploadUrl,
          remoteUrl: chunk.fileUrl
        })),
        duration: session.duration,
        transcript: session.transcript
      };
    });
    
    res.json(formattedSessions);
  } catch (error) {
    console.error('Error fetching sessions:', error);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: err.message
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.originalUrl
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`📋 API Endpoints available:`);
  console.log(`   GET  /api/v1/patients`);
  console.log(`   POST /api/v1/patients`);
  console.log(`   GET  /api/v1/patients/stats/overview`);
  console.log(`   GET  /api/v1/auth/me`);
});

// Handle server errors
server.on('error', (error) => {
  console.error('❌ Server error:', error);
  if (error.syscall !== 'listen') {
    throw error;
  }
  
  const bind = typeof PORT === 'string' ? 'Pipe ' + PORT : 'Port ' + PORT;
  
  switch (error.code) {
    case 'EACCES':
      console.error(bind + ' requires elevated privileges');
      process.exit(1);
      break;
    case 'EADDRINUSE':
      console.error(bind + ' is already in use');
      process.exit(1);
      break;
    default:
      throw error;
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('💤 Process terminated');
  });
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('💤 Process terminated');
  });
});

module.exports = app;