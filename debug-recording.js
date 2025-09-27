#!/usr/bin/env node

const mongoose = require('mongoose');
require('dotenv').config();

// Import models
const Session = require('./src/models/Session');
const Patient = require('./src/models/Patient');

async function debugRecordingFlow() {
  try {
    console.log('🔍 Debugging Recording to MongoDB Flow...\n');
    
    // Connect to MongoDB
    console.log('1. Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected to MongoDB\n');
    
    // Check existing sessions
    console.log('2. Checking existing sessions...');
    const existingSessions = await Session.find({}).populate('patientId', 'name');
    console.log(`📊 Found ${existingSessions.length} existing sessions:`);
    existingSessions.forEach((session, index) => {
      console.log(`   ${index + 1}. ${session._id} - Patient: ${session.patientId?.name || 'Unknown'} - Status: ${session.status} - Chunks: ${session.chunks.length}`);
    });
    console.log('');
    
    // Check existing patients
    console.log('3. Checking existing patients...');
    const existingPatients = await Patient.find({});
    console.log(`👥 Found ${existingPatients.length} existing patients:`);
    existingPatients.forEach((patient, index) => {
      console.log(`   ${index + 1}. ${patient._id} - ${patient.name} - Age: ${patient.age}`);
    });
    console.log('');
    
    // Create a test session if we have patients
    if (existingPatients.length > 0) {
      console.log('4. Creating test recording session...');
      const testPatient = existingPatients[0];
      
      const testSession = new Session({
        patientId: testPatient._id,
        doctorId: new mongoose.Types.ObjectId('507f1f77bcf86cd799439011'), // Mock doctor ID
        sessionNotes: 'Test recording session for debugging',
        sessionType: 'consultation',
        priority: 'normal',
        status: 'recording',
        patientConsent: {
          recording: true,
          transcription: true,
          storage: true,
          sharing: false,
          consentTimestamp: new Date()
        }
      });
      
      const savedSession = await testSession.save();
      console.log(`✅ Created test session: ${savedSession._id}`);
      
      // Add test chunks
      console.log('5. Adding test audio chunks...');
      const testChunks = [
        {
          chunkId: `chunk_${Date.now()}_1`,
          chunkIndex: 0,
          duration: 30,
          fileSize: 1024 * 1024, // 1MB
          mimeType: 'audio/wav',
          fileKey: `sessions/${savedSession._id}/chunks/chunk_1.wav`,
          uploadStatus: 'completed'
        },
        {
          chunkId: `chunk_${Date.now()}_2`,
          chunkIndex: 1,
          duration: 25,
          fileSize: 800 * 1024, // 800KB
          mimeType: 'audio/wav',
          fileKey: `sessions/${savedSession._id}/chunks/chunk_2.wav`,
          uploadStatus: 'completed'
        }
      ];
      
      for (const chunkData of testChunks) {
        await savedSession.addChunk(chunkData);
        console.log(`   ✅ Added chunk: ${chunkData.chunkId}`);
      }
      
      // Verify chunks were saved
      const updatedSession = await Session.findById(savedSession._id);
      console.log(`📁 Session now has ${updatedSession.chunks.length} chunks saved in MongoDB`);
      
      // Show chunk details
      updatedSession.chunks.forEach((chunk, index) => {
        console.log(`   Chunk ${index + 1}: ${chunk.chunkId} - Status: ${chunk.uploadStatus} - Size: ${(chunk.fileSize / 1024).toFixed(1)}KB`);
      });
      
    } else {
      console.log('⚠️  No patients found. Creating a test patient...');
      
      const testPatient = new Patient({
        name: 'Debug Test Patient',
        age: 35,
        sex: 'male',
        address: '123 Debug Street',
        phone: '+1234567890',
        email: 'debug@test.com',
        doctorId: new mongoose.Types.ObjectId('507f1f77bcf86cd799439011'),
        consentForTreatment: true,
        consentForRecording: true,
        isActive: true
      });
      
      const savedPatient = await testPatient.save();
      console.log(`✅ Created test patient: ${savedPatient._id} - ${savedPatient.name}`);
    }
    
    console.log('\n🎯 Recording Flow Analysis Complete!');
    
  } catch (error) {
    console.error('❌ Debug failed:', error);
  } finally {
    await mongoose.connection.close();
    console.log('📚 Database connection closed');
    process.exit(0);
  }
}

// Run the debug
debugRecordingFlow();