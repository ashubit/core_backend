/*
 Seed script for demo data: users, sessions, and audit logs.
 Run: node scripts/seed.js
*/

require('dotenv').config();
const db = require('../models');
const mongoose = db.mongoose;

const User = db.user;
const UserSession = require('../models/userSession.model');
const AuditLog = require('../models/auditLog.model');
const RefreshToken = require('../models/refreshToken.model');
const bcrypt = require('bcryptjs');

// Configuration for the seeder
const NUM_USERS = 50; // will create 50 users
const SESSIONS_PER_USER = 2; // 2 sessions each -> 100 sessions
const AUDIT_PER_USER = 5; // audit logs per user

function randomFrom(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

async function seed() {
  try {
    await mongoose.connect(db.url);
    console.log('Connected to DB for seeding');

    // Clear existing demo data (be careful in production)
    await Promise.all([
      User.deleteMany({}),
      UserSession.deleteMany({}),
      AuditLog.deleteMany({}),
      RefreshToken.deleteMany({})
    ]);

    // Create users
    const users = [];
    for (let i = 0; i < NUM_USERS; i++) {
      const email = `user${i + 1}@example.com`;
      const username = `user${i + 1}`;
      const pwd = await bcrypt.hash(`password${i + 1}`, 12);
      users.push({ username, email, pwd, role: i % 10 === 0 ? 'admin' : 'user' });
    }

    const createdUsers = await User.insertMany(users);
    console.log(`Created ${createdUsers.length} users`);

    // Sample locations
    const locations = [
      { country: 'US', city: 'San Francisco', ll: [37.7749, -122.4194] },
      { country: 'GB', city: 'London', ll: [51.5074, -0.1278] },
      { country: 'IN', city: 'Bangalore', ll: [12.9716, 77.5946] },
      { country: 'DE', city: 'Berlin', ll: [52.52, 13.4050] },
      { country: 'AU', city: 'Sydney', ll: [-33.8688, 151.2093] }
    ];

    const now = Date.now();

    // Create sessions and refresh tokens
    const sessionDocs = [];
    for (const u of createdUsers) {
      for (let s = 0; s < SESSIONS_PER_USER; s++) {
        const loc = randomFrom(locations);
        const daysAgo = Math.floor(Math.random() * 30);
        sessionDocs.push({
          userId: u._id,
          deviceInfo: {
            userAgent: 'Mozilla/5.0 (seed-script)',
            ip: `198.51.100.${Math.floor(Math.random() * 200)}`,
            lastLocation: loc
          },
          isActive: s === 0, // keep first session active
          lastActivity: new Date(now - daysAgo * 24 * 60 * 60 * 1000),
          refreshToken: `seed-${u._id.toString().slice(-6)}-${s}-${Math.random().toString(36).slice(2,8)}`,
          expiresAt: new Date(now + 30 * 24 * 60 * 60 * 1000)
        });
      }
    }

    const createdSessions = await UserSession.insertMany(sessionDocs);
    console.log(`Created ${createdSessions.length} sessions`);

    // Create refresh token docs for active sessions
    const refreshDocs = createdSessions.filter(s => s.isActive).map(s => ({
      userId: s.userId,
      token: s.refreshToken,
      issuedAt: new Date(),
      sessionId: s._id
    }));
    if (refreshDocs.length) {
      await RefreshToken.insertMany(refreshDocs);
      console.log(`Created ${refreshDocs.length} refresh tokens`);
    }

    // Create audit logs per user, linking to a random session of that user when possible
    const actions = ['login', 'view', 'update', 'logout', 'download'];
    const auditEntries = [];
    for (const u of createdUsers) {
      const userSessions = createdSessions.filter(s => s.userId.toString() === u._id.toString());
      for (let i = 0; i < AUDIT_PER_USER; i++) {
        const when = new Date(now - Math.floor(Math.random() * 30) * 24 * 60 * 60 * 1000);
        const act = randomFrom(actions);
        const sess = randomFrom(userSessions) || null;
        auditEntries.push({
          userId: u._id,
          action: act,
          resourceType: 'demo',
          resourceId: sess ? sess._id : undefined,
          status: 'success',
          details: { idx: i },
          ip: sess ? sess.deviceInfo.ip : `198.51.100.${Math.floor(Math.random() * 200)}`,
          userAgent: sess ? sess.deviceInfo.userAgent : 'seed-script',
          method: 'GET',
          path: '/api/demo',
          sessionId: sess ? sess._id : undefined,
          createdAt: when,
          updatedAt: when
        });
      }
    }

    await AuditLog.insertMany(auditEntries);
    console.log(`Inserted ${auditEntries.length} audit logs`);

    console.log('Seeding complete.');
    process.exit(0);
  } catch (err) {
    console.error('Seeding failed:', err);
    process.exit(1);
  }
}

seed();
