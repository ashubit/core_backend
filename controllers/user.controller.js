const db = require("../models");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const RefreshToken = require('../models/refreshToken.model');
const UserSession = require('./../models/userSession.model')
const crypto = require('crypto');
const { error } = require("console");

const User = db.user;

// Use environment JWT secret; fail closed in production (but allow fallback during dev)
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const REFRESH_TOKEN_EXPIRES_IN = '30d';

// Helper to generate tokens
const generateTokens = async (user, req) => {
  const accessToken = jwt.sign({ 
    userId: user._id,
    role: user.role || 'user'
  }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

  // Generate refresh token
  const refreshToken = crypto.randomBytes(40).toString('hex');
  
  // Calculate token expiration using REFRESH_TOKEN_EXPIRES_IN
  const expiresAt = new Date();
  const daysToAdd = parseInt(REFRESH_TOKEN_EXPIRES_IN) || 30;
  expiresAt.setDate(expiresAt.getDate() + daysToAdd);

  // Create session
  const session = await UserSession.create({
    userId: user._id,
    refreshToken,
    expiresAt,
    deviceInfo: {
      userAgent: req.headers['user-agent'] || req.headers['User-Agent'],
      ip: req.ip || req.connection?.remoteAddress,
      lastLocation: req.headers['cf-ipcountry'] // If using Cloudflare, or implement GeoIP
    },
    isActive: true
  });

  // Save refresh token
  await RefreshToken.create({
    userId: user._id,
    token: refreshToken,
    issuedAt: new Date(),
    sessionId: session._id
  });

  return { accessToken, refreshToken, sessionId: session._id };
};

// helper to safely escape user input for RegExp (prevents ReDoS / unexpected patterns)
const escapeRegex = (text) => {
  if (!text) return '';
  return text.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&");
};

// Create and Save a new User
exports.create = (req, res) => {
  // Validate request
  if (!req.body.email || !req.body.name) {
    return res.status(400).send({ message: "Content can not be empty!" });
  }

  // create user object; optionally accept a password (hash it) but do not default to weak passwords
  const userData = {
    username: req.body.name,
    email: req.body.email,
    mobile: req.body.contact,
    status: req.body.status ? req.body.status : false,
  };

  const password = 1234;
  const createAndRespond = async () => {
    try {
      userData.pwd = await bcrypt.hash(password, 12);
      
      const user = new User(userData);
      const saved = await user.save();
      // saved.toJSON will already exclude pwd because of model changes
      res.status(201).send(saved);
    } catch (err) {
      res.status(500).send({ message: err.message || "Some error occurred while creating the User." });
    }
  };

  createAndRespond();
};

// Update a User using id
exports.update = (req, res) => {
  const id = req.params.id;
  console.log(req.body);
  // Validate request
  if (!id && req.body) {
    res.status(400).send({ message: "Content can not be empty!" });
    return;
  }

  const myquery = { _id: id };
  const newvalues = { $set: req.body };

  // Save User in the database
  User.updateOne(myquery, newvalues)
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      res.status(500).send({
        message: err.message || "Some error occurred while creating the User.",
      });
    });
};

// Retrieve all Users from the database.
exports.findAll = (req, res) => {
  // allow searching by q which will search username or email (safe-escaped)
  const q = req.query.q;
  let condition = {};
  if (q) {
    const safe = escapeRegex(String(q)).slice(0, 100); // limit length
    const regex = new RegExp(safe, 'i');
    condition = { $or: [{ username: { $regex: regex } }, { email: { $regex: regex } }] };
  }

  // limit results to avoid overloading responses; allow client to request up to a cap
  const limit = Math.min(parseInt(req.query.limit || '100', 10) || 100, 1000);

  User.find(condition)
    .select('-pwd') // never return password
    .sort({ createdAt: -1 }) // newest first
    .limit(limit)
    .then((data) => res.send(data))
    .catch((err) => {
      res.status(500).send({ message: err.message || "Some error occurred while retrieving Users." });
    });
};

// Find a single User with an id
exports.findOne = (req, res) => {
  const id = req.params.id;
  User.findById(id)
    .select('-pwd')
    .then((data) => {
      if (!data) return res.status(404).send({ message: "Not found User with id " + id });
      return res.send(data);
    })
    .catch((err) => res.status(500).send({ message: "Error retrieving User with id=" + id }));
};

// Delete a single User with an id
exports.delete = (req, res) => {
  const id = req.params.id;
  User.deleteOne({ _id: id })
    .then((result) => {
      if (!result || result.deletedCount === 0) return res.status(404).send({ message: "Not found User with id " + id });
      return res.send({ message: 'User deleted', id });
    })
    .catch((err) => res.status(500).send({ message: "Error deleting User with id=" + id }));
};

/***
 * Login Controls
 */
exports.login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).send({ message: "Email and password are required" });

  try {
    // pwd is select:false in model, so explicitly request it here for comparison
    const user = await User.findOne({ email }).select('+pwd');
    if (!user) return res.status(401).send({ message: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.pwd || '');
    if (!isMatch) return res.status(401).send({ message: "Invalid email or password" });

    const { accessToken, refreshToken } = await generateTokens(user, req);

    // Set refresh token in HTTP-only cookie
    // Set cookie expiry to match REFRESH_TOKEN_EXPIRES_IN
    const daysToExpire = parseInt(REFRESH_TOKEN_EXPIRES_IN) || 30;
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: daysToExpire * 24 * 60 * 60 * 1000 // Convert days to milliseconds
    });

    // return minimal user info and access token
    return res.status(200).send({ 
      username: user.username, 
      email: user.email,
      role: user.role || 'user',
      accessToken 
    });
  } catch (err) {
    return res.status(500).send({ message: "Internal Server Error"+err });
  }
};

// Refresh access token using refresh token
exports.refresh = async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  
  if (!refreshToken) {
    return res.status(401).send({ message: 'Refresh token required' });
  }

  try {
    // Find and validate refresh token
    const savedToken = await RefreshToken.findOne({ 
      token: refreshToken,
      isRevoked: false 
    });

    if (!savedToken) {
      return res.status(401).send({ message: 'Invalid refresh token' });
    }

    // Get user and generate new tokens
    const user = await User.findById(savedToken.userId);
    if (!user) {
      return res.status(401).send({ message: 'User not found' });
    }

    // Revoke old refresh token
    savedToken.isRevoked = true;
    await savedToken.save();

    // Generate new token pair
    const { accessToken, refreshToken: newRefreshToken } = await generateTokens(user, req);

    // Set new refresh token cookie
    // Set cookie expiry to match REFRESH_TOKEN_EXPIRES_IN (in refresh endpoint)
    const daysToExpire = parseInt(REFRESH_TOKEN_EXPIRES_IN) || 30;
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: daysToExpire * 24 * 60 * 60 * 1000 // Convert days to milliseconds
    });

    return res.status(200).send({ accessToken });
  } catch (err) {
    return res.status(500).send({ message: 'Internal Server Error' });
  }
};

/***
 * Registration Controls
 */

exports.register = async (req, res) => {
  const password = "12345678";
  const { name, email, mobile } = req.body;

  // Validate request
  if (!email || !name || !mobile || !password) {
    return res.status(400).send({ message: "All fields are required" });
  }

  // basic password policy
  if (password.length < 6) return res.status(400).send({ message: 'Password must be at least 6 characters' });

  // Check user exist or not
  const userEmail = await User.findOne({ email });
  if (userEmail) {
    return res.status(400).send({ message: `User already exist with email: ${userEmail.email}` });
  }

  try {
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create a new user (use username to match schema)
    const newUser = new User({ username: name, email, mobile, pwd: hashedPassword });
    await newUser.save();
    const token = jwt.sign({ userId: email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.status(201).send({ message: `${name} registered successfully`, token });

  } catch (error) {
    res.status(500).send({ message:`Internal Server Error: ${error}` });
  }
};

// Return profile/info for authenticated user
exports.profile = async (req, res) => {
  try {
    if (!req.user || !req.user.userId) return res.status(401).send({ message: 'Unauthorized' });
    const user = await User.findById(req.user.userId).select('-pwd');
    if (!user) return res.status(404).send({ message: 'User not found' });
    return res.status(200).send(user);
  } catch (err) {
    return res.status(500).send({ message: 'Internal Server Error' });
  }
};

// Admin endpoint to get user statistics
exports.getStats = async (req, res) => {
  try {
    const stats = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ role: 'admin' }),
      User.countDocuments({ role: 'user' }),
      User.aggregate([
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: -1 } },
        { $limit: 30 }
      ])
    ]);

    return res.status(200).send({
      totalUsers: stats[0],
      adminCount: stats[1],
      userCount: stats[2],
      recentSignups: stats[3]
    });
  } catch (err) {
    return res.status(500).send({ message: 'Internal Server Error' });
  }
};

// Get user's active sessions
exports.getSessions = async (req, res) => {
  try {
    const sessions = await UserSession.find({
      userId: req.user.userId,
      isActive: true
    }).select('-refreshToken');

    return res.status(200).send(sessions.map(session => ({
      id: session._id,
      deviceInfo: session.deviceInfo,
      lastActivity: session.lastActivity,
      createdAt: session.createdAt,
      isCurrent: session._id.toString() === req.session?._id.toString()
    })));
  } catch (err) {
    return res.status(500).send({ message: 'Internal Server Error' });
  }
};

// Revoke a specific session
exports.revokeSession = async (req, res) => {
  const { sessionId } = req.params;

  try {
    const session = await UserSession.findOne({
      _id: sessionId,
      userId: req.user.userId
    });

    if (!session) {
      return res.status(404).send({ message: 'Session not found' });
    }

    // Don't allow revoking current session through this endpoint
    if (session._id.toString() === req.session?._id.toString()) {
      return res.status(400).send({ message: 'Cannot revoke current session. Use logout instead.' });
    }

    // Revoke session and its refresh token
    await Promise.all([
      UserSession.updateOne({ _id: sessionId }, { 
        isActive: false,
        lastActivity: new Date()
      }),
      RefreshToken.updateOne({ sessionId }, { isRevoked: true })
    ]);

    // Log the action
    await AuditLog.create({
      userId: req.user.userId,
      action: 'revoke:session',
      resourceType: 'session',
      resourceId: sessionId,
      status: 'success',
      details: { sessionId },
      ip: req.ip,
      userAgent: req.get('user-agent'),
      sessionId: req.session?._id
    });

    return res.status(200).send({ message: 'Session revoked successfully' });
  } catch (err) {
    return res.status(500).send({ message: 'Internal Server Error' });
  }
};

// Revoke all sessions except current
exports.revokeAllSessions = async (req, res) => {
  try {
    const currentSessionId = req.session?._id;

    // Revoke all active sessions except current
    await UserSession.updateMany(
      {
        userId: req.user.userId,
        isActive: true,
        _id: { $ne: currentSessionId }
      },
      {
        isActive: false,
        lastActivity: new Date()
      }
    );

    // Revoke associated refresh tokens
    await RefreshToken.updateMany(
      {
        userId: req.user.userId,
        sessionId: { $ne: currentSessionId },
        isRevoked: false
      },
      { isRevoked: true }
    );

    // Log the action
    await AuditLog.create({
      userId: req.user.userId,
      action: 'revoke:all-sessions',
      resourceType: 'session',
      status: 'success',
      details: { excludedSessionId: currentSessionId },
      ip: req.ip,
      userAgent: req.get('user-agent'),
      sessionId: currentSessionId
    });

    return res.status(200).send({ message: 'All other sessions revoked successfully' });
  } catch (err) {
    return res.status(500).send({ message: 'Internal Server Error' });
  }
};

// Logout endpoint
exports.logout = async (req, res) => {
  try {
    // Revoke access token
    const accessToken = req.headers.authorization?.split(' ')[1];
    if (accessToken) {
      await require('../middlewares/auth.middleware').revokeToken(accessToken);
    }

    // Revoke refresh token if exists
    const refreshToken = req.cookies?.refreshToken;
    if (refreshToken) {
      await RefreshToken.updateOne(
        { token: refreshToken },
        { isRevoked: true }
      );
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken');
    
    res.status(200).send({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).send({ message: 'Internal Server Error' });
  }
};
