const jwt = require('jsonwebtoken');
const TokenBlacklist = require('../models/tokenBlacklist.model');

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_production';

exports.authenticate = async (req, res, next) => {

  const authHeader = req.headers.authorization || req.headers.Authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization token missing or invalid' });
  }

  const token = authHeader.split(' ')[1];
  try {
    // Check if token is blacklisted
    const blacklisted = await TokenBlacklist.findOne({ token });
    if (blacklisted) {
      return res.status(401).json({ message: 'Token has been revoked' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    console.log(decoded);
    
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Logout helper - add token to blacklist
exports.revokeToken = async (token) => {
  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.exp) {
      throw new Error('Invalid token');
    }

    // Store in blacklist until original expiration
    const expiresAt = new Date(decoded.exp * 1000);
    await TokenBlacklist.create({ token, expiresAt });
    return true;
  } catch (error) {
    console.error('Token revocation failed:', error);
    return false;
  }
};
