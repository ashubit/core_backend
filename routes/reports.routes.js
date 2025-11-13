const express = require('express');
const router = express.Router();
const AuditService = require('../services/audit.service');
const { hasRole } = require('../middlewares/roles.middleware');
const auth = require('../middlewares/auth.middleware');

// Activity Report
router.get('/activity', 
    auth.authenticate,
    hasRole(['admin']),
    async (req, res) => {
        try {
            const { start, end, userId } = req.query;
            const report = await AuditService.getActivityReport(
                start || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
                end || new Date(),
                userId
            );
            res.json(report);
        } catch (err) {
            res.status(500).json({ message: 'Error generating activity report' });
        }
    }
);

// Security Report
router.get('/security',
    auth.authenticate,
    hasRole(['admin']),
    async (req, res) => {
        try {
            const { start, end } = req.query;
            const report = await AuditService.getSecurityReport(
                start || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
                end || new Date()
            );
            res.json(report);
        } catch (err) {
            res.status(500).json({ message: 'Error generating security report' });
        }
    }
);

// Location Report
router.get('/location',
    auth.authenticate,
    hasRole(['admin']),
    async (req, res) => {
        try {
            const { start, end } = req.query;
            const report = await AuditService.getLocationReport(
                start || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
                end || new Date()
            );
            res.json(report);
        } catch (err) {
            res.status(500).json({ message: 'Error generating location report' });
        }
    }
);

// User Timeline
router.get('/user/:userId/timeline',
    auth.authenticate,
    hasRole(['admin']),
    async (req, res) => {
        try {
            const { userId } = req.params;
            const { limit } = req.query;
            const timeline = await AuditService.getUserActivityTimeline(userId, limit);
            res.json(timeline);
        } catch (err) {
            res.status(500).json({ message: 'Error retrieving user timeline' });
        }
    }
);

module.exports = router;