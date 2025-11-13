const express = require('express');
const router = express.Router();
const VisualizationService = require('../services/visualization.service');
const { authenticate } = require('../middlewares/auth.middleware');
const { hasRole } = require('../middlewares/roles.middleware');

// Get activity heatmap data
router.get('/heatmap',
    authenticate,
    hasRole(['admin']),
    async (req, res) => {
        try {
            const { start, end, userId } = req.query;
            const data = await VisualizationService.getActivityHeatmap(
                start || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
                end || new Date(),
                userId
            );
            res.json(data);
        } catch (err) {
            res.status(500).json({ message: 'Error generating heatmap data' });
        }
    }
);

// Get geospatial activity data
router.get('/geo-activity',
    authenticate,
    hasRole(['admin']),
    async (req, res) => {
        try {
            const { start, end } = req.query;
            const data = await VisualizationService.getGeoActivityData(
                start || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
                end || new Date()
            );
            res.json(data);
        } catch (err) {
            res.status(500).json({ message: 'Error generating geo-activity data' });
        }
    }
);

// Get session statistics
router.get('/session-stats',
    authenticate,
    hasRole(['admin']),
    async (req, res) => {
        try {
            const { start, end } = req.query;
            const data = await VisualizationService.getSessionStats(
                start || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
                end || new Date()
            );
            res.json(data);
        } catch (err) {
            res.status(500).json({ message: 'Error generating session statistics' });
        }
    }
);

// Get device distribution
router.get('/device-distribution',
    authenticate,
    hasRole(['admin']),
    async (req, res) => {
        try {
            const { start, end } = req.query;
            const data = await VisualizationService.getDeviceDistribution(
                start || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
                end || new Date()
            );
            res.json(data);
        } catch (err) {
            res.status(500).json({ message: 'Error generating device distribution data' });
        }
    }
);

// Get active user trends
router.get('/user-trends',
    authenticate,
    hasRole(['admin']),
    async (req, res) => {
        try {
            const { days } = req.query;
            const data = await VisualizationService.getActiveUserTrends(
                parseInt(days) || 30
            );
            res.json(data);
        } catch (err) {
            res.status(500).json({ message: 'Error generating user trends data' });
        }
    }
);

module.exports = router;