const express = require('express');
const router = express.Router();
const AnomalyDetectionService = require('../services/anomaly.service');
const { authenticate } = require('../middlewares/auth.middleware');
const { hasRole } = require('../middlewares/roles.middleware');

// Get security anomalies for a user
router.get('/user/:userId/anomalies',
    authenticate,
    hasRole(['admin']),
    async (req, res) => {
        try {
            const anomalies = await AnomalyDetectionService.detectBehaviorAnomalies(req.params.userId);
            res.json(anomalies);
        } catch (err) {
            res.status(500).json({ message: 'Error detecting anomalies' });
        }
    }
);

// Get user risk score
router.get('/user/:userId/risk-score',
    authenticate,
    hasRole(['admin']),
    async (req, res) => {
        try {
            const score = await AnomalyDetectionService.calculateUserRiskScore(req.params.userId);
            res.json(score);
        } catch (err) {
            res.status(500).json({ message: 'Error calculating risk score' });
        }
    }
);

// Get current user's security status
router.get('/my-security-status',
    authenticate,
    async (req, res) => {
        try {
            const [anomalies, riskScore] = await Promise.all([
                AnomalyDetectionService.detectBehaviorAnomalies(req.user.userId),
                AnomalyDetectionService.calculateUserRiskScore(req.user.userId)
            ]);

            res.json({
                anomalies,
                riskScore,
                requiresVerification: req.session?.requiresSecurityVerification || false
            });
        } catch (err) {
            res.status(500).json({ message: 'Error retrieving security status' });
        }
    }
);

module.exports = router;