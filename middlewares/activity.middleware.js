const geoip = require('geoip-lite');
const UserSession = require('../models/userSession.model');
const AnomalyDetectionService = require('../services/anomaly.service');
const useragent = require('useragent');

exports.activityTracker = async (req, res, next) => {
    // Skip tracking for static assets or non-auth routes
    if (!req.user || req.path.startsWith('/public')) {
        return next();
    }

    try {
        // Get IP address
        const ip = req.ip || 
                  req.connection.remoteAddress || 
                  req.headers['x-forwarded-for']?.split(',')[0];

        // Get geo location
        const geo = geoip.lookup(ip);
        const location = geo ? {
            country: geo.country,
            region: geo.region,
            city: geo.city,
            ll: geo.ll // latitude/longitude
        } : null;

        // Parse User Agent for device info
        const agent = useragent.parse(req.headers['user-agent']);
        const deviceInfo = {
            browser: agent.family,
            browserVersion: agent.toVersion(),
            os: agent.os.toString(),
            device: agent.device.toString(),
            isMobile: agent.device.family !== 'Other',
            screenResolution: req.headers['sec-ch-viewport-width'] 
                ? `${req.headers['sec-ch-viewport-width']}x${req.headers['sec-ch-viewport-height']}`
                : undefined,
            timezone: req.headers['sec-ch-timezone'],
            languages: req.headers['accept-language'],
            platform: req.headers['sec-ch-ua-platform'],
            lastIp: ip,
            lastLocation: location
        };

        // Check for anomalies
        const anomalies = await AnomalyDetectionService.detectSuspiciousLogins(
            req.user.userId,
            ip,
            location
        );

        // If high severity anomalies are detected, you might want to take action
        const highSeverityAnomalies = anomalies.filter(a => a.severity === 'high');
        if (highSeverityAnomalies.length > 0) {
            // Add anomaly info to the request for later use
            req.securityAnomalies = highSeverityAnomalies;
            
            // Optionally force re-authentication or add security challenges
            if (req.path !== '/api/v1/auth/verify-security-challenge') {
                req.session.requiresSecurityVerification = true;
            }
        }

        // Calculate user risk score
        const riskScore = await AnomalyDetectionService.calculateUserRiskScore(req.user.userId);

        // Update session if exists
        if (req.session?._id) {
            await UserSession.findByIdAndUpdate(req.session._id, {
                lastActivity: new Date(),
                lastPath: req.path,
                lastMethod: req.method,
                deviceInfo,
                securityScore: riskScore.finalScore,
                anomalies: anomalies.length > 0 ? anomalies : undefined
            }, { new: true });
        }

        // Add security info to request for audit logging
        req.geoLocation = location;
        req.deviceInfo = deviceInfo;
        req.securityScore = riskScore.finalScore;
        
        next();
    } catch (error) {
        console.error('Activity tracking error:', error);
        next(); // Continue even if tracking fails
    }
};