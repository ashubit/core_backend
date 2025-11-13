const UserSession = require('../models/userSession.model');
const AuditLog = require('../models/auditLog.model');
const geoip = require('geoip-lite');

class AnomalyDetectionService {
    // Check for suspicious login patterns
    async detectSuspiciousLogins(userId, ip, location) {
        try {
            // Get user's recent login history
            const recentLogins = await AuditLog.find({
                userId,
                action: 'login',
                createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
            }).sort({ createdAt: -1 });

            const anomalies = [];

            // Check for rapid location changes
            if (recentLogins.length > 0) {
                for (let i = 1; i < recentLogins.length; i++) {
                    const timeDiff = recentLogins[i-1].createdAt - recentLogins[i].createdAt;
                    const prevLocation = recentLogins[i-1].location;
                    const currLocation = recentLogins[i].location;

                    // If locations are different and time difference is too short
                    if (prevLocation && currLocation && 
                        prevLocation.country !== currLocation.country && 
                        timeDiff < 3600000) { // Less than 1 hour
                        anomalies.push({
                            type: 'rapid_location_change',
                            severity: 'high',
                            details: {
                                prevLocation,
                                currLocation,
                                timeDiff
                            }
                        });
                    }
                }
            }

            // Check for unusual access times
            const hour = new Date().getHours();
            const unusualHours = await this.isUnusualAccessTime(userId, hour);
            if (unusualHours) {
                anomalies.push({
                    type: 'unusual_access_time',
                    severity: 'medium',
                    details: { hour }
                });
            }

            // Check for multiple failed attempts
            const failedAttempts = await AuditLog.countDocuments({
                userId,
                action: 'login',
                status: 'failed',
                createdAt: { $gte: new Date(Date.now() - 1 * 60 * 60 * 1000) } // Last hour
            });

            if (failedAttempts > 5) {
                anomalies.push({
                    type: 'multiple_failed_attempts',
                    severity: 'high',
                    details: { failedAttempts }
                });
            }

            // Check for concurrent sessions from different locations
            const activeSessions = await UserSession.find({
                userId,
                isActive: true
            });

            if (activeSessions.length > 1) {
                const locations = new Set(activeSessions.map(s => s.deviceInfo?.lastLocation?.country).filter(Boolean));
                if (locations.size > 1) {
                    anomalies.push({
                        type: 'concurrent_sessions_different_locations',
                        severity: 'high',
                        details: {
                            sessionCount: activeSessions.length,
                            locations: Array.from(locations)
                        }
                    });
                }
            }

            return anomalies;
        } catch (error) {
            console.error('Error in anomaly detection:', error);
            return [];
        }
    }

    // Check if the access time is unusual for the user
    async isUnusualAccessTime(userId, currentHour) {
        // Get user's typical access patterns over the last 30 days
        const accessPatterns = await AuditLog.aggregate([
            {
                $match: {
                    userId,
                    createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
                }
            },
            {
                $group: {
                    _id: { $hour: "$createdAt" },
                    count: { $sum: 1 }
                }
            }
        ]);

        // Create a map of hour -> frequency
        const hourFrequency = new Map(accessPatterns.map(p => [p._id, p.count]));
        
        // If this hour has less than 5% of total activity, consider it unusual
        const totalActivity = Array.from(hourFrequency.values()).reduce((a, b) => a + b, 0);
        const currentHourActivity = hourFrequency.get(currentHour) || 0;
        
        return (currentHourActivity / totalActivity) < 0.05;
    }

    // Detect anomalies in user behavior patterns
    async detectBehaviorAnomalies(userId) {
        const anomalies = [];
        
        // Analyze recent activity patterns
        const recentActivity = await AuditLog.find({
            userId,
            createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        }).sort({ createdAt: -1 });

        // Check for sudden changes in activity volume
        const hourlyActivityCount = new Map();
        recentActivity.forEach(activity => {
            const hour = activity.createdAt.getHours();
            hourlyActivityCount.set(hour, (hourlyActivityCount.get(hour) || 0) + 1);
        });

        // Calculate average and standard deviation of hourly activity
        const values = Array.from(hourlyActivityCount.values());
        const avg = values.reduce((a, b) => a + b, 0) / values.length;
        const stdDev = Math.sqrt(values.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / values.length);

        // Check current hour's activity
        const currentHour = new Date().getHours();
        const currentActivity = hourlyActivityCount.get(currentHour) || 0;

        if (Math.abs(currentActivity - avg) > 2 * stdDev) {
            anomalies.push({
                type: 'unusual_activity_volume',
                severity: 'medium',
                details: {
                    current: currentActivity,
                    average: avg,
                    standardDeviation: stdDev
                }
            });
        }

        return anomalies;
    }

    // Get user's risk score based on recent activity
    async calculateUserRiskScore(userId) {
        const score = {
            base: 100, // Start with base score of 100
            factors: [],
            finalScore: 100
        };

        // Check failed login attempts (last 24 hours)
        const failedLogins = await AuditLog.countDocuments({
            userId,
            action: 'login',
            status: 'failed',
            createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });

        if (failedLogins > 0) {
            score.factors.push({
                name: 'failed_logins',
                impact: -10 * failedLogins,
                count: failedLogins
            });
        }

        // Check location changes (last 24 hours)
        const uniqueLocations = await UserSession.distinct('deviceInfo.lastLocation.country', {
            userId,
            createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });

        if (uniqueLocations.length > 1) {
            score.factors.push({
                name: 'multiple_locations',
                impact: -15 * (uniqueLocations.length - 1),
                count: uniqueLocations.length
            });
        }

        // Calculate final score
        score.finalScore = score.base + score.factors.reduce((total, factor) => total + factor.impact, 0);
        score.finalScore = Math.max(0, Math.min(100, score.finalScore)); // Clamp between 0 and 100

        return score;
    }
}

module.exports = new AnomalyDetectionService();