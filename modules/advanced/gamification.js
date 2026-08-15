/**
 * Gamification System
 * Achievements, leaderboards, and security scores
 */

const crypto = require('crypto');

class GamificationEngine {
    constructor(db) {
        this.db = db;
        this.achievements = this.initializeAchievements();
        this.challenges = this.initializeChallenges();
    }

    /**
     * Initialize achievement definitions
     */
    initializeAchievements() {
        return {
            // Security achievements
            first_scan: {
                id: 'first_scan',
                name: 'Security Scout',
                description: 'Complete your first security scan',
                icon: '🔍',
                points: 10,
                category: 'security',
                tier: 'bronze'
            },
            no_secrets: {
                id: 'no_secrets',
                name: 'Secret Keeper',
                description: 'Create a script with zero hardcoded secrets',
                icon: '🔐',
                points: 50,
                category: 'security',
                tier: 'gold'
            },
            honeypot_triggered: {
                id: 'honeypot_triggered',
                name: 'Trap Master',
                description: 'Successfully detect an attacker with honeypot',
                icon: '🍯',
                points: 100,
                category: 'security',
                tier: 'platinum'
            },

            // Operational achievements
            first_deployment: {
                id: 'first_deployment',
                name: 'Deployer',
                description: 'Deploy your first script',
                icon: '🚀',
                points: 10,
                category: 'operations',
                tier: 'bronze'
            },
            zero_downtime: {
                id: 'zero_downtime',
                name: 'Uptime Champion',
                description: '30 days with 100% fleet uptime',
                icon: '⬆️',
                points: 200,
                category: 'operations',
                tier: 'platinum'
            },
            fleet_master: {
                id: 'fleet_master',
                name: 'Fleet Commander',
                description: 'Manage 100+ hosts',
                icon: '👑',
                points: 150,
                category: 'operations',
                tier: 'gold'
            },

            // Efficiency achievements
            speed_demon: {
                id: 'speed_demon',
                name: 'Speed Demon',
                description: 'Optimize a script to run in <1 second',
                icon: '⚡',
                points: 75,
                category: 'efficiency',
                tier: 'gold'
            },
            automation_king: {
                id: 'automation_king',
                name: 'Automation King',
                description: 'Create 50+ automated workflows',
                icon: '🤖',
                points: 100,
                category: 'efficiency',
                tier: 'gold'
            },

            // Chaos achievements
            chaos_survivor: {
                id: 'chaos_survivor',
                name: 'Chaos Survivor',
                description: 'System withstood chaos experiment with 95%+ success',
                icon: '💥',
                points: 125,
                category: 'resilience',
                tier: 'platinum'
            },
            failure_hunter: {
                id: 'failure_hunter',
                name: 'Failure Hunter',
                description: 'Find and fix 10 issues via predictive maintenance',
                icon: '🔮',
                points: 150,
                category: 'resilience',
                tier: 'gold'
            },

            // Collaboration achievements
            team_player: {
                id: 'team_player',
                name: 'Team Player',
                description: 'Approve 50 peer commands',
                icon: '🤝',
                points: 50,
                category: 'collaboration',
                tier: 'silver'
            },
            mentor: {
                id: 'mentor',
                name: 'Mentor',
                description: 'Share 10 scripts with teammates',
                icon: '🎓',
                points: 75,
                category: 'collaboration',
                tier: 'gold'
            },

            // Special achievements
            perfect_week: {
                id: 'perfect_week',
                name: 'Perfect Week',
                description: '7 days with zero incidents',
                icon: '✨',
                points: 200,
                category: 'special',
                tier: 'diamond'
            },
            bug_bounty: {
                id: 'bug_bounty',
                name: 'Bug Hunter',
                description: 'Report a critical security issue',
                icon: '🐛',
                points: 500,
                category: 'special',
                tier: 'diamond'
            }
        };
    }

    /**
     * Initialize weekly/monthly challenges
     */
    initializeChallenges() {
        return [
            {
                id: 'weekly_scans',
                name: 'Weekly Security Sweep',
                description: 'Run security scans on all hosts',
                duration: '7d',
                reward_points: 100,
                progress_metric: 'hosts_scanned',
                target: 'all'
            },
            {
                id: 'incident_free_week',
                name: 'Incident-Free Week',
                description: 'Maintain zero critical incidents for 7 days',
                duration: '7d',
                reward_points: 150,
                progress_metric: 'incident_count',
                target: 0
            },
            {
                id: 'optimization_month',
                name: 'Optimization Month',
                description: 'Reduce average script execution time by 25%',
                duration: '30d',
                reward_points: 250,
                progress_metric: 'avg_execution_time_improvement',
                target: 25
            }
        ];
    }

    /**
     * Award achievement to user
     */
    async awardAchievement(userId, achievementId, context = {}) {
        const achievement = this.achievements[achievementId];

        if (!achievement) {
            throw new Error(`Unknown achievement: ${achievementId}`);
        }

        // Check if already awarded
        const existing = await this.db.query(`
            SELECT * FROM user_achievements
            WHERE user_id = $1 AND achievement_id = $2
        `, [userId, achievementId]);

        if (existing.rows.length > 0) {
            return {
                already_awarded: true,
                achievement: achievement
            };
        }

        // Award achievement
        await this.db.query(`
            INSERT INTO user_achievements (
                user_id, achievement_id, awarded_at, context
            ) VALUES ($1, $2, $3, $4)
        `, [userId, achievementId, new Date(), JSON.stringify(context)]);

        // Add points to user
        await this.db.query(`
            UPDATE users
            SET total_points = total_points + $2,
                achievements_count = achievements_count + 1
            WHERE user_id = $1
        `, [userId, achievement.points]);

        console.log(`🏆 Achievement unlocked: ${userId} earned "${achievement.name}" (+${achievement.points} pts)`);

        return {
            achievement_id: achievementId,
            name: achievement.name,
            description: achievement.description,
            points: achievement.points,
            tier: achievement.tier,
            icon: achievement.icon,
            newly_awarded: true
        };
    }

    /**
     * Check and award automatic achievements
     */
    async checkAutomaticAchievements(userId, event) {
        const awarded = [];

        switch (event.type) {
            case 'script_deployed':
                // First deployment
                const deploymentCount = await this.getUserStat(userId, 'deployments');
                if (deploymentCount === 1) {
                    const result = await this.awardAchievement(userId, 'first_deployment', event);
                    if (result.newly_awarded) awarded.push(result);
                }
                break;

            case 'security_scan_completed':
                // First scan
                const scanCount = await this.getUserStat(userId, 'scans');
                if (scanCount === 1) {
                    const result = await this.awardAchievement(userId, 'first_scan', event);
                    if (result.newly_awarded) awarded.push(result);
                }

                // No secrets achievement
                if (event.secrets_found === 0) {
                    const result = await this.awardAchievement(userId, 'no_secrets', event);
                    if (result.newly_awarded) awarded.push(result);
                }
                break;

            case 'honeypot_triggered':
                const result = await this.awardAchievement(userId, 'honeypot_triggered', event);
                if (result.newly_awarded) awarded.push(result);
                break;

            case 'uptime_milestone':
                if (event.days >= 30 && event.uptime_percent === 100) {
                    const result = await this.awardAchievement(userId, 'zero_downtime', event);
                    if (result.newly_awarded) awarded.push(result);
                }
                break;

            case 'fleet_size_milestone':
                if (event.host_count >= 100) {
                    const result = await this.awardAchievement(userId, 'fleet_master', event);
                    if (result.newly_awarded) awarded.push(result);
                }
                break;
        }

        return awarded;
    }

    /**
     * Get leaderboard
     */
    async getLeaderboard(options = {}) {
        const timeframe = options.timeframe || 'all_time'; // 'all_time', 'monthly', 'weekly'
        const category = options.category; // Filter by achievement category
        const limit = options.limit || 100;

        let query = `
            SELECT
                u.user_id,
                u.username,
                u.total_points,
                u.achievements_count,
                u.rank,
                u.avatar_url
            FROM users u
        `;

        const conditions = [];
        const params = [];

        if (timeframe === 'monthly') {
            // Points earned this month
            query = `
                SELECT
                    u.user_id,
                    u.username,
                    SUM(a.points) as total_points,
                    COUNT(*) as achievements_count,
                    u.avatar_url
                FROM users u
                JOIN user_achievements ua ON u.user_id = ua.user_id
                JOIN achievements a ON ua.achievement_id = a.achievement_id
                WHERE EXTRACT(MONTH FROM ua.awarded_at) = EXTRACT(MONTH FROM CURRENT_DATE)
                GROUP BY u.user_id, u.username, u.avatar_url
            `;
        } else if (timeframe === 'weekly') {
            query = `
                SELECT
                    u.user_id,
                    u.username,
                    SUM(a.points) as total_points,
                    COUNT(*) as achievements_count,
                    u.avatar_url
                FROM users u
                JOIN user_achievements ua ON u.user_id = ua.user_id
                JOIN achievements a ON ua.achievement_id = a.achievement_id
                WHERE ua.awarded_at >= DATE_TRUNC('week', CURRENT_DATE)
                GROUP BY u.user_id, u.username, u.avatar_url
            `;
        }

        query += ` ORDER BY total_points DESC, achievements_count DESC LIMIT ${limit}`;

        const result = await this.db.query(query, params);

        // Add rank numbers
        const leaderboard = result.rows.map((row, index) => ({
            rank: index + 1,
            ...row,
            badge: this.getRankBadge(row.total_points)
        }));

        return {
            timeframe: timeframe,
            leaderboard: leaderboard,
            total_players: leaderboard.length
        };
    }

    /**
     * Get rank badge based on points
     */
    getRankBadge(points) {
        if (points >= 10000) return { name: 'Legend', icon: '👑', color: '#FFD700' };
        if (points >= 5000) return { name: 'Master', icon: '💎', color: '#00CED1' };
        if (points >= 2000) return { name: 'Expert', icon: '🌟', color: '#9370DB' };
        if (points >= 1000) return { name: 'Pro', icon: '⭐', color: '#FFA500' };
        if (points >= 500) return { name: 'Advanced', icon: '🔷', color: '#4169E1' };
        if (points >= 100) return { name: 'Intermediate', icon: '🔹', color: '#32CD32' };
        return { name: 'Novice', icon: '🌱', color: '#90EE90' };
    }

    /**
     * Get user stats and progress
     */
    async getUserProgress(userId) {
        const result = await this.db.query(`
            SELECT * FROM users WHERE user_id = $1
        `, [userId]);

        if (result.rows.length === 0) {
            return null;
        }

        const user = result.rows[0];

        // Get achievements
        const achievementsResult = await this.db.query(`
            SELECT ua.*, a.*
            FROM user_achievements ua
            JOIN achievements a ON ua.achievement_id = a.achievement_id
            WHERE ua.user_id = $1
            ORDER BY ua.awarded_at DESC
        `, [userId]);

        const achievements = achievementsResult.rows;

        // Get active challenges
        const activeChallenges = await this.getActiveChallenges(userId);

        // Calculate progress to next rank
        const currentBadge = this.getRankBadge(user.total_points);
        const rankThresholds = [0, 100, 500, 1000, 2000, 5000, 10000];
        const nextThreshold = rankThresholds.find(t => t > user.total_points) || 10000;
        const prevThreshold = rankThresholds.reverse().find(t => t <= user.total_points) || 0;

        const progressToNextRank = ((user.total_points - prevThreshold) / (nextThreshold - prevThreshold) * 100);

        return {
            user_id: userId,
            username: user.username,
            total_points: user.total_points,
            achievements_count: user.achievements_count,
            current_badge: currentBadge,
            progress_to_next_rank: progressToNextRank.toFixed(1) + '%',
            points_needed: nextThreshold - user.total_points,
            achievements: achievements,
            active_challenges: activeChallenges,
            recent_activity: await this.getRecentActivity(userId)
        };
    }

    /**
     * Get active challenges for user
     */
    async getActiveChallenges(userId) {
        return this.challenges.map(challenge => ({
            ...challenge,
            progress: 0, // Would calculate real progress
            completed: false
        }));
    }

    /**
     * Get recent activity
     */
    async getRecentActivity(userId) {
        const result = await this.db.query(`
            SELECT
                'achievement' as type,
                achievement_id as id,
                awarded_at as timestamp
            FROM user_achievements
            WHERE user_id = $1
            ORDER BY awarded_at DESC
            LIMIT 10
        `, [userId]);

        return result.rows;
    }

    /**
     * Get user stat
     */
    async getUserStat(userId, stat) {
        const result = await this.db.query(`
            SELECT ${stat} FROM user_stats WHERE user_id = $1
        `, [userId]);

        return result.rows[0]?.[stat] || 0;
    }

    /**
     * Calculate security score
     */
    async calculateSecurityScore(userId) {
        const factors = {
            secrets_scanned: await this.getUserStat(userId, 'secrets_scans'),
            honeypots_deployed: await this.getUserStat(userId, 'honeypots'),
            incidents_resolved: await this.getUserStat(userId, 'incidents_resolved'),
            zero_day_patches: await this.getUserStat(userId, 'security_patches'),
            failed_auth_rate: await this.getUserStat(userId, 'failed_auth_rate')
        };

        let score = 50; // Base score

        // Positive factors
        score += Math.min(factors.secrets_scanned * 2, 20);
        score += Math.min(factors.honeypots_deployed * 5, 15);
        score += Math.min(factors.incidents_resolved, 10);
        score += Math.min(factors.zero_day_patches * 3, 15);

        // Negative factors
        score -= Math.min(factors.failed_auth_rate * 10, 20);

        return {
            score: Math.max(0, Math.min(100, score)),
            grade: this.getSecurityGrade(score),
            factors: factors,
            recommendations: this.getSecurityRecommendations(factors)
        };
    }

    getSecurityGrade(score) {
        if (score >= 90) return 'A+';
        if (score >= 80) return 'A';
        if (score >= 70) return 'B';
        if (score >= 60) return 'C';
        if (score >= 50) return 'D';
        return 'F';
    }

    getSecurityRecommendations(factors) {
        const recommendations = [];

        if (factors.secrets_scanned < 10) {
            recommendations.push('Run more secrets scans to improve security');
        }

        if (factors.honeypots_deployed === 0) {
            recommendations.push('Deploy honeypots to detect intrusions');
        }

        if (factors.failed_auth_rate > 0.05) {
            recommendations.push('High failed auth rate - enable rate limiting');
        }

        return recommendations;
    }

    /**
     * Award daily login bonus
     */
    async awardDailyBonus(userId) {
        const lastLogin = await this.getUserStat(userId, 'last_login_date');
        const today = new Date().toDateString();

        if (lastLogin === today) {
            return {
                already_claimed: true,
                message: 'Daily bonus already claimed today'
            };
        }

        // Award 10 points for daily login
        await this.db.query(`
            UPDATE users
            SET total_points = total_points + 10,
                last_login_date = $2
            WHERE user_id = $1
        `, [userId, today]);

        // Check for streak
        const streak = await this.calculateLoginStreak(userId);

        // Bonus for 7-day streak
        if (streak === 7) {
            await this.awardAchievement(userId, 'perfect_week');
        }

        return {
            points_awarded: 10,
            message: 'Daily login bonus claimed!',
            streak: streak
        };
    }

    async calculateLoginStreak(userId) {
        // Calculate consecutive login days
        return 1; // Simplified
    }
}

module.exports = GamificationEngine;
