/**
 * Logger module for Git-Captain
 * Created as part of Git-Captain modernization - 7/10/25
 */

const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Ensure logs directory exists (use /tmp in Lambda)
const logsDir = process.env.AWS_LAMBDA_FUNCTION_NAME 
    ? '/tmp/logs' 
    : path.join(__dirname, '..', 'logs');

if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Create logger instance
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'git-captain' },
    transports: [
        // Write all logs to file
        new winston.transports.File({
            filename: path.join(logsDir, `git-captain-${new Date().toISOString().split('T')[0]}.log`),
            level: 'info'
        }),
        // Write errors to separate file
        new winston.transports.File({
            filename: path.join(logsDir, `git-captain-errors-${new Date().toISOString().split('T')[0]}.log`),
            level: 'error'
        })
    ]
});

// Add console transport for development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        )
    }));
}

module.exports = logger;
