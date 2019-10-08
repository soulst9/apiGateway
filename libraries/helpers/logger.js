const winston = require('winston')

const { combine, timestamp, label, printf } = winston.format;
const format = printf(({ level, message, label, timestamp }) => {
    return `${timestamp} [${label}] ${level}: ${message}`;
})

const options = {
    file: {
        level: 'info',
        filename: `/log/test.log`,
        handleExceptions: true,
        json: false,
        colorize: false,
        maxFile: 10,
        format: combine(
            label({ label: 'api gateway' }),
            timestamp(),
            format
        )
    },
    console: {
        level: 'debug',
        handleExceptions: true,
        json: false,
        colorize: true,
        format: combine(
            label({ label: 'api gateway' }),
            timestamp(),
            format
        )
    }
}

let logger = new winston.createLogger({
    transports: [
        new winston.transports.File(options.file)
    ],
    exitOnError: false
})

logger.stream = {
    write: function(message, encoding) {
        logger.info(message)
    },
}

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console(options.console))
}

module.exports = logger;