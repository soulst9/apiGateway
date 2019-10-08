const blacklist = require('../../config/blacklist.json');
const { ClientError } = require('../error')
const url = require('url')

exports.security = (req, res, next) => {
    let verifyObject,
        pass = true,
        word;

    if (req.method === 'POST') {
        verifyObject = req.body;
    } else if (req.method === 'GET') {
        const factor = url.parse(req.url, true).pathname.split('/')
        const params = { ...factor };
        verifyObject =  Object.assign(req.query, params);
    }

    if (verifyObject) {
        const keyList = Object.keys(verifyObject);
        
        for (let key of keyList) {
            if (key === 'fileName' || key === 'img') {
                if (!check(verifyObject[key], "common", ["filedown"])) {                    
                    pass = false;
                    word = verifyObject[key];
                    break;
                }
            } else {
                if (!check(verifyObject[key], "forEditor", ["xss", "sqlinjection"])) {
                    pass = false;
                    word = verifyObject[key];
                    break;
                }
            }
            
        }
    }

    if (pass) {
        next();
    } else {
        const error = new ClientError('0000', null, word);
        console.error(error);
        res.status(error.statusCode).json({ message: error.message });
    }
}

function check (val, serviceName, Vulnerability) {
    if (typeof val !== "string") {
        return true;
    }

    if (typeof serviceName !== "string") {
        throw new Error("serviceName is not string!")
    }

    if (!Array.isArray(Vulnerability)) {
        throw new Error("VulnerabilityArray is not array!")
    }

    if (!blacklist[serviceName]) {
        throw new Error("serviceName : " + serviceName + " is not defined!")
    }

    for (let vul of Vulnerability) {
        if (!blacklist[serviceName][vul]) {
            throw new Error("Vulnerability : " + vul + " is not defined!")
        }

        const list = blacklist[serviceName][vul];
        for (let word of list) {
            if (val.indexOf(word) > -1) {
                return false;
            }
        }
    }

    return true;
}

