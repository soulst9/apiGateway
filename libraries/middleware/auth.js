const { decodeToken } = require('../helpers/token');
const { ClientError } = require('../error');
const url = require('url');
const authorization = require('../../config/authorization');

exports.auth = async (req, res, next) => {

    const free = ["/signin", "/reset"];

    let url_parse = url.parse(req.url, true);
    let pathname = url_parse.pathname;

    let include = false;
    free.forEach(key => {
        if (pathname.indexOf(key) > -1) {
            include = true;
        }
    })
    
    if (include) {
        next();
    } else {
        // const token = req.body.token || req.query.token || req.headers['x-access-token'];
        const token = req.headers['x-access-token'];
        console.log('token', token)
        if (token) {
            decodeToken(token, (err, decoded) => {
                if (err) {
                    const error = new ClientError("0001", 401);
                    return res.status(error.statusCode).json({ message: error.message });
                } else {
                    if (isAuthorization(decoded.userlv, req.method, pathname)) {
                        next();
                    } else {
                        const error = new ClientError("0003", 403);
                        return res.status(error.statusCode).send({ error: error.message })
                    }
                }
            });
        } else {
            const error = new ClientError("0002", 401);
            return res.status(error.statusCode).send({ error: error.message });
        }
    }
}


/**
 * pathname 구조
 * /prefix/version/collection(component)/document/controller
 * /api/v1/users/iwsys/register
 */
function isAuthorization (lv, method, pathname) {
    if (!lv) {
        return false;
    }
    
    if (lv === '1') {
        return true;
    }

    const parts = pathname.split('/');
    const prefix = parts[1];
    const controller = parts[5];

    if (lv === '2' && prefix === "api") {
        return false;
    }

    const collection = parts[3];
    const componentAPIs = authorization[lv][collection];
    if (!componentAPIs) {
        return false;
    }
    
    let result = false;
    for (let item of componentAPIs) {
        if (item.method === method && item.controller === controller) {
            return true;
        }
    }

    return false;    
}