/**
 * api gate way 역할
 * 1. 인증(Authentication), 허가(Authorization)
 * 2. 라우터
 * 3. RB (로드밸런싱)
 * 4. 보안/파라미터 검증
 * 5. 로그 기록
 */

'use strict'

const http = require('http')
const express = require('express');
const bodyParser = require('body-parser')
const cors = require('cors');
const helmet = require('helmet');
const httpProxy = require('http-proxy');
const normalizePort = require('normalize-port')
const qs = require('querystring')
const config = require('./config/config')
const morgan = require('morgan')
const morganBody = require('morgan-body')
const rfs = require('rotating-file-stream')
const path = require('path')
const moment = require('moment')
const fs = require('fs')

const { security } = require('./libraries/middleware/security')
const { SystemError } = require('./libraries/error')
const { auth } = require('./libraries/middleware/auth')
const { createToken } = require('./libraries/helpers/token');
// const logger = require('./libraries/helpers/logger')


const DEF_CUR_ERR_FILENMAE = "today_err.log";
const DEF_CUR_OK_FILENMAE = "today_ok.log";
const suffix_ok = "ok";
const suffix_err = "err";

/**
 * http-proxy를 사용할 경우 일반 api내에서 bodyParse를 하면 서버 응답이 없는 오류가 발생되어
 * 아래의 http-proxy 이벤트를 사용하여 body에 필요한 데이터를 추가해야 함
 * resource api서버로 code_03에 대해 보낼 방안이 없어서 우선은 사용하지 않는 것으로 결정
 */

const apiProxy = httpProxy.createProxyServer();
apiProxy.on('proxyReq', function (proxyReq, req, res, options) {
    if (req.body) {
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type','application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);        
    }
})

apiProxy.on('proxyRes', function (proxyRes, req, res) {
    let chunks = [];
    proxyRes.on('data', function (data) {
        chunks.push(data);
    });
    proxyRes.on('end', function () {
        const filename = proxyRes.statusCode < 400 ? DEF_CUR_OK_FILENMAE : DEF_CUR_ERR_FILENMAE;
        const keyLen = Object.keys(req.body).length;
        if (keyLen) {
            const reqBody = JSON.stringify(req.body);
            fs.appendFileSync(path.join(__dirname, 'log/') + filename, 'Request Body: ' + reqBody + '\n');
        }
        const resBody = Buffer.concat(chunks).toString('utf8');
        fs.appendFileSync(path.join(__dirname, 'log/') + filename, 'Response Body: ' + resBody + '\n');
    });    
});

const app = express();
const port = normalizePort(process.env.PORT || '7000');
app.set('port', port);

/**
 * 로그 저장
 * 성공 로그와 에러 로그를 분리
 */
const errlogStream = rfs(errlogfilename, {
    interval: '1d',
    maxFiles: 2,
    path: path.join(__dirname, 'log')
})
const errorlog = morgan('combined', {
    stream: errlogStream,
    skip: function(req, res) { return res.statusCode < 400 }
})
app.use(errorlog);

const oklogStream = rfs(oklogfilename, {
    interval: '1d',
    maxFiles: 2,
    path: path.join(__dirname, 'log')
})
const successlog = morgan('combined', {
    stream: oklogStream,
    skip: function(req, res) { return res.statusCode >= 400 }
})
app.use(successlog);

/**
 * CORS 적용
 */
app.use(cors({
    "methods": "POST, GET, PUT, DELETE"
}));

/**
 * body parsing시 주의해야할 사항
 * 아래처럼 전체적으로 bodyParser를 사용할 경우 Post request를 Proxy하는 경우 응답 타임아웃 발생
 * 방지하기 위해서는 proxyReq 이벤트를 사용하던지 혹은 bodyParser가 필요한 path에 대해서만 아래처럼 예외처리
 * app.post('/signin', bodyParser.json(), function (req, res) {});
 */
app.use(bodyParser.json());
// morganBody(app, {
//     skip: function(req, res) { return res.statusCode >= 400 },
//     noColors: true,
//     logResponseBody: false,
//     stream: oklogStream
// })

// morganBody(app, {
//     skip: function(req, res) { return res.statusCode < 400 },
//     noColors: true,
//     logResponseBody: false,
//     stream: errlogStream
// })


/**
 * 보안
 */
app.use(helmet());

/**
 *  파라미터 값 검증
 */
app.use(security);

/**
 *  허가
 */
app.use(auth);

/**
 *  인증
 */
app.post('/signin', function (req, res) {

    const postData = JSON.stringify(req.body);
    const options = {
        host: config.resouceServer.ip,
        port: config.resouceServer.port,
        method: req.method,
        path: '/api/v1/users/signin',
        timeout: 10*1000,
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
        }
    }

    let resData = '';
    const proxy = http.request(options, (resRes) => {
        resRes.on('data', function(d) {
            resData += d;
        })        

        resRes.on('end', () => {
            const payload = JSON.parse(resData)
            if (resRes.statusCode === 200) {
                const token = createToken(payload, config.secret, config.expiredTokenTime);
                if (payload.userlv === '9') {
                    res.json({ accessToken: token, message: "Your password has expired. Issued tokens are only available for password change purposes" });    
                } else {
                    res.json({ accessToken: token });    
                }
            } else {
                res.status(resRes.statusCode).json(payload);
            }
        })
    }); 

    proxy.write(postData);
    proxy.end();
})

app.put('/reset/:reset_token', function (req, res) {

    const postData = JSON.stringify(req.body);
    const options = {
        host: config.resouceServer.ip,
        port: config.resouceServer.port,
        method: req.method,
        path: '/api/v1/users/reset/' + req.params.reset_token,
        timeout: 10*1000,
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
        }
    }

    let resData = '';
    const proxy = http.request(options, (resRes) => {
        resRes.on('data', function(d) {
            resData += d;
        })        

        resRes.on('end', () => {
            const payload = JSON.parse(resData)
            res.status(resRes.statusCode).json(payload);
        })
    }); 

    proxy.write(postData);
    proxy.end();
})

app.all('/api/*', function (req, res) {
    console.log('redirectring to setup server', req.method, req.url);
    apiProxy.web(req, res, { target: { host: config.resouceServer.ip, port: config.resouceServer.port } });
});

// app.all(/^(?!api).*$/, function (req, res, next) {
//     console.log('redirectring to dashboard server', req.method, req.url);
//     apiProxy.web(req, res, { target: { host: config.dashboardServer.ip, port: config.dashboardServer.port } });
// })

app.use(function(err, req, res, next) {
    console.error('error handler', err.stack);
    const error = new SystemError("9999");
    res.status(error.statusCode).json({ message: error.message });
});

function errlogfilename(time, index) {
	if (!time) return DEF_CUR_ERR_FILENMAE;
    return moment().format("YYYYMMDD") + '-err.log';
}

function oklogfilename(time, index) {
	if (!time) return DEF_CUR_OK_FILENMAE;
    return moment().format("YYYYMMDD") + '-ok.log';
}

app.listen(port, () => {
    // logger.info(`listening on ${port}`);
});

module.exports = app;
