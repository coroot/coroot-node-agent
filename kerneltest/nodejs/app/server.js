// Usage: node server.js <tls port> [<plain port>]
// TLS requests get 404 and plain requests get 200, so the status tells them apart in the metrics.
const fs = require('fs'), https = require('https'), http = require('http');

const [tlsPort, plainPort] = process.argv.slice(2);
const tls = {key: fs.readFileSync('/nodetest/key.pem'), cert: fs.readFileSync('/nodetest/cert.pem')};
const respond = (status) => (req, res) => {
    res.statusCode = status;
    res.end();
};
https.createServer(tls, respond(404)).listen(tlsPort, '127.0.0.1').keepAliveTimeout = 3600000;
if (plainPort) {
    http.createServer(respond(200)).listen(plainPort, '127.0.0.1').keepAliveTimeout = 3600000;
}
