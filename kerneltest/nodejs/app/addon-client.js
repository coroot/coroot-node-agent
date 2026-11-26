// Usage: node addon-client.js <tls port> <plain port> <count file>
// The addon makes TLS connections with their own socket I/O and sends two requests over each one, as client.js does:
// the first write of a connection is traced before the agent has seen any read on it. In the same tick the script
// also writes a plain HTTP request through Node.js, so a TLS request bound to the wrong socket shows up under the
// plain one. It writes the number of completed TLS requests to the count file. SIGUSR2 pauses it and SIGUSR1
// resumes it.
const fs = require('fs'), net = require('net');
const addon = require('/nodetest/addon.node');

const [tlsPort, plainPort, countFile] = process.argv.slice(2);
const req = 'GET /plain HTTP/1.1\r\nHost: nodetest\r\nConnection: keep-alive\r\n\r\n';

let done = 0, n = 0, timer, plain;
const tick = () => {
    if (n++ % 2 === 0) {
        addon.close();
        if (!addon.open('127.0.0.1', tlsPort)) {
            console.log('the addon could not connect');
            return;
        }
    }
    if (addon.request().startsWith('HTTP/1.1 404')) {
        fs.writeFileSync(countFile, String(++done));
    }
    plain.write(req);
};
// the servers can start after the client
const start = () => {
    let connected = false;
    plain = net.connect(plainPort, '127.0.0.1');
    plain.on('error', (e) => (connected ? console.log(e.message) : setTimeout(start, 1000)));
    plain.on('data', () => {});
    plain.on('connect', () => {
        connected = true;
        timer = setInterval(tick, 250);
        process.on('SIGUSR2', () => {
            clearInterval(timer);
            timer = undefined;
        });
        process.on('SIGUSR1', () => (timer = timer || setInterval(tick, 250)));
    });
};
start();
