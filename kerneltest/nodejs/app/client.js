// Usage: node client.js <tls port> <count file>
// Sends HTTPS requests one at a time, two over each connection: the first write of a connection is traced
// before the agent has seen any read on it, the second one after. The client closes the connections itself,
// because the agent loses some responses on connections that the server closes, with or without TLS.
// It writes the number of completed requests to the count file. SIGUSR2 pauses it and SIGUSR1 resumes it.
const fs = require('fs'), https = require('https');

const [port, countFile] = process.argv.slice(2);
const newAgent = () => new https.Agent({keepAlive: true, maxSockets: 1});
let agent = newAgent(), n = 0, done = 0, paused = false;
const send = () => {
    // the timer also keeps the process alive while it is paused
    if (paused) {
        setTimeout(send, 250);
        return;
    }
    if (n++ % 2 === 0) {
        agent.destroy();
        agent = newAgent();
    }
    https.get({host: '127.0.0.1', port, path: '/', agent, rejectUnauthorized: false}, (res) => {
        res.resume();
        res.on('end', () => {
            fs.writeFileSync(countFile, String(++done));
            setTimeout(send, 250);
        });
    }).on('error', (e) => {
        console.log(e.message);
        setTimeout(send, 1000);
    });
};
process.on('SIGUSR2', () => (paused = true));
process.on('SIGUSR1', () => (paused = false));
send();
