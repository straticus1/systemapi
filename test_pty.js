const WebSocket = require('ws');

// Assuming hostId is known. I will fetch the hostId via REST API first.
const axios = require('axios');

async function test() {
    try {
        const res = await axios.get('http://localhost:3003/api/v1/fleet', { headers: { 'X-API-Key': 'ak_live_1234.demo' } });
        if (res.data.hosts.length === 0) {
            console.log("No hosts found");
            return;
        }
        const hostId = res.data.hosts[0].host_id;
        console.log("Using Host ID:", hostId);

        const ws = new WebSocket(`ws://localhost:3003/api/v1/systems/terminal/${hostId}?api_key=ak_live_1234.demo`);

        ws.on('open', () => {
            console.log("Connected to terminal WebSocket");
        });

        ws.on('message', (data) => {
            console.log("Received from terminal:", typeof data, data.toString());
        });

        ws.on('close', () => {
             console.log("Terminal WebSocket closed");
        });

        ws.on('error', (err) => {
             console.log("Terminal WebSocket error:", err);
        });
    } catch (e) {
        console.log("REST Error:", e.response?.data || e.message);
    }
}

test();
