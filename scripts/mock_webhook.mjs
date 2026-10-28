// 本地 mock webhook：接收 SocradarBot 推送，落盘用于断言
import http from 'node:http';
import fs from 'node:fs';

const OUT = new URL('./mock_received.json', import.meta.url);
const reqs = [];
http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    reqs.push({ time: new Date().toISOString(), path: req.url, body: body.slice(0, 6000) });
    fs.writeFileSync(OUT, JSON.stringify(reqs, null, 2));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ errcode: 0, errmsg: 'ok' }));
  });
}).listen(18080, '127.0.0.1', () => console.log('mock webhook listening on http://127.0.0.1:18080'));
