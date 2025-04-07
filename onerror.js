const express = require('express');
require('dotenv').config();
const http = require('http');
const https = require('https');
const fs = require('fs');

const app = express();
const host = "0.0.0.0";
const port = process.env.port || 443;
const port_http = process.env.port_http || 80;
const credentials = { key: fs.readFileSync("keys/key.pem", 'utf8'), cert: fs.readFileSync("keys/cert.pem", 'utf8') };

// 创建 HTTPS 服务器
app.use(async (req, res, next) => {
	// 处理 CORS
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
	res.setHeader('Access-Control-Allow-Headers', 'Content-Type, content-type');
	// 处理 OPTIONS 预检请求
	if (req.method === 'OPTIONS') {
		res.writeHead(204);
		return res.end();
	}
	res.writeHead(200, {
		"Content-Type": "text/plain; charset=utf-8",
		"Cache-Control": "public, max-age=3600",
		"Content-Disposition": "inline",
		"Cross-Origin-Resource-Policy": "same-origin",
		"X-Frame-Options": "DENY",
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Content-Type-Options": "nosniff",
		"X-XSS-Protection": "1; mode=block",
		"Referrer-Policy": "no-referrer",
		"Permissions-Policy": "geolocation=(), camera=(), microphone=()"
	});
	res.end("We are currently experiencing technical difficulties and are making every effort to resolve them as quickly as possible.\n系统目前遇到技术故障，技术团队正在全力抢修中。");
});

https.createServer(credentials, app).listen(port, () => {
	console.log(`服务器运行在: http://localhost:${port} && `);
}).on('error', err => {
	console.error('启动失败:', err);
});
http.createServer((req, res) => {
	res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
	res.end();
}).listen(port_http, () => {
	console.log(`http 重定向服务器运行在: http://localhost:${port_http}`);
});