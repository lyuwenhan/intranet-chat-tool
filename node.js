// Project: Intranet Chat Tool
// Copyright (C) 2025 lyuwenhan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const fs = require('fs');
const { spawn, execSync } = require('child_process');

fs.mkdirSync("./error/critical", { recursive: true });
fs.mkdirSync("./error/normal", { recursive: true });
const ERROR_FLAG_FILE = './error/.error_status.json';

function killOldOnErrorProcess() {
  if (fs.existsSync(ERROR_FLAG_FILE)) {
	const { pid } = JSON.parse(fs.readFileSync(ERROR_FLAG_FILE));
	try {
	  	process.kill(pid);
		console.log("error.js killed");
	} catch (e) {
	  	console.warn(`进程结束失败: ${e.message}`);
	}
	fs.unlinkSync(ERROR_FLAG_FILE);
  }
}

killOldOnErrorProcess();

function critical_error(err){
	fs.writeFileSync(`error/critical/error_${Date.now()}.log`, `Critical Error (${(new Date()).toString()})\nfrom: node.js\n${err}`);
	console.log(err);
	const child = spawn('node', ['error.js'], {
		detached: true,
		stdio: 'ignore',
	});
	child.unref();
	fs.writeFileSync(ERROR_FLAG_FILE, JSON.stringify({
		pid: child.pid,
		time: Date.now()
	}, null, 2));
	process.exit(1);
}
process.on('uncaughtException', (err) => {
	critical_error(err);
});
process.on('unhandledRejection', (err) => {
	critical_error(err);
});

// throw new Error("test");
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const cors = require('cors');
const readline = require('readline');
const http = require('http');
const https = require('https');
const path = require('path');
const mime = require('mime-types');
const multer = require('multer');
const marked = require("marked");
const Prism = require('prismjs');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const renderer = new marked.Renderer();
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const Database = require('better-sqlite3');
const db = new Database('./data/users.db');
fs.mkdirSync("./cppfile", { recursive: true });
const db_codes = new Database('./cppfile/codes.db');
const credentials = { key: fs.readFileSync("keys/key.pem", 'utf8'), cert: fs.readFileSync("keys/cert.pem", 'utf8') };
const svgCaptcha = require('svg-captcha');
const sharp = require('sharp');
const app = express();

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));
function banIp(ip) {
	if (!ban_list2.includes(ip)) {
		ban_list2.push(ip);
		fs.writeFileSync(banPath, JSON.stringify(ban_list2, null, 2));
		fs.appendFileSync('log/ban.log', `${ip} 被自动封禁 ${new Date().toString()}\n`);
	}
}

const baseWindow = 60 * 1000; // 60 秒
const windowScale = { s: 1, m: 5, l: 60 };
const maxScale = { s: 1, m: 4, l: 42 };

// 生成 limiter 实例
function createLimiter(label, level, baseMax, ban = false) {
	const timeFactor = windowScale[level.replace('_ban', '')] || 1;
	const windowMs = baseWindow * timeFactor;
	const max = baseMax * (ban ? 4 : 1) * (maxScale[level.replace('_ban', '')] || 1);
	const tag = `${label}_${level}`;

	return rateLimit({
		windowMs,
		max,
		message: { message: `请求频率过高（${tag}）${level}` },
		handler: ban
			? (req, res) => {
				const ip = req.ip.replace("::ffff:", "");
				banIp(ip);
				res.status(429).json({ message: `访问过于频繁，已封禁（${tag}）` });
			}
			: undefined
	});
}

// 自动挂载所有配置
function applyLimiters(app, configList) {
	for (const config of configList) {
		const { path, label, max, levels } = config;
		const limiters = levels.map(level =>
			createLimiter(label, level, max, level.includes('_ban'))
		);
		app.use(path, ...limiters);
	}
}

const limiterConfig = [
	{
		path: '/api/login/',
		label: 'auth',
		max: 10,
		levels: ['s', 'm', 'l', 's_ban', 'm_ban', 'l_ban'] // 登录注册
	},
	{
		path: 'api/captcha/',
		label: 'auth',
		max: 5,
		levels: ['s', 'm', 'l', 's_ban', 'm_ban', 'l_ban'] // 登录注册
	},
	{
		path: '/api/',
		label: 'auth',
		max: 150,
		levels: ['s', 'm', 'l', 's_ban', 'm_ban', 'l_ban'] // 登录注册
	},
	{
		path: '/cpp-run',
		label: 'run',
		max: 3,
		levels: ['s', 'm', 'l', 's_ban', 'm_ban', 'l_ban'] // 代码运行
	},
	{
		path: ['/upload', '/uploadimg'],
		label: 'upload',
		max: 5,
		levels: ['s', 'm', 'l', 's_ban', 'm_ban', 'l_ban'] // 上传文件/图像
	},
	{
		path: '/',
		label: 'global',
		max: 300,
		levels: ['s', 'm', 'l', 's_ban', 'm_ban', 'l_ban'] // 全站访问
	}
];
applyLimiters(app, limiterConfig);

DOMPurify.addHook('uponSanitizeAttribute', (node, data) => {
	if (data.attrName === 'style' && /position\s*:/.test(data.attrValue)) {
		data.keepAttr = false;
	}
});
// 手动 HTML 转义，防止 XSS
const escapeHtml = (code) => {
	return code
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
};

renderer.codespan = function(text) {
	return `<code class='code'>${text.text}</code>`;
};
renderer.code = function(code) {
	if(!code.lang){
		code.lang = "none";
	}
	if(code.lang == 'c++'){
		code.lang = "cpp";
	}
	if(code.lang == 'cpp' || code.lang == 'c'){
		code.lang = "clike" + code.lang;
	}
	return `<pre class="line-numbers language-${code.lang}"><code class="language-${code.lang}">${escapeHtml(code.text)}</code></pre>`;
};

marked.setOptions({
	renderer: renderer,
	highlight: function(code, lang) {
		const language = Prism.languages[lang] || Prism.languages.javascript;
		return Prism.highlight(code, language, lang);
	}
});
function make128(){
	return crypto.randomBytes(64).toString('hex');
}
const private_pwd = make128();
const session_pwd = process.env.session_pwd;
const allow_register = process.env.allow_register === 'true';
const host = "0.0.0.0";
const port = process.env.port || 443;
const port_http = process.env.port_http || 80;
const { v4: uuidv4 } = require('uuid');
const { exec } = require('child_process');

const session = require('express-session');

app.use(session({
	secret: session_pwd,
	resave: false,
	saveUninitialized: true,
	rolling: true,
	cookie: {
		httpOnly: true,
		secure: true,
		sameSite: 'Strict',
		maxAge: 1000 * 60 * 30
	}
}));
app.use((req, res, next) => {
	res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
	next();
});


/*
RSA + SHA
*/
function to_json(file_name){
	if (fs.existsSync(file_name)) {
		let rawData = fs.readFileSync(file_name);
		if(rawData == ""){
			rawData = "[]";
		}
		return JSON.parse(rawData);
	}
	return null;
}

/**
 * 生成 RSA 公私钥对
 * @param {number} [modulusLength=2048] - RSA 密钥长度，默认 2048
 * @param {string} [passphrase=''] - 私钥加密用的口令，如果不需要加密私钥可为空字符串
 * @returns {{ publicKey: string, privateKey: string }} - 返回 PEM 格式公钥、私钥字符串
 */
function generateKeyPairRSA(modulusLength = 2048, passphrase = '') {
	const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
		modulusLength,
		publicKeyEncoding: {
		type: 'pkcs1',
		format: 'pem'
		},
		privateKeyEncoding: {
		type: 'pkcs8',
		format: 'pem',
		...(passphrase
			? { cipher: 'aes-256-cbc', passphrase }
			: {}
		)
		}
	});

	return { publicKey, privateKey };
	}

	/**
	 * 使用 RSA 公钥 (RSA-OAEP + SHA-256) 加密
	 * @param {string|Buffer} plaintext - 原始明文
	 * @param {string} publicKey - PEM 格式公钥
	 * @returns {string} - Base64 编码的密文
	 */
	function encryptRSA(plaintext, publicKey) {
	// 1. 准备明文二进制数据
	const buffer = Buffer.isBuffer(plaintext)
		? plaintext
		: Buffer.from(plaintext, 'utf8');

	// 2. 使用 RSA 公钥进行加密 (RSA-OAEP 填充 + SHA-256)
	const encrypted = crypto.publicEncrypt(
		{
		key: publicKey,
		padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
		oaepHash: 'sha256'
		},
		buffer
	);

	// 3. 返回 Base64 编码结果
	return encrypted.toString('base64');
	}

	/**
	 * 使用 RSA 私钥 (RSA-OAEP + SHA-256) 解密
	 * @param {string} ciphertextBase64 - Base64 编码的密文
	 * @param {string} privateKey - PEM 格式私钥
	 * @param {string} [passphrase=''] - 如果私钥加了口令，需要传入同样的口令
	 * @returns {string} - 解密后明文（UTF-8）
	 */
function decryptRSA(ciphertextBase64, privateKey, passphrase = '') {
	// 1. Base64 转 Buffer
	const buffer = Buffer.from(ciphertextBase64, 'base64');

	let decrypted;
	// 2. 区分是否有私钥口令
	if (passphrase) {
		decrypted = crypto.privateDecrypt(
		{
			key: privateKey,
			passphrase,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: 'sha256'
		},
		buffer
		);
	} else {
		decrypted = crypto.privateDecrypt(
		{
			key: privateKey,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: 'sha256'
		},
		buffer
		);
	}

	// 3. 返回明文字符串
	return decrypted.toString('utf8');
}

	/**
	 * 判断是否是可解密的合法密文 (RSA-OAEP + SHA-256)
	 * @param {string} ciphertextBase64 - Base64 编码的密文
	 * @param {string} privateKey - PEM 格式私钥
	 * @param {string} [passphrase=''] - 如果私钥加了口令，需要传入同样的口令
	 * @returns {boolean} - 解密成功且明文非空返回true，否则返回false
	 */
	function isValidCiphertext(ciphertextBase64, privateKey, passphrase = '') {
	try {
		// 1. Base64 解码
		const buffer = Buffer.from(ciphertextBase64, 'base64');

		// 2. 使用私钥尝试解密 (同上，加 RSA-OAEP + SHA-256)
		let decrypted;
		if (passphrase) {
		decrypted = crypto.privateDecrypt({
			key: privateKey,
			passphrase,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: 'sha256'
		}, buffer);
		} else {
		decrypted = crypto.privateDecrypt({
			key: privateKey,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: 'sha256'
		}, buffer);
		}

		// 3. 解密成功后转换为字符串，做简单校验
		const plaintext = decrypted.toString('utf8');
		if (!plaintext || plaintext.trim().length === 0) {
		return false;
		}
		return true; // 解密成功且非空
	} catch (err) {
		// 解密出错 => 认为密文不合法
		return false;
	}
	}


function sha256(data) {
	return crypto
	.createHash('sha256')   // 创建一个 SHA-256 哈希实例
	.update(data)           // 填入待散列的数据
	.digest('base64');         // 以 hex（十六进制）格式输出
}

/*
RSA + SHA
*/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
remove trash
*/
fs.rmSync("./uploads/iofiles", { recursive: true, force: true });
fs.rmSync("./judge/codes", { recursive: true, force: true });
fs.rmSync("./judge/exefiles", { recursive: true, force: true });
fs.rmSync("./judge/inputfiles", { recursive: true, force: true });
fs.mkdirSync("./uploads/iofiles", { recursive: true });
fs.mkdirSync("./uploads/img", { recursive: true });
fs.mkdirSync("./uploads/download", { recursive: true });
fs.mkdirSync("./judge/codes", { recursive: true });
fs.mkdirSync("./judge/exefiles", { recursive: true });
fs.mkdirSync("./judge/inputfiles", { recursive: true });
fs.mkdirSync("./log", { recursive: true });
/*
remove trash
*/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*database*/
db.prepare(`
	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		role TEXT,
		salt TEXT,
		hash TEXT
	)
`).run();
db_codes.prepare(`
	CREATE TABLE IF NOT EXISTS codes (
		filename TEXT PRIMARY KEY,
		readOnly INTEGER DEFAULT 0,
		roname TEXT DEFAULT NULL,
		updated_at INTEGER DEFAULT 0
	)
`).run();
const insertUser = db.prepare('INSERT INTO users (username, role, salt, hash) VALUES (?, ?, ?, ?)');
const getUser = db.prepare('SELECT * FROM users WHERE username = ?');
const deleteUser = db.prepare('DELETE FROM users WHERE username = ?');
const getAllUsers = db.prepare('SELECT username, role FROM users');
const saveNewCode = db_codes.prepare(`INSERT INTO codes (filename, readOnly, roname, updated_at) VALUES (?, 0, NULL, ?) ON CONFLICT(filename) DO UPDATE SET readOnly = 0, roname = NULL, updated_at = ?`);
const getCode = db_codes.prepare('SELECT * FROM codes WHERE filename = ?');
const setRoName = db_codes.prepare('UPDATE codes SET roname = ?, updated_at = ? WHERE filename = ?');
const saveRoCode = db_codes.prepare('INSERT INTO codes (filename, readOnly, roname, updated_at) VALUES (?, 1, ?, ?)');
const deleteCode = db_codes.prepare('DELETE FROM codes WHERE filename = ?');
const refreshCode = db_codes.prepare(`UPDATE codes SET updated_at = ? WHERE filename = ?`);
const getOldCode = db_codes.prepare(`SELECT filename FROM codes WHERE updated_at <= ?`);
// console.log(getAllUsers.all());
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
role:
admin/user
*/
function addUser(username, role, pwd){
	const salt = make128();
	const hashed_pwd = sha256(pwd + salt);
	insertUser.run(username, role, salt, hashed_pwd);
}
function findUser(username){
	return getUser.get(username);
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
main server
*/
app.use(cors());
app.use(bodyParser.json());

const dataFilePath = './data/data.json', banFilePath = "./data/ban_list.json", get_path = "./data/get_cnt.json";
var waiting_clear=false;
var waiting=null;
const ban_list = [];
var ban_list2 = to_json(banFilePath);
const ban_name = ["sb", "shabi", "dashabi", "shab", "shb", "sabi", "sab", "hundan"];
// const ip_cntlimit = [20, 700];
var data = [{chats : []}, {chats : []}];
const cleartime = 1000 * 60 * 60 * 24 * 14;

function getToday() {
	return new Date().toISOString().split('T')[0];
}

// 读取计数器
function readCounter() {
	if (fs.existsSync(get_path)) {
		return JSON.parse(fs.readFileSync(get_path, 'utf-8'));
	} else {
		return { date: getToday(), count: 0 };
	}
}

// 写入计数器
function writeCounter(data) {
	fs.writeFileSync(get_path, JSON.stringify(data));
}

// 主函数（调用时+1，每日自动重置）
function incrementCounter() {
	let data = readCounter();

	if (data?.date !== getToday()) {
		fs.appendFileSync("log/get-svg.log", `UTC New Day ${Date.now()} ${(new Date()).toString()}\n`);
		data = { date: getToday(), count: 1 };
	} else {
		data.count += 1;
	}

	writeCounter(data);
	return data.count;
}


// 1. 生成密钥对
const { publicKey, privateKey } = generateKeyPairRSA(2048, private_pwd);

if (fs.existsSync(dataFilePath)) {
	data = to_json(dataFilePath);
	if(!data || !data[1]){
		data = [{}, {}];
	}
	if(!data[0].chats){
		data[0].chats=[];
	}
	if(!data[1].chats){
		data[1].chats=[];
	}
}

function consoleInput(question) {
	return new Promise((resolve) => {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout
		});
		rl.question(question, (answer) => {
			resolve(answer);
			rl.close();
		});
	});
}
async function getinput(inp) {
	let input = await consoleInput(inp + '\n');
	return input;
}


async function clear(){
	if(waiting_clear){
		return { message: 'refuse' };
	}

	waiting_clear = true;
	let input = await getinput("clear (Y/n)");

	waiting_clear = false;
	if(input == 'y' || input == 'Y'){
		data = [{ "chats": [] }, { "chats": [] }];
		fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
		return { message: 'success' };
	} else {
		return { message: 'refuse' };
	}
}

async function start_clear(){
	if(waiting){
		return await waiting;
	}

	waiting = clear().then(res => {
		waiting = null;
		return res;
	});

	return await waiting;
}

function isValidUsername(username){
	return username && username.length <= 20 && !ban_name.some(user => user == username) && /^\w+$/.test(username);
}
function encodeRSA(pwd){
	if(pwd && isValidCiphertext(pwd, privateKey, private_pwd)){
		return decryptRSA(pwd, privateKey, private_pwd);
	}else{
		return null;
	}
}
async function generateCaptcha(options = {}) {
	const captcha = svgCaptcha.create({
		size: 4,
		noise: 2,
		color: true,
		background: '#f1f1f1',
		ignoreChars: 'Il',
		...options
	});
	return {text: captcha.text,data: `data:image/png;base64,${(await sharp(Buffer.from(captcha.data), { density: 144 }).png().toBuffer()).toString('base64')}`};
}

app.post('/api/login/', (req, res) => {
	const receivedContent = req.body.content || {};
	var ip=req.ip.replace("::ffff:", ""), rawip = ip;
	if(ban_list.some(user => user == ip) || ban_list2.some(user => user == ip)){
		return res.status(403).end();
	}
	const now = Date.now();
	fs.appendFileSync("log/ip.log", `${ip} ${now} ${(new Date()).toString()} server.login\n`);
	fs.appendFileSync("log/login.log", `${ip} ${now} ${(new Date()).toString()} ${JSON.stringify(receivedContent)}\n`);
	console.log('收到的内容：');
	console.log("realip:", ip);
	if(/^[0-9]+(?:\.[0-9]+){3}$/.test(ip)){
		ip = ip.split(".");
		ip = ip[0].slice(0, ip[0].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[0][ip[0].length - 1] + ".*.*." + ip[3].slice(0, ip[3].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[3][ip[3].length - 1];
	}
	receivedContent.ip=ip;
	console.log(receivedContent);
	if(receivedContent.type == "login"){
		if(!receivedContent.username){
			res.json({ message: 'refuse', info:'Username cannot be empty'});
			return;
		}
		if(!isValidUsername(receivedContent.username)){
			res.json({ message: 'refuse', info:'Username is not valid'});
			return;
		}
		const pwd = encodeRSA(receivedContent.pwd);
		const userinfo = findUser(receivedContent.username);
		if((userinfo && pwd && sha256(pwd + userinfo.salt) === userinfo.hash)){
			req.session.username = receivedContent.username;
			res.json({ message: 'success' });
		}else{
			res.json({ message: 'refuse', info:'Username or password is incorrect'});
		}
		return;
	}else if(allow_register && receivedContent.type == "register" && receivedContent.username && receivedContent.captcha){
		if(!receivedContent.username){
			res.json({ message: 'refuse', info:'Username cannot be empty'});
			return;
		}
		if(!isValidUsername(receivedContent.username)){
			res.json({ message: 'refuse', info:'Username is not valid'});
			return;
		}
		const userinfo = findUser(receivedContent.username);
		if(userinfo){
			res.json({ message: 'refuse', info:'Username already exists'});
			return;
		}
		if(!req.session.captcha || req.session.captcha != receivedContent.captcha.toLowerCase()){
			res.json({ message: 'refuse', info:'Captcha not correct'});
			return;
		}
		const pwd = encodeRSA(receivedContent.pwd);
		if(!pwd){
			res.json({ message: 'refuse', info:'Password cannot be empty'});
			return;
		}
		if(pwd.length < 6){
			res.json({ message: 'refuse', info:'Password too short'});
			return;
		}
		addUser(receivedContent.username, "user", pwd);
		res.json({ message: 'success' });
		return;
	}else if(receivedContent.type == "logout"){
		if(!req.session.username){
			res.json({ message: 'refuse'});
			return;
		}
		req.session.username = "";
		res.json({ message: 'success' });
		return;
	}
	res.json({ message: 'faild' });
});
app.post('/api/captcha', async (req, res) => {
	var ip=req.ip.replace("::ffff:", ""), rawip = ip;
	if(ban_list.some(user => user == ip) || ban_list2.some(user => user == ip)){
		return res.status(403).end();
	}
	const now = Date.now();
	fs.appendFileSync("log/ip.log", `${ip} ${now} ${(new Date()).toString()} server.captcha\n`);
	fs.appendFileSync("log/captcha.log", `${ip} ${now} ${(new Date()).toString()}\n`);
	console.log('收到的内容：');
	console.log("realip:", ip);
	if(/^[0-9]+(?:\.[0-9]+){3}$/.test(ip)){
		ip = ip.split(".");
		ip = ip[0].slice(0, ip[0].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[0][ip[0].length - 1] + ".*.*." + ip[3].slice(0, ip[3].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[3][ip[3].length - 1];
	}
	const captcha = await generateCaptcha();
	req.session.captcha = captcha.text.toLowerCase();
	res.json({ message: 'success', image: captcha.data });
});

app.post('/api/', (req, res) => {
	const receivedContent = req.body.content || {};
	var ip=req.ip.replace("::ffff:", ""), rawip = ip;
	if(ban_list.some(user => user == ip) || ban_list2.some(user => user == ip)){
		return res.status(403).end();
	}
	const now = Date.now();
	fs.appendFileSync("log/ip.log", `${ip} ${now} ${(new Date()).toString()} server.main\n`);
	fs.appendFileSync("log/main.log", `${ip} ${now} ${(new Date()).toString()} ${JSON.stringify(receivedContent)}\n`);
	console.log('收到的内容：');
	console.log("realip:", ip);
	if(/^[0-9]+(?:\.[0-9]+){3}$/.test(ip)){
		ip = ip.split(".");
		ip = ip[0].slice(0, ip[0].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[0][ip[0].length - 1] + ".*.*." + ip[3].slice(0, ip[3].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[3][ip[3].length - 1];
	}
	receivedContent.ip=ip;
	console.log(receivedContent);
	if(receivedContent.type == "get-username"){
		res.json(req.session.username || "");
		return;
	}else if(receivedContent.type == "get-key"){
		res.json(publicKey);
		return;
	}else if(!isValidUsername(req.session.username)){
		res.status(401).json({ error: 'Unauthorized' });
		return;
	}else if(receivedContent.type == "send"){
		if(!receivedContent.info || receivedContent.info.replace(/\n+/g, "\n").trimStart().trimEnd() == ""){
			res.json({ message: 'faild' });
			return;
		}
		data[0].chats.push({username:req.session.username, info:receivedContent.info.replace(/\n+/g, "\n").trimStart().trimEnd(),ip:receivedContent.ip, type:"text"});
		data[1].chats.push(rawip);
		fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
		res.json({ message: 'success' , chats: data[0].chats});
		return;
	}else if(receivedContent.type == "send-code"){
		if(!receivedContent.info || receivedContent.info.replace(/\n+/g, "\n").trimEnd() == ""){
			res.json({ message: 'faild' });
			return;
		}
		let js = {username:req.session.username, info:receivedContent.info.replace(/\n\n\n+/g, "\n\n").trimEnd(),ip:receivedContent.ip, type:"code"};
		if(receivedContent.language){
			js.language = receivedContent.language;
			if(receivedContent.language == "markdown"){
				js.html = DOMPurify.sanitize(marked.parse(js.info), {
					FORBID_TAGS: ['script', 'iframe', 'style'],
					FORBID_ATTR: ['onclick','ondblclick','onmousedown','onmouseup','onmouseenter','onmouseleave','onmouseover','onmouseout','onmousemove','oncontextmenu','onkeydown','onkeypress','onkeyup','onfocus','onblur','onchange','oninput','onreset','onsubmit','oninvalid','ondrag','ondragstart','ondragend','ondragenter','ondragleave','ondragover','ondrop','oncopy','oncut','onpaste','ontouchstart','ontouchmove','ontouchend','ontouchcancel','onscroll','onwheel','onresize','onload','onerror','onabort','onbeforeunload','onunload','onplay','onpause','onended','onvolumechange','oncanplay','oncanplaythrough','onwaiting','onseeking','onseeked','ontimeupdate','onanimationstart','onanimationend','onanimationiteration','ontransitionend','onshow','ontoggle','onmessage','onopen','onclose']
				});
			}
		}
		data[0].chats.push(js);
		data[1].chats.push(rawip);
		fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
		res.json({ message: 'success' , chats: data[0].chats});
		return;
	}else if(receivedContent.type == "get"){
		res.json(data[0]);
		return;
	}else if(receivedContent.type == "command" && receivedContent.info == "/clear"){
		if(JSON.stringify(data[0]) === JSON.stringify({ chats: [] })){
			res.json({ message: 'faild', info: 'nothing to do' });
		}else if((findUser(req.session.username))?.role == "admin"){
			data = [{ "chats": [] }, { "chats": [] }];
			fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
			fs.rmSync("./uploads", { recursive: true, force: true });
			fs.rmSync("./judge/codes", { recursive: true, force: true });
			fs.rmSync("./judge/exefiles", { recursive: true, force: true });
			fs.rmSync("./judge/inputfiles", { recursive: true, force: true });
			fs.rmSync("./data/gat_cnt.json", { recursive: true, force: true });
			fs.rmSync("./log", { recursive: true, force: true });
			fs.mkdirSync("./uploads/iofiles", { recursive: true });
			fs.mkdirSync("./uploads/img", { recursive: true });
			fs.mkdirSync("./uploads/download", { recursive: true });
			fs.mkdirSync("./judge/codes", { recursive: true });
			fs.mkdirSync("./judge/exefiles", { recursive: true });
			fs.mkdirSync("./judge/inputfiles", { recursive: true });
			fs.mkdirSync("./log", { recursive: true });
			res.json({ message: 'success', chats: data[0].chats });
		}else{
			res.json({ message: 'refuse' });
		}
		return;
	}
	res.json({ message: 'faild' });
});

function readFirst(filename) {
	const buffer = Buffer.alloc(1024); // 预分配 1KB 缓冲区
	const fd = fs.openSync(filename, 'r'); // 以只读方式打开文件
	const bytesRead = fs.readSync(fd, buffer, 0, 1024, 0); // 从偏移量 0 读取 1024 字节
	fs.closeSync(fd); // 关闭文件
	return buffer.toString('utf-8', 0, bytesRead); // 转换为字符串
}

app.post('/cpp-run', (req, res) => {
	const receivedContent = req.body.content || {};
	var ip=req.ip.replace("::ffff:", ""), rawip = ip;
	const now = Date.now();
	fs.appendFileSync("log/ip.log", `${ip} ${now} ${(new Date()).toString()} cpp.run\n`);
	if(req.session.cppRunning){
		res.json({ message: 'faild', stdout: "ERROR", stderr: "you cannot run more than one codes at the same time"});
		fs.appendFileSync("log/run.log", `${ip} ${now} ${(new Date()).toString()} too many codes\n`);
		return;
	}
	fs.appendFileSync("log/run.log", `${ip} ${now} start\n${receivedContent.code}\n`);
	if(ban_list.some(user => user == ip) || ban_list2.some(user => user == ip)){
		return res.status(403).end();
	}
	console.log('收到的内容：');
	console.log("realip:", ip);
	if(/^[0-9]+(?:\.[0-9]+){3}$/.test(ip)){
		ip = ip.split(".");
		ip = ip[0].slice(0, ip[0].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[0][ip[0].length - 1] + ".*.*." + ip[3].slice(0, ip[3].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[3][ip[3].length - 1];
	}
	receivedContent.ip=ip;
	console.log(receivedContent);
	if(!isValidUsername(req.session.username)){
		res.status(401).json({ error: 'Unauthorized' });
		return;
	}else if(receivedContent.type == "run-code"){
		if(!receivedContent.code || receivedContent.code.replace(/\n+/g, "\n").trimStart().trimEnd() == ""){
			res.json({ message: 'faild' });
			return;
		}
		const filename = uuidv4() + "";
		const cpp = "judge/codes/" + filename + ".cpp";
		const input = "judge/inputfiles/" + filename + ".in";
		const output = "iofiles/" + filename + ".out";
		const errfile = "iofiles/" + filename + ".err";
		const exefile = "judge/exefiles/" + filename + ".exe";
		fs.writeFileSync(cpp, receivedContent.code || "");
		fs.writeFileSync(input, (receivedContent.input ? receivedContent.input : ""));
		req.session.cppRunning = true;
		exec("judge\\judge.exe " + cpp + " " + input + " uploads/" + output + " uploads/" + errfile + " " + exefile + " 10000 128 1048576 -O2", (error, stdout, stderr) => {
			fs.rm(cpp, (err)=>{});
			fs.rm(input, (err)=>{});
			fs.rm(exefile, (err)=>{});
			if (stderr) {
				res.json({ message: 'faild', stdout, stderr});
				req.session.cppRunning = null;
				req.session.save(err=>{});
				return;
			}
			var outsize, errsize;
			if(!fs.existsSync("uploads/" + output)){
				fs.writeFileSync("uploads/" + output, "");
			}
			if(!fs.existsSync("uploads/" + errfile)){
				fs.writeFileSync("uploads/" + errfile, "");
			}
			outsize = fs.statSync("uploads/" + output).size;
			errsize = fs.statSync("uploads/" + errfile).size;
			req.session.cppRunning = null;
			req.session.save(err=>{});
			fs.appendFileSync("log/run.log", `${ip} ${now} ${(new Date()).toString()} end\n`);
			res.json({ message: 'success', outsize, stdoutfile: output, stdout: readFirst("uploads/" + output), errsize, stderrfile: errfile, stderr: readFirst("uploads/" + errfile)});
		});
		return;
	}
	res.json({ message: 'faild' });
});
function isValidUUIDv4(uuid) {
	const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
	return regex.test(uuid);
}

function saveCode(code, filename, type){
	if (!filename || !type){
		return
	};
	const basePath = "cppfile/";
	if(type === 'savecpp'){
		fs.writeFileSync(path.join(basePath, `${filename}.cpp`), code || "");
		fs.writeFileSync(path.join(basePath, `${filename}-unsave.cpp`), code || "");
	}else if (type === 'savecpp-unsave'){
		fs.writeFileSync(path.join(basePath, `${filename}-unsave.cpp`), code || "");
	}else{
		fs.writeFileSync(path.join(basePath, `${filename}.in`), code || "");
	}
	const now = Date.now();
	saveNewCode.run(filename, now, now);
}
function getRoName(filename) {
	const record = getCode.get(filename);
	if (record?.roname) return record.roname;
	const filename2 = uuidv4();
	const basePath = "cppfile/";
	const cppcode = fs.readFileSync(path.join(basePath, `${filename}.cpp`), 'utf-8') || "";
	fs.writeFileSync(path.join(basePath, `${filename2}-unsave.cpp`), cppcode);
	fs.writeFileSync(path.join(basePath, `${filename2}.cpp`), cppcode);
	fs.writeFileSync(path.join(basePath, `${filename2}.in`), fs.readFileSync(path.join(basePath, `${filename}.in`), 'utf-8') || "");
	const now = Date.now();
	setRoName.run(filename2, now, filename);
	saveRoCode.run(filename2, filename2, now);
	return filename2;
}
function getCpName(filename) {
	const filename2 = uuidv4();
	const basePath = "cppfile/";
	const cppPath = path.join(basePath, `${filename}.cpp`);
	if (!fs.existsSync(cppPath)) {
		fs.writeFileSync(cppPath, "");
	}
	const cppcode = fs.readFileSync(cppPath, 'utf-8');
	const inPath = path.join(basePath, `${filename}.in`);
	if (!fs.existsSync(inPath)) {
		fs.writeFileSync(inPath, "");
	}
	const inputCode = fs.readFileSync(inPath, 'utf-8');
	fs.writeFileSync(path.join(basePath, `${filename2}-unsave.cpp`), cppcode);
	fs.writeFileSync(path.join(basePath, `${filename2}.cpp`), cppcode);
	fs.writeFileSync(path.join(basePath, `${filename2}.in`), fs.readFileSync(inPath, 'utf-8'));
	const now = Date.now();
	saveNewCode.run(filename2, now, now);
	return filename2;
}
function deleteFile(filename){
	const basePath = "cppfile/";
	const suffixes = ["-unsave.cpp", ".cpp", ".in"];
	for(const ext of suffixes){
		const filePath = path.join(basePath, filename + ext);
		if(fs.existsSync(filePath)){
			fs.rmSync(filePath, { force: true });
		}
	}
	deleteCode.run(filename);
}
function refreshFile(filename){
	if(!filename){
		return;
	}
	const now = Date.now();
	refreshCode.run(now, filename);
}
function cleanOldCode(){
	const now = Date.now();
	const expired = getOldCode.all(now - cleartime);
	for(const row of expired){
		deleteFile(row.filename);
	}
}

Promise.resolve().then(cleanOldCode);
setInterval(cleanOldCode, 10 * 60 * 1000);

app.post('/cpp-save', (req, res) => {
	const receivedContent = req.body.content || {};
	var ip=req.ip.replace("::ffff:", ""), rawip = ip;
	const now = Date.now();
	fs.appendFileSync("log/ip.log", `${ip} ${now} ${(new Date()).toString()} cpp.save\n`);
	fs.appendFileSync("log/save.log", `${ip} ${now} ${(new Date()).toString()} ${receivedContent.code}\n`);
	if(ban_list.some(user => user == ip) || ban_list2.some(user => user == ip)){
		return res.status(403).end();
	}
	console.log('收到的内容：');
	console.log("realip:", ip);
	if(/^[0-9]+(?:\.[0-9]+){3}$/.test(ip)){
		ip = ip.split(".");
		ip = ip[0].slice(0, ip[0].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[0][ip[0].length - 1] + ".*.*." + ip[3].slice(0, ip[3].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[3][ip[3].length - 1];
	}
	receivedContent.ip=ip;
	console.log(receivedContent);
	if(!isValidUsername(req.session.username)){
		res.status(401).json({ error: 'Unauthorized' });
		return;
	}else if((receivedContent.type == "savecpp" || receivedContent.type == "savecpp-unsave" || receivedContent.type == "saveinput") && receivedContent.link){
		const filename = receivedContent.link;
		const file = getCode.get(filename);
		if(!isValidUUIDv4(filename) || (file && file.readOnly)){
			res.json({ message: 'faild' });
			return;
		}
		saveCode(receivedContent.code || "", filename, receivedContent.type);
		res.json({ message: 'success' });
		return;
	}else if(receivedContent.type == "cp" && receivedContent.link){
		const filename = receivedContent.link;
		const file = getCode.get(filename);
		if(!isValidUUIDv4(filename) || !file){
			res.json({ message: 'faild' });
			return;
		}
		refreshFile(filename);
		res.json({ message: 'success', link: getCpName(filename) });
		return;
	}else if(receivedContent.type == "cpro" && receivedContent.link){
		const filename = receivedContent.link;
		const file = getCode.get(filename);
		if(!isValidUUIDv4(filename) || !file){
			res.json({ message: 'faild' });
			return;
		}
		refreshFile(filename);
		res.json({ message: 'success', link: getRoName(filename) });
		return;
	}else if(receivedContent.type == "read" && receivedContent.link){
		if(!isValidUUIDv4(receivedContent.link)){
			res.json({ message: 'faild' });
			return;
		}
		const filename = receivedContent.link;
		const file = getCode.get(filename);
		if(!fs.existsSync("cppfile/" + filename + "-unsave.cpp")){
			saveCode(receivedContent.code || "", filename, "savecpp-unsave");
			fs.writeFileSync("cppfile/" + filename + "-unsave.cpp", "");
		}
		if(!fs.existsSync("cppfile/" + filename + ".cpp")){
			saveCode(receivedContent.code || "", filename, "savecpp-cpponly");
			fs.writeFileSync("cppfile/" + filename + ".cpp", "");
		}
		if(!fs.existsSync("cppfile/" + filename + ".in")){
			saveCode(receivedContent.code || "", filename, "saveinput");
			fs.writeFileSync("cppfile/" + filename + ".in", "");
		}
		let ro = file?.readOnly;
		refreshFile(filename);
		res.json({ message: 'success', readOnly: ro, cppfile: fs.readFileSync("cppfile/" + filename + ".cpp", { encoding: 'utf-8' }), unsave_cppfile: fs.readFileSync("cppfile/" + filename + "-unsave.cpp", { encoding: 'utf-8' }), inputfile: fs.readFileSync("cppfile/" + filename + ".in", { encoding: 'utf-8' }) });
		return;
	}
	res.json({ message: 'faild' });
});
/*
main server
*/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
https server2
*/


// 设置上传目录路径
const UPLOADS_DIR = "uploads";

// 文件读取和路径安全处理
function getSafePath2(urlPath) {
	let safeUrlPath = decodeURIComponent(urlPath.split("?")[0]);
	let safePath = path.normalize(path.join(UPLOADS_DIR, safeUrlPath));
	if (!safePath.startsWith(UPLOADS_DIR) || safePath.includes('\0')) {
		return null; // 防止路径跳出上传目录
	}
	return safePath;
}

async function readFileAsync(filePath) {
	return fs.promises.readFile(filePath);
}

// 请求处理
async function requestHandler2(req, res) {
	try {
		// 解析 URL 并获取安全路径
		let safePath = getSafePath2(req.url);
		if (!safePath) {
			res.writeHead(403, { "Content-Type": "text/plain" });
			return res.end("403 Forbidden");
		}

		// 获取文件的 Content-Type

		// 读取请求的文件
		if (safePath.startsWith('uploads\\test-connect\\') || safePath == 'uploads\\test-connect') {
			try {
				res.writeHead(200, {
					"Cache-Control": "public, max-age=3600",
					"Content-Type": "text/html",
					"X-Content-Type-Options": "nosniff",
					"X-Frame-Options": "DENY",
					"Cross-Origin-Resource-Policy": "same-origin",
					"Content-Security-Policy": "sandbox"
				});
				return res.end();
			} catch (err) {
				res.writeHead(404, { "Content-Type": "text/plain" });
				return res.end("");
			}
		}else if (safePath.startsWith('uploads\\img\\download\\')) {
			safePath = safePath.replace(/^uploads\\img\\download\\/, 'uploads\\img\\');
			// 是以 /img/ 开头的路径
			try {
				let fileContent = await readFileAsync(safePath);
				res.writeHead(200, {
					"Cache-Control": "public, max-age=3600",
					"Content-Type": "application/octet-stream",
					"Content-Disposition": "attachment",
					"X-Content-Type-Options": "nosniff",
					"X-Frame-Options": "DENY",
					"Cross-Origin-Resource-Policy": "same-origin",
					"Content-Security-Policy": "sandbox"
				});
				return res.end(fileContent);
			} catch (err) {
				res.writeHead(404, { "Content-Type": "text/plain" });
				return res.end("");
			}
		}else if (safePath.startsWith('uploads\\img\\')) {
			// 是以 /img/ 开头的路径
			let contentType = mime.lookup(safePath) || "application/octet-stream";
			try {
				let fileContent = await readFileAsync(safePath);
				res.writeHead(200, {
					"Cache-Control": "public, max-age=3600",
					"Content-Type": contentType,
					"X-Content-Type-Options": "nosniff",
					"X-Frame-Options": "DENY",
					"Cross-Origin-Resource-Policy": "same-origin",
					"Content-Security-Policy": "sandbox"
				});
				return res.end(fileContent);
			} catch (err) {
				res.writeHead(404, { "Content-Type": "text/plain" });
				return res.end("");
			}
		}else if (safePath.startsWith('uploads\\allow-connect\\') || safePath == 'uploads\\allow-connect') {
			try {
				let fileContent = await readFileAsync("allow-connect.html");
				res.writeHead(200, {
					"Cache-Control": "public, max-age=3600",
					"Content-Type": "text/html",
					"X-Content-Type-Options": "nosniff",
					"X-Frame-Options": "DENY",
					"Cross-Origin-Resource-Policy": "same-origin",
					// "Content-Security-Policy": "sandbox"
				});
				return res.end(fileContent);
			} catch (err) {
				res.writeHead(404, { "Content-Type": "text/plain" });
				return res.end("");
			}
		}else if (safePath.startsWith('uploads\\download\\')){
			try {
				let fileContent = await readFileAsync(safePath);
				res.writeHead(200, {
					"Cache-Control": "public, max-age=3600",
					"Content-Type": "application/octet-stream",
					"Content-Disposition": "attachment",
					"X-Content-Type-Options": "nosniff",
					"X-Frame-Options": "DENY",
					"Cross-Origin-Resource-Policy": "same-origin",
					"Content-Security-Policy": "sandbox"
				});
				return res.end(fileContent);
			} catch (err) {
				res.writeHead(404, { "Content-Type": "text/plain" });
				return res.end("");
			}
		}else if (safePath.startsWith('uploads\\iofiles\\')){
			try {
				let fileContent = await readFileAsync(safePath);
				res.writeHead(200, {
					"Cache-Control": "public, max-age=3600",
					"Content-Type": "application/octet-stream",
					"Content-Disposition": "attachment",
					"X-Content-Type-Options": "nosniff",
					"X-Frame-Options": "DENY",
					"Cross-Origin-Resource-Policy": "same-origin",
					"Content-Security-Policy": "sandbox"
				});
				return res.end(fileContent);
			} catch (err) {
				res.writeHead(404, { "Content-Type": "text/plain" });
				return res.end("");
			}
		}else{
			// try {
			// 	let fileContent = await readFileAsync(safePath);
			// 	res.writeHead(200, {
			// 		"Cache-Control": "public, max-age=3600",
			// 		"Content-Type": "application/octet-stream",
			// 		"Content-Disposition": "attachment",
			// 		"X-Content-Type-Options": "nosniff",
			// 		"X-Frame-Options": "DENY",
			// 		// "Cross-Origin-Resource-Policy": "same-origin",
			// 		"Content-Security-Policy": "sandbox"
			// 	});
			// 	return res.end(fileContent);
			// } catch (err) {
			res.writeHead(404, { "Content-Type": "text/plain" });
			return res.end("");
			// }
		}
	} catch (err) {
		res.writeHead(500, { "Content-Type": "text/plain" });
		res.end("500 Internal Server Error");
	}
}

app.use("/uploads", async (req, res, next) => {
	// 处理 CORS
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
	res.setHeader('Access-Control-Allow-Headers', 'Content-Type, content-type');

	// 处理 OPTIONS 预检请求
	if (req.method === 'OPTIONS') {
		return res.status(204).end();
	}

	let ip = req.socket.remoteAddress.replace("::ffff:", "");
	const now = Date.now();
	fs.appendFileSync("log/ip.log", `${ip} ${now} ${(new Date()).toString()} server.file\n`);
	fs.appendFileSync("log/https-server2.log", `${ip} ${now} ${(new Date()).toString()} ${req.url}\n`);
	if (ban_list.some(user => user == ip) || ban_list2.some(user => user == ip)) {
		return res.status(403).end();
	}
	if(!isValidUsername(req.session.username)){
		res.status(401).json({ error: 'Unauthorized' });
		return;
	}

	await requestHandler2(req, res);
});

/*
https server2
*/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
文件上传
*/

// 设置文件存储路径
const storage = multer.diskStorage({
	destination: (req, file, cb) => {
		cb(null, './uploads/download'); // 设置上传文件的存储路径
	},
	filename: (req, file, cb) => {
		cb(null, (Date.now() + path.extname(Buffer.from(file.originalname, "base64").toString("utf-8")))); // 使用时间戳加扩展名设置文件名
	}//Buffer.from(file.originalname, "base64").toString("utf-8")
});

// 配置 multer
const upload = multer({
	storage: storage,
	limits: { fileSize: 5 * 1024 * 1024 }  // 限制文件大小为 5MB
});

// 上传文件路由
app.post('/upload', upload.single('file'), (req, res) => {
	// 如果文件上传成功，multer 会将文件信息保存在 req.file 中
	const receivedContent = JSON.parse(req.body.content);
	var ip=req.ip.replace("::ffff:", ""), rawip = ip;
	const now = Date.now();
	fs.appendFileSync("log/ip.log", `${ip} ${now} ${(new Date()).toString()} server.upload\n`);
	fs.appendFileSync("log/upload.log", `${ip} ${now} ${(new Date()).toString()}\n`);
	if(ban_list.some(user => user == ip) || ban_list2.some(user => user == ip)){
		return res.status(403).end();
	}
	if(/^[0-9]+(?:\.[0-9]+){3}$/.test(ip)){
		ip = ip.split(".");
		ip = ip[0].slice(0, ip[0].length - 1).replace(/\d/,"*").replace(/\d/,"*")+ip[0][ip[0].length - 1] + ".*.*." + ip[3].slice(0, ip[3].length - 1).replace(/\d/,"*").replace(/\d/,"*")+ip[3][ip[3].length - 1];
		// ip=ip[0].replace(/(.*)(.)/,"$1").replace(/\d/,"*").replace(/\d/,"*").replace(/\d/,"*")+ip[0].replace(/(.*)(.)/,"$2")+".*.*.*"+ip[3].replace(/(.*)(.)/,"$1").replace(/\d/,"*").replace(/\d/,"*").replace(/\d/,"*")+ip[3].replace(/(.*)(.)/,"$2");
	}
	if(!isValidUsername(req.session.username)){
		res.status(401).json({ error: 'Unauthorized' });
		return;
	}else if (req.file) {
		console.log(req.ip);
		console.log('收到的内容：');
		req.file.originalname = Buffer.from(req.file.originalname, "base64").toString("utf-8");
		receivedContent.filename = req.file.originalname;
		receivedContent.path = `${req.file.filename}`;
		receivedContent.info = "none";
		receivedContent.size = req.file.size;
		fs.appendFileSync("log/upload.log", `${JSON.stringify(receivedContent, null, 2)}\n`);
		receivedContent.ip = ip;
		fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
		data[0].chats.push(receivedContent);
		data[1].chats.push(rawip);
		res.send({message: 'success', chats: data[0].chats});
	} else {
		res.send({message: "faild", info: "no file"});
	}
});
/*
文件上传
*/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
图片上传
*/
const allowedMimeTypes = [
	'image/jpeg',   // jpg, jpeg
	'image/png',
	'image/webp',
	'image/bmp',
	'image/x-icon'  // .ico
];
const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp', '.bmp', '.ico'];
const uploadImg = multer({
	storage: multer.diskStorage({
		destination: (req, file, cb) => {
			cb(null, './uploads/img'); // 设置上传文件的存储路径
		},
		filename: (req, file, cb) => {
			cb(null, (Date.now() + path.extname(Buffer.from(file.originalname, "base64").toString("utf-8")))); // 使用时间戳加扩展名设置文件名
		}//Buffer.from(file.originalname, "base64").toString("utf-8")
	}),
	limits: { fileSize: 5 * 1024 * 1024 },
	fileFilter: (req, file, cb) => {
		const ext = path.extname(Buffer.from(file.originalname, "base64").toString("utf-8")).toLowerCase();
		const mime = file.mimetype;
		if (allowedMimeTypes.includes(mime) && allowedExtensions.includes(ext)) {
			cb(null, true);
		} else {
			cb(new Error('仅支持 jpg、png、webp、bmp、ico 图片文件'), false);
		}
	}
	});
app.post('/uploadimg', uploadImg.single('image'), (req, res) => {
	// 如果文件上传成功，multer 会将文件信息保存在 req.file 中
	const receivedContent = JSON.parse(req.body.content);
	var ip=req.ip.replace("::ffff:", ""), rawip = ip;
	const now = Date.now();
	fs.appendFileSync("log/ip.log", `${ip} ${now} ${(new Date()).toString()} server.upload\n`);
	fs.appendFileSync("log/upload-image.log", `${ip} ${now} ${(new Date()).toString()}\n`);
	if(ban_list.some(user => user == ip) || ban_list2.some(user => user == ip)){
		return res.status(403).end();
	}
	if(/^[0-9]+(?:\.[0-9]+){3}$/.test(ip)){
		ip = ip.split(".");
		ip = ip[0].slice(0, ip[0].length - 1).replace(/\d/,"*").replace(/\d/,"*")+ip[0][ip[0].length - 1] + ".*.*." + ip[3].slice(0, ip[3].length - 1).replace(/\d/,"*").replace(/\d/,"*")+ip[3][ip[3].length - 1];
		// ip=ip[0].replace(/(.*)(.)/,"$1").replace(/\d/,"*").replace(/\d/,"*").replace(/\d/,"*")+ip[0].replace(/(.*)(.)/,"$2")+".*.*.*"+ip[3].replace(/(.*)(.)/,"$1").replace(/\d/,"*").replace(/\d/,"*").replace(/\d/,"*")+ip[3].replace(/(.*)(.)/,"$2");
	}
	if(!isValidUsername(req.session.username)){
		res.status(401).json({ error: 'Unauthorized' });
		return;
	}
	console.log(receivedContent);
	if (req.file) {
		console.log(req.ip);
		console.log('收到的内容：');
		req.file.originalname = Buffer.from(req.file.originalname, "base64").toString("utf-8");
		receivedContent.filename = req.file.originalname;
		receivedContent.path = `${req.file.filename}`;
		receivedContent.info = "none";
		receivedContent.size = req.file.size;
		receivedContent.type = "image";
		fs.appendFileSync("log/upload.log", `${JSON.stringify(receivedContent, null, 2)}\n`);
		receivedContent.ip = ip;
		fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
		data[0].chats.push(receivedContent);
		data[1].chats.push(rawip);
		res.send({message: 'success', chats: data[0].chats});
	} else {
		res.send({message: "faild", info: "no file"});
	}
});
/*
图片上传
*/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
main https server
*/
const CLIENT_DIR = "html";
function getSafePath(urlPath) {
	let safeUrlPath = decodeURIComponent(urlPath.split("?")[0]);
	let safePath = path.normalize(path.join(CLIENT_DIR, safeUrlPath));
	if (!safePath.startsWith(CLIENT_DIR) || safePath.includes('\0')) {
		return null;
	}
	return safePath;
}

async function readFileAsync(filePath) {
	return fs.promises.readFile(filePath);
}
// 处理请求
async function requestHandler(req, res) {
	try {
		if (req.url.startsWith('/.ignore/') || req.url == '/.ignore') {
			res.writeHead(404, { "Content-Type": "text/plain" });
			return res.end("");
		}
		if (req.url === '/get.svg') {
			const svgContent = `
			<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="125" height="20">
				<rect x="0" y="0" width="125" height="20" style="fill-opacity:1.00; fill:rgb(90,90,90); padding: 2px 5px;"/>
				<rect x="0" y="0" width="80" height="20" style="fill-opacity:1.00; fill:rgb(49, 197, 83);"/>
				<text x="6" y="14" style="text-anchor:start;font-size:12px;fill:white;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif,Apple Color Emoji,Segoe UI Emoji;">Page Views</text>
				<text x="86" y="14" style="text-anchor:start;font-size:12px;fill:white;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif,Apple Color Emoji,Segoe UI Emoji;">${incrementCounter()}</text>
			</svg>`;
			fs.appendFileSync("log/get-svg.log", `${req.socket.remoteAddress.replace("::ffff:", "")} ${Date.now()} ${(new Date()).toString()}\n`);
			res.writeHead(200, {
				"Content-Type": "image/svg+xml",
			});
			return res.end(svgContent);
		}
		// 解析 URL 并获取安全路径
		let safePath = getSafePath(req.url);

		if (!safePath) {
			res.writeHead(403, { "Content-Type": "text/plain" });
			return res.end("403 Forbidden");
		}

		// 获取文件的 Content-Type
		let contentType = mime.lookup(safePath) || "application/octet-stream";
		if (!contentType || contentType === "application/octet-stream") {
			contentType = "text/html"; // 强制设为 HTML 以防止下载
		}
		try {
			// 读取请求的文件
			let fileContent = await readFileAsync(safePath);
			res.writeHead(200, {
				"Content-Type": contentType,
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
			return res.end(fileContent);
		} catch (err) {
			try {
				// 读取请求的文件
				let fileContent = await readFileAsync(safePath + '.html');
				res.writeHead(200, {
					"Content-Type": contentType,
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
				return res.end(fileContent);
			} catch (err) {
				try {
					// 读取请求的文件
					let fileContent = await readFileAsync(safePath + '/index.html');
					res.writeHead(200, {
						"Content-Type": contentType,
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
					return res.end(fileContent);
				} catch (err) {
					res.writeHead(404, { "Content-Type": "text/plain" });
					return res.end("");
				}
			}
		}
	} catch (err) {
		res.writeHead(500, { "Content-Type": "text/plain" });
		res.end("500 Internal Server Error");
	}
}

// 创建 HTTP 服务器
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
	let ip = req.socket.remoteAddress.replace("::ffff:", "");
	const now = Date.now();
	fs.appendFileSync("log/ip.log", `${ip} ${now} ${(new Date()).toString()} server.http\n`);
	fs.appendFileSync("log/https-server.log", `${ip} ${now} ${(new Date()).toString()} ${req.url}\n`);
	if(ban_list.some(user => user == ip) || ban_list2.some(user => user == ip)){
		res.writeHead(404, { "Content-Type": "text/plain" });
		return res.end("");
	}
	await requestHandler(req, res);
});

/*
main https server
*/

// 错误处理：文件大小超过限制时的响应
app.use((err, req, res, next) => {
	if (err instanceof multer.MulterError) {
		if (err.code === 'LIMIT_FILE_SIZE') {
			return res.send({message:'faild',info: 'File too big'});
		}
	}
		next(err); // 如果不是 `multer` 错误，继续传递错误
});

https.createServer(credentials, app).listen(port, () => {
	console.log(`服务器运行在: http://localhost:${port} && `);
	console.log(`main https server运行在: http://localhost:${port} && `);
	console.log(`https server2运行在: http://localhost:${port}`);
}).on('error', err => {
	if(err.code === 'EADDRINUSE'){
		console.log(`服务器启动失败: http://localhost:${port} && `);
		console.log(`main https server启动失败: http://localhost:${port} && `);
		console.log(`https server2启动失败: http://localhost:${port}`);
		fs.writeFileSync(`error/normal/error_${Date.now()}.log`, `Normal Error (${(new Date()).toString()})\nfrom: node.js\n${err}`);
		process.exit(1);
	}else{
		throw err;
	}
});

http.createServer((req, res) => {
	res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
	res.end();
}).listen(port_http, () => {
	console.log(`http 重定向服务器运行在: http://localhost:${port_http}`);
}).on('error', err => {
	if(err.code === 'EADDRINUSE'){
		console.log(`http 重定向服务器启动失败: http://localhost:${port_http}`);
		fs.writeFileSync(`error/normal/error_${Date.now()}.log`, `Normal Error (${(new Date()).toString()})\nfrom: node.js\n${err}`);
		process.exit(1);
	}else{
		throw err;
	}
});
