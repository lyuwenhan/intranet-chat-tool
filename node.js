const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const cors = require('cors');
const fs = require('fs');
const readline = require('readline');
const http = require('http');
const https = require('https');
const path = require('path');
const mime = require('mime-types');
const multer = require('multer');
const marked = require("marked");
const {"main-pwd": pwd, private_pwd} = to_json('keys/pwd.json');
const app = express();
const host = "0.0.0.0";
const port = 8080;
const port2 = 8081;
const { v4: uuidv4 } = require('uuid');
const { exec } = require('child_process');

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
/*
main server
*/
app.use(cors());
app.use(bodyParser.json());

const dataFilePath = './data/data.json', banFilePath = "./data/ban_list.json";
var waiting_clear=false;
var waiting=null;
const allow_clear = to_json('./data/config.json')["allow_clear"];
const ban_list = [];
var ban_list2 = to_json(banFilePath);
const ban_name = ["sb", "shabi", "dashabi", "shab", "shb", "sabi", "sab", "hundan"];
const ips = [];
var ip_count = [{}, {}];
const limcnt = 2;
const ip_tlimit = [1000, 60000];
const ip_cntlimit = [20, 700];
var data = [{chats : []}, {chats : []}];

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
setInterval(() => {
	const currentTime = Date.now();
	ip_count = [{}, {}];
	for(let i = 0; i < ips.length; i++) {
		for(let j = limcnt - 1; j >= 0; j--){
			if (currentTime - ips[i].time <= ip_tlimit[j]) {
				if(!ip_count[j][ips[i].ip]){
					ip_count[j][ips[i].ip] = 0;
				}
				ip_count[j][ips[i].ip]++;
			}else{
				// break;
			}
		}
	}
	while(ips.length && currentTime - ips[0].time >= ip_tlimit[limcnt]){
		ips.shift();
	}
	for(let j = 0; j < limcnt; j++){
		for(let ip in ip_count[j]) {
			ad = true;
			if(ip_count[j][ip] > ip_cntlimit[j] && !ban_list2.some(user => user == ip)){
				ban_list2.push(ip);
			}
		}
	}
	for(let i = 0; i < ips.length; i++) {
		if(ban_list2.some(user => user == ips[i].ip)){
			ips.splice(i, 1);
			i--;
			continue;
		}
	}
	for(let i = 0; i < data[1].chats.length; i++) {
		if(ban_list2.some(user => user == data[1].chats[i])){
			data[0].chats.splice(i, 1);
			data[1].chats.splice(i, 1);
			i--;
			continue;
		}
	}
	fs.writeFileSync(banFilePath, JSON.stringify(ban_list2, null, 2));
	fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
}, 100);

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
		// console.log("已拒绝");
		return { message: 'refuse' };
	}

	waiting_clear = true;
	let input = await getinput("clear (Y/n)");

	waiting_clear = false;
	if(input == 'y' || input == 'Y'){
		// console.log("已清空");
		data = [{ "chats": [] }, { "chats": [] }];
		fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
		return { message: 'success' };
	} else {
		// console.log("已拒绝");
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
app.post('/', (req, res) => {
	const receivedContent = req.body.content;
	var ip=req.ip.replace("::ffff:", ""), rawip = ip;
	// console.log(ips.size);w
	if(ban_list.some(user => user == ip)){
		console.log("banned ip:", ip)
		res.json({ message: 'ban' , chats: [{ type:"ban", ip:"???.???.???.???", info: "You're banned"}]});
		return;
	}
	if(ban_list2.some(user => user == ip)){
		console.log("banned ip:", ip)
		res.json({ message: 'ban' , chats: [{ type:"ban", ip:"???.???.???.???", info: "Don't do that! You're banned"}]});
		return;
	}
	const now = Date.now();
	fs.appendFile("log/ip.log", `${ip} ${now} server.main\n`, (err)=>{});
	ips.push({ip:ip, time:now});
	fs.appendFileSync("log/main.log", ip + ' ' + now + ' ' + JSON.stringify(receivedContent) + '\n');
	if(receivedContent.type == "check-name"){
		if(!isValidUsername(receivedContent.info)){
			res.json({ message: 'faild' });
			return;
		}
		res.json({ message: 'success' });
		return;
	}else{
		if(!isValidUsername(receivedContent.username)){
			res.json({ message: 'ban' , chats: [{ type:"ban", ip:"???.???.???.???", info: "Invalid Username"}]});
			return;
		}
	}
	console.log('收到的内容：');
	console.log("realip:", ip);
	if(/^[0-9]+(?:\.[0-9]+){3}$/.test(ip)){
		ip = ip.split(".");
		ip = ip[0].slice(0, ip[0].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[0][ip[0].length - 1] + ".*.*." + ip[3].slice(0, ip[3].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[3][ip[3].length - 1];
	}
	receivedContent.ip=ip;
	console.log(receivedContent);
	if(receivedContent.type == "send"){
		if(!receivedContent.info || receivedContent.info.replace(/\n+/g, "\n").trimStart().trimEnd() == ""){
			res.json({ message: 'faild' });
			return;
		}
		data[0].chats.push({username:receivedContent.username, info:receivedContent.info.replace(/\n+/g, "\n").trimStart().trimEnd(),ip:receivedContent.ip, type:"text"});
		data[1].chats.push(rawip);
		fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
		res.json({ message: 'success' , chats: data[0].chats});
		return;
	}else if(receivedContent.type == "send-code"){
		if(!receivedContent.info || receivedContent.info.replace(/\n+/g, "\n").trimStart().trimEnd() == ""){
			res.json({ message: 'faild' });
			return;
		}
		let js = {username:receivedContent.username, info:receivedContent.info.replace(/\n\n\n+/g, "\n\n").trimStart().trimEnd(),ip:receivedContent.ip, type:"code"};
		if(receivedContent.language){
			js.language = receivedContent.language;
			if(receivedContent.language == "markdown"){
				js.html = marked.parse(js.info);
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
	}else if(receivedContent.type == "get-key"){
		res.json(publicKey);
		return;
	}else if(receivedContent.type == "get-cleartype"){
		res.json(allow_clear);
		return;
	}else if(receivedContent.type == "command" && receivedContent.info == "/clear"){
		if(JSON.stringify(data[0]) === JSON.stringify({ chats: [] })){
			res.json({ message: 'faild', info: 'nothing to do' });
		}else if(allow_clear == -1){
			start_clear().then(result=>{
				res.json(result || { message: "Error: Empty response" });
			});
		}else if(allow_clear == 2 || (allow_clear == 1 && receivedContent.pwd && isValidCiphertext(receivedContent.pwd, privateKey, private_pwd) && sha256(decryptRSA(receivedContent.pwd, privateKey, private_pwd)) == pwd)){
			data = [{ "chats": [] }, { "chats": [] }];
			fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
			fs.rmSync("uploads", { recursive: true, force: true });
			fs.rmSync("./uploads/iofiles", { recursive: true, force: true });
			fs.rmSync("./judge/codes", { recursive: true, force: true });
			fs.rmSync("./judge/exefiles", { recursive: true, force: true });
			fs.rmSync("./judge/inputfiles", { recursive: true, force: true });
			fs.rmSync("./log", { recursive: true, force: true });
			fs.mkdirSync("./uploads/iofiles", { recursive: true });
			fs.mkdirSync("./judge/codes", { recursive: true });
			fs.mkdirSync("./judge/exefiles", { recursive: true });
			fs.mkdirSync("./judge/inputfiles", { recursive: true });
			fs.mkdirSync("./log", { recursive: true });
			// console.log("已清空");
			res.json({ message: 'success', chats: data[0].chats });
		}else{
			// console.log("已拒绝");
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

app.post('/cpp/', (req, res) => {
	const receivedContent = req.body.content;
	var ip=req.ip.replace("::ffff:", ""), rawip = ip;
	const now = Date.now();
	fs.appendFile("log/ip.log", `${ip} ${now} cpp.run\n`, (err)=>{});
	fs.appendFileSync("log/run.log", ip + ' ' + now + '\n' + receivedContent.code + '\n');
	if(ban_list.some(user => user == ip)){
		console.log("banned ip:", ip)
		res.json({ message: 'ban' , chats: [{ type:"ban", ip:"???.???.???.???", info: "You're banned"}]});
		return;
	}
	if(ban_list2.some(user => user == ip)){
		console.log("banned ip:", ip)
		res.json({ message: 'ban' , chats: [{ type:"ban", ip:"???.???.???.???", info: "Don't do that! You're banned"}]});
		return;
	}
	ips.push({ip:ip, time:now});
	console.log('收到的内容：');
	console.log("realip:", ip);
	if(/^[0-9]+(?:\.[0-9]+){3}$/.test(ip)){
		ip = ip.split(".");
		ip = ip[0].slice(0, ip[0].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[0][ip[0].length - 1] + ".*.*." + ip[3].slice(0, ip[3].length - 1).replace(/\d/g,"*").replace(/\d/g,"*")+ip[3][ip[3].length - 1];
	}
	receivedContent.ip=ip;
	console.log(receivedContent);
	if(receivedContent.type == "run-code"){
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
		fs.writeFileSync(cpp, receivedContent.code);
		fs.writeFileSync(input, (receivedContent.input ? receivedContent.input : ""));
		exec("judge\\judge.exe " + cpp + " " + input + " uploads/" + output + " uploads/" + errfile + " " + exefile + " 10000 128 1048576 -O2", (error, stdout, stderr) => {
			// if (error) {
			// 	res.json({ message: 'faild', stderr: error.message, stdout});
			// 	return;
			// }
			if (stderr) {
				// console.log(stderr);
				res.json({ message: 'faild', stdout, stderr});
				return;
			}
			if (stderr) {
				// console.error(`Stderr: ${stderr}`);
			}
			// console.log(`Output: ${stdout}`);
			var outsize, errsize;
			if(!fs.existsSync("uploads/" + output)){
				fs.writeFileSync("uploads/" + output, "");
			}
			if(!fs.existsSync("uploads/" + errfile)){
				fs.writeFileSync("uploads/" + errfile, "");
			}
			outsize = fs.statSync("uploads/" + output).size;
			errsize = fs.statSync("uploads/" + errfile).size;
			fs.rm(cpp, (err)=>{});
			fs.rm(input, (err)=>{});
			fs.rm(exefile, (err)=>{});
			res.json({ message: 'success', outsize, stdoutfile: output, stdout: readFirst("uploads/" + output), errsize, stderrfile: errfile, stderr: readFirst("uploads/" + errfile)});
		});
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
http server
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
				"Content-Disposition": "inline"
			});
			return res.end(fileContent);
		} catch (err) {
			try {
				// 读取请求的文件
				let fileContent = await readFileAsync(safePath + '/index.html');
				res.writeHead(200, {
					"Content-Type": contentType,
					"Cache-Control": "public, max-age=3600",
					"Content-Disposition": "inline"
				});
				return res.end(fileContent);
			} catch (err) {
				// 文件不存在，返回 index.html（SPA 支持）
				let fallbackPath = path.join(CLIENT_DIR, "404.html");
				try {
					let fallbackContent = await readFileAsync(fallbackPath);
					res.writeHead(200, { "Content-Type": "text/html" });
					return res.end(fallbackContent);
				} catch (fallbackErr) {
					res.writeHead(404, { "Content-Type": "text/plain" });
					return res.end();
				}
			}
		}
	} catch (err) {
		res.writeHead(500, { "Content-Type": "text/plain" });
		res.end("500 Internal Server Error");
	}
}

// 创建 HTTP 服务器
const server = http.createServer(async (req, res) => {
	// 处理 CORS
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
	res.setHeader('Access-Control-Allow-Headers', 'Content-Type, content-type');
	// 处理 OPTIONS 预检请求
	if (req.method === 'OPTIONS') {
		res.writeHead(204);
		return res.end();
	}
	let ip = req.socket.remoteAddress;
	const now = Date.now();
	fs.appendFile("log/ip.log", `${ip} ${now} server.http\n`, (err)=>{});
	if(ban_list.some(user => user == ip)){
		console.log("banned ip:", ip)
		res.end(JSON.stringify({ message: 'Access denied' }));
		return;
	}
	if(ban_list2.some(user => user == ip)){
		console.log("banned ip:", ip)
		res.end(JSON.stringify('Access denied'));
		return;
	}
	await requestHandler(req, res);
});

// 启动服务器
server.listen(8000, host, () => {
	console.log(`http server 运行在: http://localhost:8000`);
});

/*
http server
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
https server
*/

const credentials = { key: fs.readFileSync("keys/key.pem", 'utf8'), cert: fs.readFileSync("keys/cert.pem", 'utf8') };

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
		let contentType = mime.lookup(safePath) || "application/octet-stream";

		// 读取请求的文件
		try {
			let fileContent = await readFileAsync(safePath);
			res.writeHead(200, {
				"Content-Type": contentType,
				"Cache-Control": "public, max-age=3600" // 1 小时缓存
			});
			return res.end(fileContent);
		} catch (err) {
			res.writeHead(404, { "Content-Type": "text/plain" });
			return res.end();
		}
	} catch (err) {
		res.writeHead(500, { "Content-Type": "text/plain" });
		res.end("500 Internal Server Error");
	}
}

// 创建 HTTPS 服务器
const server2 = https.createServer(credentials, async (req, res) => {
	// 处理 CORS
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
	res.setHeader('Access-Control-Allow-Headers', 'Content-Type, content-type');

	// 处理 OPTIONS 预检请求
	if (req.method === 'OPTIONS') {
		res.writeHead(204);
		return res.end();
	}

	let ip = req.socket.remoteAddress;
	const now = Date.now();
	fs.appendFile("log/ip.log", `${ip} ${now} server.file\n`, (err)=>{});
	// 假设你有一个 ban_list（黑名单）检查 IP
	if (ban_list.some(user => user == ip)) {
		console.log("banned ip:", ip)
		res.end(JSON.stringify({ message: 'Access denied5' }));
		return;
	}
	if (ban_list2.some(user => user == ip)) {
		console.log("banned ip:", ip)
		res.end(JSON.stringify('Access denied6'));
		return;
	}

	await requestHandler2(req, res);
});

// 启动 HTTPS 服务器
server2.listen(port2, host, () => {
	console.log(`https server 运行在: https://localhost:${port2}`);
});

/*
https server
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
		cb(null, './uploads'); // 设置上传文件的存储路径
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
	fs.appendFile("log/ip.log", `${ip} ${now} server.upload\n`, (err)=>{});
	if(ban_list.some(user => user == ip)){
		console.log("banned ip:", ip)
		res.json({ message: 'ban' , chats: [{ type:"ban", ip:"???.???.???.???", info: "You're banned"}]});
		return;
	}
	if(ban_list2.some(user => user == ip)){
		console.log("banned ip:", ip)
		res.json({ message: 'ban' , chats: [{ type:"ban", ip:"???.???.???.???", info: "Don't do that! You're banned"}]});
		return;
	}
	ips.push({ip:ip, time:Date.now()});
	if(/^[0-9]+(?:\.[0-9]+){3}$/.test(ip)){
		ip = ip.split(".");
		ip = ip[0].slice(0, ip[0].length - 1).replace(/\d/,"*").replace(/\d/,"*")+ip[0][ip[0].length - 1] + ".*.*." + ip[3].slice(0, ip[3].length - 1).replace(/\d/,"*").replace(/\d/,"*")+ip[3][ip[3].length - 1];
		// ip=ip[0].replace(/(.*)(.)/,"$1").replace(/\d/,"*").replace(/\d/,"*").replace(/\d/,"*")+ip[0].replace(/(.*)(.)/,"$2")+".*.*.*"+ip[3].replace(/(.*)(.)/,"$1").replace(/\d/,"*").replace(/\d/,"*").replace(/\d/,"*")+ip[3].replace(/(.*)(.)/,"$2");
	}
	console.log(receivedContent);
	if (req.file) {
		ips.push({ip:ip, time:Date.now()});
		console.log(req.ip);
		console.log('收到的内容：');
		// isValidCiphertext(receivedContent.pwd, privateKey, private_pwd) && sha256(decryptRSA(receivedContent.pwd, privateKey, private_pwd)) == pwd
		req.file.originalname = Buffer.from(req.file.originalname, "base64").toString("utf-8");
		receivedContent.filename = req.file.originalname;
		receivedContent.path = `${req.file.filename}`;
		receivedContent.ip = ip;
		receivedContent.info = "none";
		receivedContent.size = req.file.size;
		console.log(receivedContent);
		console.log(req.file);
		fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
		data[0].chats.push(receivedContent);
		data[1].chats.push(rawip);
		res.send({message: 'success', chats: data[0].chats});
  	} else {
		res.send({message: "faild", info: "no file"});
  	}
});

// 错误处理：文件大小超过限制时的响应
app.use((err, req, res, next) => {
	if (err instanceof multer.MulterError) {
		if (err.code === 'LIMIT_FILE_SIZE') {
			return res.send({message:'faild',info: 'File too big'});
		}
	}
  	next(err); // 如果不是 `multer` 错误，继续传递错误
});


app.listen(port, host, () => {
	console.log(`服务器运行在: http://localhost:${port}`);
}).on('error', err => {
	console.error('启动失败:', err);
});
/*
文件上传
*/