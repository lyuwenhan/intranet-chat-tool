const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const cors = require('cors');
const fs = require('fs');
const readline = require('readline');
const { message } = require('statuses');
const path = require('path');
const pwd = to_json('keys/pwd.json')["main-pwd"];
const private_pwd = to_json('keys/pwd.json')["private-pwd"];
const app = express();
const port = 8080;
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

app.use(cors());
app.use(bodyParser.json());

const dataFilePath = './data/data.json', banFilePath = "./data/ban_list.json";
var waiting_clear=false;
var waiting=null;
const need_ask = false, allow_clear = 1;
// const ban_list = ["192.168.10.100"];
const ban_list = ["192.168.10.236"];
var ban_list2 = [];
const ban_name = ["sb", "shabi", "dashabi", "shab", "shb", "sabi", "sab", "hundan"];
const ips = [];
var ip_count = [{}, {}, {}, {}, {}];
const ip_tlimit = [1000, 60000];
const ip_cntlimit = [30, 1400];
var data = [{chats : []}, {chats : []}];

// 1. 生成密钥对
const { publicKey, privateKey } = generateKeyPairRSA(2048, private_pwd);//

if (fs.existsSync(dataFilePath)) {
	data = to_json(dataFilePath);
	if(!data){
		rawData = "[{}, {}]";
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
	ip_count = {};

	for(let i = 0; i < ips.length; i++) {
		if (currentTime - ips[i].time <= ip_tlimit[0]) {
			if(!ip_count[ips[i].ip]){
				ip_count[ips[i].ip] = 0;
			}
			ip_count[ips[i].ip]++;
		}
	}
	for(let ip in ip_count) {
		if(ip_count[ip] > ip_cntlimit[0] && !ban_list2.some(user => user == ip)){
			ban_list2.push(ip);
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
}, 1000);

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
		return { message: 'sucsess' };
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
	ips.push({ip:ip, time:Date.now()});
	// console.log(ips.size);
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
	if(receivedContent.type == "check-name"){
		if(!isValidUsername(receivedContent.info)){
			res.json({ message: 'faild' });
			return;
		}
		res.json({ message: 'sucsess' });
		return;
	}else{
		if(!isValidUsername(receivedContent.username)){
			res.json({ message: 'ban' , chats: [{ type:"ban", ip:"???.???.???.???", info: "access denied"}]});
			return;
		}
	}
	console.log('收到的内容：');
	console.log("realip:", ip);
	if(/^[0-9]+(?:\.[0-9]+){3}$/.test(ip)){
		ip = ip.split(".");
		ip = ip[0].slice(0, ip[0].length - 1).replace(/\d/,"*").replace(/\d/,"*")+ip[0][ip[0].length - 1] + ".*.*." + ip[3].slice(0, ip[3].length - 1).replace(/\d/,"*").replace(/\d/,"*")+ip[3][ip[3].length - 1];
		// ip=ip[0].replace(/(.*)(.)/,"$1").replace(/\d/,"*").replace(/\d/,"*").replace(/\d/,"*")+ip[0].replace(/(.*)(.)/,"$2")+".*.*.*"+ip[3].replace(/(.*)(.)/,"$1").replace(/\d/,"*").replace(/\d/,"*").replace(/\d/,"*")+ip[3].replace(/(.*)(.)/,"$2");
	}
	receivedContent.ip=ip;
	console.log(receivedContent);
	if(receivedContent.type == "send"){
		if(receivedContent.info.replace(/\s+/,"") == ""){
			res.json({ message: 'faild' });
			return;
		}
		data[0].chats.push({username:receivedContent.username, info:receivedContent.info.trimEnd(),ip:receivedContent.ip, type:"text"});
		data[1].chats.push(rawip);
	}else if(receivedContent.type == "send-code"){
		if(receivedContent.info.replace(/\s+/,"") == ""){
			res.json({ message: 'faild' });
			return;
		}
		let js = {username:receivedContent.username, info:receivedContent.info.trimEnd(),ip:receivedContent.ip, type:"code"};
		if(receivedContent.language){
			js.language = receivedContent.language;
		}
		data[0].chats.push(js);
		data[1].chats.push(rawip);
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
			console.log("no");
			res.json({ message: 'faild', info: 'nothing to do' });
		}else if(need_ask){
			start_clear().then(result=>{
				res.json(result || { message: "Error: Empty response" });
			});
		}else if(allow_clear == 2 || (allow_clear == 1 && receivedContent.pwd && isValidCiphertext(receivedContent.pwd, privateKey, private_pwd) && sha256(decryptRSA(receivedContent.pwd, privateKey, private_pwd)) == pwd)){
			data = [{ "chats": [] }, { "chats": [] }];
			fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
			// console.log("已清空");
			res.json({ message: 'sucsess' });
		}else{
			// console.log("已拒绝");
			res.json({ message: 'refuse' });
		}
		return;
	}
	fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
	res.json({ message: 'sucsess' });
});

app.listen(port, "0.0.0.0", () => {
	console.log(`服务器运行在 http://localhost:${port}`);
}).on('error', err => {
	console.error('启动失败:', err);
});