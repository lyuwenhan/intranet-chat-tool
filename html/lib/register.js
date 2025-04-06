'use strict';
function logout(){
	let inputContent = { type: "logout" };
	fetch(`https://${ip}/api/login`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(response => {
		return response.json();
	})
	.then(data => {
		console.log("服务器返回的数据：", data);
		if(data.message == "success"){
			location.reload();
		}
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
var username;
function get_key() {
	var ret = null;
	var inputContent = { type: "get-key", username };
	fetch(`https://${ip}/api`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(response => {
		return response.json();
	})
	.then(data => {
		publicKey = data;
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
function isValidIPv4(str) {
	if (str == null || str == undefined) {
		return false;
	}
	if(str === "localhost"){
		return true;
	}
	let parts = str.split(".");
	if (parts.length !== 4) {
		return false;
	}
	for (let part of parts) {
		if (!part.match(/^\d+$/)) {
			return false;
		}
		let num = parseInt(part, 10);
		if (num < 0 || num > 255) {
			return false;
		}
		if (part !== num.toString()) {
			return false;
		}
	}
	return true;
}
var ip = "";
var publicKey;
window.onload = async function () {
	let mayip="";
	if(isValidIPv4(window.location.hostname)){
		mayip = window.location.hostname;
	}
	ip = mayip;
	let inputContent = { type: "get-username" };
	fetch(`https://${ip}/api`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(response => {
		return response.json();
	})
	.then(data => {
		username = data;
	})
	.catch(error => {
		console.error('错误:', error);
	});
	if(!mayip){
		ip = prompt("请输入服务器ipv4", mayip);
		while (!isValidIPv4(ip)) {
			ip = prompt("请输入合法的服务器ipv4", mayip);
		}
	}
	let inputContent2 = { type: "get-username" };
	fetch(`https://${ip}/api`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent2 })
	})
	.then(response => {
		return response.json();
	})
	.then(data => {
		document.getElementById("username").innerText = username = data;
		if(data){
			location.href = '/';
			document.getElementById("logout").hidden = false;
		}else{
			document.getElementById("login").hidden = false;
		}
		get_key();
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
async function encryptWithOAEP(plainText, publicKeyPem) {
	// 1️⃣ 解析 PEM 格式公钥
	const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);

	// 2️⃣ 使用 `RSA-OAEP` 加密数据
	const encrypted = publicKey.encrypt(forge.util.encodeUtf8(plainText), "RSA-OAEP", {
		md: forge.md.sha256.create() // 采用 SHA-256 作为哈希
	});

	// 3️⃣ Base64 编码，方便传输
	return forge.util.encode64(encrypted);
}
const error_messageele = document.getElementById("error-message");
document.getElementById('login-form').addEventListener('submit', async function(e) {
	e.preventDefault();
	error_messageele.innerHTML = "";
	const username = e.target[0].value;
	const password = e.target[1].value;
	if(password != e.target[2].value){
		error_messageele.innerText = "两次密码不一样";
		return;
	}
	console.log(password);
	const encrypted = await encryptWithOAEP(password, publicKey);
	var inputContent = { type: "register", username, pwd: encrypted };
	fetch(`https://${ip}/api/login`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
		.then(response => {
			return response.json();
		})
		.then(data => {
			console.log('服务器返回的数据:', data)
			if(data.message == "success"){
				location.replace("/login");
			}else{
				error_messageele.innerText = data.info;
			}
		})
		.catch(error => {
			console.error('错误:', error);
		});
});