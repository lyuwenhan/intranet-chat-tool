/*
 * Project: Intranet Chat Tool
 * Copyright (C) 2025 lyuwenhan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

'use strict';
async function safeFetch(url, options = {}) {
	const res = await fetch(url, options);
	if (res.status === 401) {
		const win = window.open('/login', '_blank');
		if (!win || win.closed || typeof win.closed === "undefined") {
			window.name="from-href";
			location.href='/login';
			return null;
		}else{
			 win.name = 'from-open';
		}
		throw new Error('未登录，跳转中...');
	}
	return res;
}
function logout(){
	let inputContent = { type: "logout" };
	safeFetch(`https://${ip}/api/login`, {
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
	safeFetch(`https://${ip}/api`, {
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
const captchaele = document.getElementById("captcha-img");
var getCaptchaSuc = false;
captchaele.onclick = getCaptcha;
function getCaptcha(){
	captchaele.src = "/api/captcha?" + Date.now();
	getCaptchaSuc = false;
	captchaele.onload = ()=>{
		getCaptchaSuc = true;
	}
	captchaele.onerror = function(){
		this.onerror = null;
		this.src = 'data:image/svg+xml;charset=utf-8,%3Csvg%20style%3D%22font-family%3A%20ui-monospace%2C%20SFMono-Regular%2C%20SF%20Mono%2C%20Menlo%2C%20Consolas%2C%20Liberation%20Mono%2C%20monospace%3B%22%20width%3D%22300%22%20height%3D%22100%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%3E%0A%09%3Crect%20width%3D%22100%25%22%20height%3D%22100%25%22%20fill%3D%22%23f1f1f1%22/%3E%0A%09%3Ctext%20x%3D%2250%25%22%20y%3D%2250%25%22%20dominant-baseline%3D%22middle%22%20text-anchor%3D%22middle%22%20font-size%3D%2270%22%20fill%3D%22%23000000%22%3E%E8%8E%B7%E5%8F%96%E5%A4%B1%E8%B4%A5%3C/text%3E%0A%3C/svg%3E';
	}
}
const error_messageele = document.getElementById("error-message");
document.getElementById('login-form').addEventListener('submit', async function(e) {
	e.preventDefault();
	error_messageele.innerHTML = "";
	const username = e.target[0].value;
	const password = e.target[1].value;
	if(password != e.target[2].value){
		error_messageele.innerText = "Password must be the same";
		return;
	}
	if(password.length < 8){
		error_messageele.innerText = "Password too short";
		return;
	}
	const captcha = e.target[3].value;
	if(!captcha){
		error_messageele.innerText = "Enter the capcha";
		return;
	}
	const encrypted = await encryptWithOAEP(password, publicKey);
	var inputContent = { type: "register", username, pwd: encrypted, captcha };
	safeFetch(`https://${ip}/api/login`, {
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

document.addEventListener("DOMContentLoaded", async () => {
	let mayip="";
	if(isValidIPv4(window.location.hostname)){
		mayip = window.location.hostname;
	}
	ip = mayip;
	if(!mayip){
		ip = prompt("Please enter server ipv4", mayip);
		while (!isValidIPv4(ip)) {
			ip = prompt("Enter a valid server ipv4 address", mayip);
		}
	}
	let inputContent = { type: "command", info: "/testadmin" };
	safeFetch(`https://${ip}/api`, {
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
		if(data.message === "success"){
			document.getElementById("bt-manage").hidden = false;
		}
		let inputContent = { type: "get-username" };
		safeFetch(`https://${ip}/api`, {
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
			document.getElementById("username").innerText = username = data;
			if(data){
				location.href = '/';
				document.getElementById("logout").hidden = false;
			}else{
				document.getElementById("login").hidden = false;
				document.getElementById("sign_up").hidden = false;
			}
			get_key();
		})
		.catch(error => {
			console.error('错误:', error);
		});
		getCaptcha();
	});
});