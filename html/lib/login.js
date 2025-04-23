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
async function safeFetch(url, options = {}, isBlob = false) {
	const res = await fetch(url, options);
	if (res.status === 401) {
		const win = window.open('/login', '_blank');
		if (!win || win.closed || typeof win.closed === "undefined") {
			window.name="from-href";
			location.href='/login';
			return {};
		}else{
		 	win.name = 'from-open';
		}
		throw new Error('未登录，跳转中...');
		return {};
	}
	if(res.status === 429){
		throw new Error("访问过量");
	}
	if(!isBlob){
		let data;
		try{
			data = await res.json();
		}catch (err){
			console.error(res);
			throw new Error("返回的不是合法 JSON 格式");
		}
		if(res.status === 403){
			if(data.info == 'not admin'){
				location.replace('/');
				throw new Error("权限错误");
			}
			throw new Error("banned");
		}
		if (!res.ok){
			throw new Error("fetch fault");
		}
		return data;
	}else{
		try {
			if (!res.ok){
				throw new Error("fetch fault");
			}
			const result = await res.blob();
			return result;
		} catch (err) {
			console.error(err);
			throw new Error("Blob 解码失败");
		}
	}
}
function logout(){
	let inputContent = { type: "logout" };
	safeFetch(`/api/login`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
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
	var inputContent = { type: "get-key" };
	safeFetch(`/api`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(data => {
		publicKey = data;
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
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
const error_messageele = document.getElementById("error-message");
document.getElementById('login-form').addEventListener('submit', async function(e) {
	e.preventDefault();
	error_messageele.innerHTML = "";
	const username = e.target[0].value;
	const password = e.target[1].value;
	const encrypted = await encryptWithOAEP(password, publicKey);
	var inputContent = { type: "login", username, pwd: encrypted };
	safeFetch(`/api/login`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(data => {
		console.log('服务器返回的数据:', data)
		if(data.message == "success"){
			if(window.name === 'from-open'){
				window.close();
			}else if(window.name === 'from-href'){
				window.name = "";
				history.back();
			}else{
				location.href='/';
			}
		}else{
			error_messageele.innerText = data.info;
		}
	})
	.catch(error => {
		console.error('错误:', error);
	});
});

var role = 'user';
document.addEventListener("DOMContentLoaded", () => {
	let inputContent = { type: "get-role" };
	safeFetch(`/api/manage`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(data => {
		role = data;
		if(roleToNum[data] > 1){
			document.getElementById("bt-manage").hidden = false;
		}
		let inputContent = { type: "get-username" };
		safeFetch(`/api`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({ content: inputContent })
		})
		.then(data => {
			document.getElementById("username").innerText = username = data;
			if(data){
				if(window.name === 'from-open'){
					window.close();
				}else if(window.name === 'from-href'){
					window.name = "";
					history.back();
				}else{
					location.href='/';
				}
				document.getElementById("logout").hidden = false;
				document.getElementById("changePwd").hidden = false;
			}else{
				document.getElementById("login").hidden = false;
				document.getElementById("sign_up").hidden = false;
			}
			get_key();
		})
		.catch(error => {
			console.error('错误:', error);
		});
	});
});
const roles = Object.freeze(["user", "editor", "admin", "founder"]);
const editors = Object.freeze(["editor", "admin", "founder"]);
const roleToNum = Object.freeze({"user": 1, "editor": 2, "admin": 3, "founder": 4});