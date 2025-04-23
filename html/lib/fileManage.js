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
	safeFetch(`https://${ip}/api/login`, {
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
function isValidUUIDv4(uuid) {
	const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
	return regex.test(uuid);
}
function isValidUsername(username){
	return username && username.length <= 20 && /^\w+$/.test(username);
}
function get_key(){
	let inputContent = { type: "get-key" };
	safeFetch(`https://${ip}/api`, {
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
var ip = "", username = "";
async function encryptWithOAEP(plainText, publicKeyPem) {
	const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
	const encrypted = publicKey.encrypt(forge.util.encodeUtf8(plainText), "RSA-OAEP", {
		md: forge.md.sha256.create() // 采用 SHA-256 作为哈希
	});
	return forge.util.encode64(encrypted);
}
const mainele = document.querySelector(".main");
const tableBody = document.querySelector('#codeTable tbody');
function getCodeList() {
	let inputContent = {
		type: "getList",
	};
	safeFetch(`https://${ip}/cpp-save`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(data => {
		console.log(data);
		if(!data[0]){
			return;
		}
		tableBody.innerHTML = '';
		data.forEach((code, index) => {
			const updated = new Date(code.updated_at).toLocaleString('CA', {
				year: 'numeric',
				month: '2-digit',
				day: '2-digit',
				hour: '2-digit',
				minute: '2-digit',
				second: '2-digit'
			});

			const row = document.createElement('tr');
			row.innerHTML = `
				<td class="show0"><a href="/codeEditor?uuid=${code.uuid}" class="bt-grey">${code.filename}.cpp</a><span class="show1 can-click bt-grey" title="click to copy" onclick="copy(null, '${code.uuid}', alert('copied'))">uuid:${code.uuid}</span></td>
				<td>${updated}</td>
				<td><button onclick="renameCode('${code.uuid}')" class="bt-red">Rename</button>&nbsp;<button onclick="deleteCode('${code.filename}', '${code.uuid}')" class="bt-red">Delete</button></td>
			`;
			tableBody.appendChild(row);
		});
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
function deleteCode(filename, uuid) {
	if (confirm(`Are you sure you want to delete the file "${filename}.cpp"?`)) {
		let inputContent = { type: "delete", link: uuid };
		safeFetch(`https://${ip}/cpp-save`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({ content: inputContent })
		})
		.then(data => {
			console.log("服务器返回的数据:", data);
			if(data.message == 'success'){
				location.reload();
			}
		})
		.catch(error => {
			console.error('错误:', error);
		});
	}
}
function renameCode(uuid) {
	const filename = prompt("New file name");
	if(!filename){
		return;
	}
	let inputContent = { type: "rename", link: uuid, filename };
	safeFetch(`https://${ip}/cpp-save`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(data => {
		console.log("服务器返回的数据:", data);
		if(data.message == 'success'){
			location.reload();
		}
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
function copy(me, text, func){
	var textArea = document.createElement("textarea");
	textArea.value = text;
	textArea.style.top = "0";
	textArea.style.left = "0";
	textArea.style.position = "fixed";
	document.body.appendChild(textArea);
	textArea.focus();
	textArea.select();
	try {
		var successful = document.execCommand('copy');
		var msg = successful ? 'successful' : 'unsuccessful';
	} catch (err) {
	}
	document.body.removeChild(textArea);
	if(me){
		if(me.tiout){
			clearTimeout(me.tiout);
		}
		me.lastChild.hidden = false;
		me.tiout = setTimeout(()=>{
			me.lastChild.hidden = true;
			me.tiout = null;
		}, 1000)
	}
	if(func){
		func();
	}
}

var role = 'user';
document.addEventListener("DOMContentLoaded", () => {
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
	let inputContent = { type: "get-role" };
	safeFetch(`https://${ip}/api/manage`, {
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
		safeFetch(`https://${ip}/api`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({ content: inputContent })
		})
		.then(data => {
			document.getElementById("username").innerText = username = data;
			if(data){
				document.getElementById("logout").hidden = false;
				document.getElementById("changePwd").hidden = false;
			}else{
				document.getElementById("login").hidden = false;
				document.getElementById("sign_up").hidden = false;
				window.name="from-href";
				location.href='/login';
			}
			getCodeList();
			// get_key();
		})
		.catch(error => {
			console.error('错误:', error);
		});
	});
});
const roles = Object.freeze(["user", "editor", "admin", "founder"]);
const editors = Object.freeze(["editor", "admin", "founder"]);
const roleToNum = Object.freeze({"user": 1, "editor": 2, "admin": 3, "founder": 4});