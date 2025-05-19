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
	.then(async(blob)=>JSON.parse(await blob.text()))
	.then(data => {
		publicKey = data;
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
var publicKey;
async function encryptWithOAEP(plainText, publicKeyPem) {
	const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
	const encrypted = publicKey.encrypt(forge.util.encodeUtf8(plainText), "RSA-OAEP", {
		md: forge.md.sha256.create()
	});
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
document.getElementById('change-password-form').addEventListener('submit', async function(e) {
	e.preventDefault();
	error_messageele.innerHTML = "";
	const username = e.target[0].value;
	const password = e.target[1].value;
	const npassword = e.target[2].value;
	if(npassword != e.target[3].value){
		error_messageele.innerText = "New password must be the same";
		return;
	}
	if(npassword.length < 8){
		error_messageele.innerText = "Password too short";
		return;
	}
	const captcha = e.target[4].value;
	if(!captcha){
		error_messageele.innerText = "Enter the capcha";
		return;
	}
	const encrypted = await encryptWithOAEP(password, publicKey);
	const encrypted2 = await encryptWithOAEP(npassword, publicKey);
	var inputContent = { type: "change-pwd", username, pwd: encrypted, npwd: encrypted2, captcha };
	console.log(inputContent);
	safeFetch(`/api/login`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(async(blob)=>JSON.parse(await blob.text()))
	.then(data => {
		console.log('服务器返回的数据:', data)
		if(data.message == "success"){
			if(window.name === 'from-open'){
				window.close();
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
	.then(async(blob)=>JSON.parse(await blob.text()))
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
		.then(async(blob)=>JSON.parse(await blob.text()))
		.then(data => {
			document.getElementById("username").innerText = username = data;
			if(data){
				document.querySelectorAll(".gout").forEach(e=>{e.hidden = false});
			}else{
				document.querySelectorAll(".gin").forEach(e=>{e.hidden = false});
				if(window.name === 'from-open'){
					window.close();
				}else{
					location.href='/';
				}
			}
			get_key();
		})
		.catch(error => {
			console.error('错误:', error);
		});
		getCaptcha();
	});
});