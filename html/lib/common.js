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
const roles = Object.freeze(["user", "editor", "admin", "founder"]);
const editors = Object.freeze(["editor", "admin", "founder"]);
const roleToNum = Object.freeze({"user": 1, "editor": 2, "admin": 3, "founder": 4});

document.addEventListener('DOMContentLoaded', () => {
	let confirmResolve = null;
	let alert_chain = Promise.resolve();
	const alert_ele = document.querySelector(".alert-transmit"), alert_ok = document.querySelector(".alert-ok"), alert_cancel = document.querySelector('.alert-cancel'), alert_msgbox = document.querySelector(".alert-msgbox");
	const mask = document.querySelector('.alert_ele-transblack');
	if(mask){
		mask.addEventListener('wheel', (e) => {e.preventDefault();}, { passive: false });
		mask.addEventListener('click', (e) => {e.preventDefault();}, { passive: false });
		mask.addEventListener('mousedown', (e) => {e.preventDefault();}, { passive: false });
		mask.addEventListener('mouseup', (e) => {e.preventDefault();}, { passive: false });
		mask.addEventListener('mouseleave', (e) => {e.preventDefault();}, { passive: false });
	}
	alert_ok.addEventListener('click', function(){
		if(confirmResolve){
			confirmResolve(true);
			confirmResolve = null;
		}
	});
	alert_cancel.addEventListener('click', function(){
		if(confirmResolve){
			confirmResolve(false);
			confirmResolve = null;
		}
	});

	window.confirm = function confirm(message){
		alert_msgbox.innerText = message || "";
		alert_ele.hidden = alert_ok.hidden = alert_cancel.hidden = false;
		const pro = new Promise((resolve) => {
			confirmResolve = (result) => {
				if(result === true || result === false){
					alert_ele.hidden = alert_ok.hidden = alert_cancel.hidden = true;
					resolve(result);
				}
			};
		});
		alert_chain = alert_chain.then(()=>pro).catch(()=>{});
		return pro;
	}

	window.alert = function alert(message){
		alert_msgbox.innerText = message || "";
		alert_ele.hidden = alert_ok.hidden = false;
		const pro = new Promise((resolve) => {
			confirmResolve = () => {
				alert_ele.hidden = alert_ok.hidden = true;
				resolve();
			};
		});
		alert_chain = alert_chain.then(()=>pro).catch(()=>{});
		return pro;
	}
});

var jumping = 0;
var jumptiout = null;
function jump(){
	if(jumping == 2){
		return;
	}
	if(jumptiout){
		clearTimeout(jumptiout);
	}
	const win = window.open('/login', '_blank');
	if (!win || win.closed || typeof win.closed === "undefined") {
		jumping = 1;
		jumptiout = setTimeout(function(){
			window.name="from-href";
			location.href='/login';
			jumping = 2;
			jumptiout = setTimeout(function(){
				jumping = 0;
				jumptiout = null;
			}, 5000);
		}, 200);
		return;
	}else{
		jumping = 2;
		win.name = 'from-open';
		jumptiout = setTimeout(function(){
			jumping = 0;
			jumptiout = null;
		}, 5000);
	}
}
async function safeFetch(url, options = {}) {
	const res = await fetch(url, options);
	if (res.status === 401) {
		jump();
		throw new Error('未登录，跳转中...');
	}
	if(res.status === 429){
		throw new Error("访问过量");
	}
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
function logout(){
	let inputContent = { type: "logout" };
	safeFetch(`/api/login`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(async(blob)=>JSON.parse(await blob.text()))
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