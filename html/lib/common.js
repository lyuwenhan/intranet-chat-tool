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
const isMob = /Mobi|Android|iPhone|iPad|iPod|Phone/i.test(navigator.userAgent);

function isValidUUIDv4(uuid) {
	const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
	return regex.test(uuid);
}

document.addEventListener('DOMContentLoaded', () => {
	let confirmResolve = null;
	let alert_chain = Promise.resolve();
	const alert_ele = document.querySelector(".alert-transmit"), alert_ok = document.querySelector(".alert-ok"), alert_cancel = document.querySelector('.alert-cancel'), alert_msgbox = document.querySelector(".alert-msgbox"), alert_input = document.querySelector(".alert-input");
	const mask = document.querySelector('.alert_ele-transblack');
	let alertMode = null;
	if(mask){
		mask.addEventListener('wheel', (e) => {e.preventDefault();}, { passive: false });
		mask.addEventListener('click', (e) => {e.preventDefault();}, { passive: false });
		mask.addEventListener('mousedown', (e) => {e.preventDefault();}, { passive: false });
		mask.addEventListener('mouseup', (e) => {e.preventDefault();}, { passive: false });
	}

	function Resolve(value) {
		if(!confirmResolve || !alertMode || (!value && alertMode == 1)){
			return;
		}
		const c = confirmResolve;
		confirmResolve = null;
		alertMode = null;
		alert_input.value = "";
		alert_msgbox.innerText = alert_ok.innerText = alert_cancel.innerText = "";
		alert_ele.hidden = alert_ok.hidden = alert_cancel.hidden = alert_input.hidden = true;
		c(value);
	}

	window.addEventListener("keydown", (e) => {
		if(!confirmResolve)return;
		if(e.key === "Enter" && alertMode){
			e.preventDefault();
			e.stopPropagation();
			if(alertMode == 3){
				Resolve(alert_input.value);
			}else{
				Resolve(true);
			}
		}else if(e.key === "Escape" && alertMode > 1){
			e.preventDefault();
			e.stopPropagation();
			Resolve(false);
		}
	}, true);

	alert_ok.addEventListener('click', function(e){
		if(confirmResolve && alertMode){
			if(alertMode == 3){
				Resolve(alert_input.value);
			}else{
				Resolve(true);
			}
			e.preventDefault();
			e.stopPropagation();
		}
	});
	alert_cancel.addEventListener('click', function(e){
		if(confirmResolve && alertMode > 1){
			Resolve(false);
			e.preventDefault();
			e.stopPropagation();
		}
	});

	function delay(time, ret){
		return new Promise(resolve => {
			setTimeout(()=>{resolve(ret)}, time);
		});
	}

	window.confirm = function confirm(message, okMSG = "OK", cancelMSG = "Cancel"){
		return alert_chain = alert_chain.then(()=>{
			return new Promise((resolve) => {
				alertMode = 2;
				if(message){
					alert_msgbox.innerText = message;
				}else{
					alert_msgbox.innerHTML = "<span class='nimportant'>Here is no message.</span>";
				}
				alert_ok.innerText = okMSG || "OK";
				alert_cancel.innerText = cancelMSG || "Cancel";
				alert_ele.hidden = alert_ok.hidden = alert_cancel.hidden = false;
				confirmResolve = (result) => {
					if(result === true || result === false){
						alertMode = null;
						alert_msgbox.innerText = alert_ok.innerText = alert_cancel.innerText = "";
						alert_ele.hidden = alert_ok.hidden = alert_cancel.hidden = true;
						resolve(result);
					}
				}
			}
		)}).then((r)=>delay(100,r)).catch(()=>{});
	}

	window.alert = function alert(message, okMSG = "OK"){
		return alert_chain = alert_chain.then(()=>{
			return new Promise((resolve) => {
				alertMode = 1;
				if(message){
					alert_msgbox.innerText = message;
				}else{
					alert_msgbox.innerHTML = "<span class='nimportant'>Here is no message.</span>";
				}
				alert_ok.innerText = okMSG || "OK";
				alert_ele.hidden = alert_ok.hidden = false;
				confirmResolve = () => {
					alertMode = null;
					alert_msgbox.innerText = alert_ok.innerText = "";
					alert_ele.hidden = alert_ok.hidden = true;
					resolve();
				}
			}
		)}).then((r)=>delay(100,r)).catch(()=>{});
	}

	window.prompt = function prompt(message, okMSG = "OK", cancelMSG = "Cancel"){
		return alert_chain = alert_chain.then(()=>{
			return new Promise((resolve) => {
				alertMode = 3;
				if(message){
					alert_msgbox.innerText = message;
				}else{
					alert_msgbox.innerHTML = "<span class='nimportant'>Here is no message.</span>";
				}
				alert_ok.innerText = okMSG || "Submit";
				alert_cancel.innerText = cancelMSG || "Cancel";
				alert_ele.hidden = alert_ok.hidden = alert_input.hidden = alert_cancel.hidden = false;
				confirmResolve = (result) => {
					alertMode = null;
					alert_msgbox.innerText = alert_ok.innerText = alert_cancel.innerText = "";
					alert_ele.hidden = alert_ok.hidden = alert_input.hidden = alert_cancel.hidden = true;
					alert_input.value = "";
					resolve(result);
				};
			}
		)}).then((r)=>delay(100,r)).catch(()=>{});
	}
});

if(isMob){
	window.jump = function(){
		location.href = '/login';
	}
}else{
	var jumping = 0;
	var jumptiout = null;
	var loging = false;
	let logto = null;
	window.jump = function(){
		if(loging){
			return;
		}
		if(logto){
			clearTimeout(logto);
		}
		loging = true;
		alert("Please login").then(()=>{
			if(isMob){
				location.href = '/login';
			}else{
				const win = window.open('/login', '_blank');
				if (win && !win.closed && typeof win.closed !== "undefined"){
					win.name = "from-open";
					if(logto){
						clearTimeout(logto);
					}
					logto = setTimeout(()=>{loging = false;logto = null;}, 60000);
				}
			}
		})
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