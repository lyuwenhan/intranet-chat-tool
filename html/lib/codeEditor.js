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
function isValidUUIDv4(uuid) {
	const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
	return regex.test(uuid);
}
function isValidUsername(username){
	return username && username.length <= 20 && /^\w+$/.test(username);
}
var usp = new URLSearchParams(window.location.search);
function getParam(param) {
	return usp.get(param);
}
function setParam(param, lang){
	usp.set(param, lang);
	window.location.search = usp.toString();
}
if(!isValidUUIDv4(getParam("uuid"))){
	setParam("uuid", uuid.v4());
}
const link = getParam("uuid");
function formatSize(bytes) {
	const units = ['B', 'KB', 'MB', 'GB', 'TB'];
	let unitIndex = 0;

	while (bytes >= 1024 * 0.75 && unitIndex < units.length - 1) {
		bytes /= 1024;
		unitIndex++;
	}

	return `${bytes.toFixed(2)} ${units[unitIndex]}`;
}
function get_key() {
	let inputContent = { type: "get-key" };
	safeFetch(`https://${ip}:`, {
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
window.onload = function () {
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
				document.getElementById("logout").hidden = false;
			}else{
				document.getElementById("login").hidden = false;
				document.getElementById("sign_up").hidden = false;
				window.name="from-href";
				location.href='/login';
			}
			readcodes();
			// get_key();
		})
		.catch(error => {
			console.error('错误:', error);
		});
	});
}
async function encryptWithOAEP(plainText, publicKeyPem) {
	const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
	const encrypted = publicKey.encrypt(forge.util.encodeUtf8(plainText), "RSA-OAEP", {
		md: forge.md.sha256.create() // 采用 SHA-256 作为哈希
	});
	return forge.util.encode64(encrypted);
}
const inele = document.querySelector(".input-we"), outele = document.querySelector(".output-we"), errele = document.querySelector(".error-we")
const outdlele = document.querySelector(".download-out"), errdlele = document.querySelector(".download-err");
function show(out, err, outfile, errfile, outsize, errsize){
	inele.classList = "well input-we ";
	outele.classList = "well output-we ";
	errele.classList = "well error-we ";
	outele.hidden = true;
	errele.hidden = true;
	outdlele.hidden = true;
	errdlele.hidden = true;
	edi_input.refresh();
	outdlele.onclick = null;
	errdlele.onclick = null;
	outdlele.innerHTML = "output.txt";
	errdlele.innerHTML = "error.txt";
	if(!out && !err){
		inele.classList += "hei10 full";
	}else if(!err){
		inele.classList += "hei6 top";
		outele.classList += "hei4 pla6 bottom";
		outele.hidden = false;
		edi_output.setValue(out);
		edi_output.refresh();
		if(outfile){
			outdlele.innerHTML += ` (${formatSize(outsize)})`;
			outdlele.hidden = false;
			outdlele.onclick=function(){
				safeFetch(`https://${ip}/uploads/${outfile}`)
				.then(response => {
					if (!response.ok) {
						throw new Error('file connected err');
					}
					return response.blob();
				})
				.then(blob => {
					const url = URL.createObjectURL(blob);
					const a = document.createElement('a');
					a.style.display = 'none';
					a.href = url;
					a.download = "output.txt";
					document.body.appendChild(a);
					a.click();
					document.body.removeChild(a);
					URL.revokeObjectURL(url);
				})
				.catch(error => {
					console.error('下载文件时出错:', error);
				});
			}
		}
	}else if(!out){
		inele.classList += "hei6 top";
		errele.classList += "hei4 pla6 bottom";
		errele.hidden = false;
		edi_error.setValue(err);
		edi_error.refresh();
		if(errfile){
			errdlele.innerHTML += ` (${formatSize(errsize)})`;
			errdlele.hidden = false;
			errdlele.onclick=function(){
				safeFetch(`https://${ip}/uploads/${errfile}`)
				.then(response => {
					if (!response.ok) {
						throw new Error('file connected err');
					}
					return response.blob();
				})
				.then(blob => {
					const url = URL.createObjectURL(blob);
					const a = document.createElement('a');
					a.style.display = 'none';
					a.href = url;
					a.download = "error.txt";
					document.body.appendChild(a);
					a.click();
					document.body.removeChild(a);
					URL.revokeObjectURL(url);
				})
				.catch(error => {
					const newWindow = window.open(`https://${ip}/${outfile}`, '_blank', 'noopener,noreferrer');
					if (newWindow) {
						newWindow.opener = null;
					}
					console.error('下载文件时出错:', error);
				});
			}
		}
	}else{
		inele.classList += "hei4 top";
		outele.classList += "hei3 pla4 no";
		errele.classList += "hei3 pla7 bottom";
		outele.hidden = false;
		errele.hidden = false;
		edi_output.setValue(out);
		edi_output.refresh();
		edi_error.setValue(err);
		edi_error.refresh();
		if(outfile){
			outdlele.innerHTML += ` (${formatSize(outsize)})`;
			errdlele.innerHTML += ` (${formatSize(errsize)})`;
			outdlele.hidden = false;
			outdlele.onclick=function(){
				safeFetch(`https://${ip}/uploads/${outfile}`)
				.then(response => {
					if (!response.ok) {
						throw new Error('file connected err');
					}
					return response.blob();
				})
				.then(blob => {
					const url = URL.createObjectURL(blob);
					const a = document.createElement('a');
					a.style.display = 'none';
					a.href = url;
					a.download = "output.txt";
					document.body.appendChild(a);
					a.click();
					document.body.removeChild(a);
					URL.revokeObjectURL(url);
				})
				.catch(error => {
					console.error('下载文件时出错:', error);
				});
			}
		}
		if(errfile){
			errdlele.hidden = false;
			errdlele.onclick=function(){
				safeFetch(`https://${ip}/uploads/${errfile}`)
				.then(response => {
					if (!response.ok) {
						throw new Error('file connected err');
					}
					return response.blob();
				})
				.then(blob => {
					const url = URL.createObjectURL(blob);
					const a = document.createElement('a');
					a.style.display = 'none';
					a.href = url;
					a.download = "error.txt";
					document.body.appendChild(a);
					a.click();
					document.body.removeChild(a);
					URL.revokeObjectURL(url);
				})
				.catch(error => {
					console.error('下载文件时出错:', error);
				});
			}
		}
	}
}
var lasave = "";
function tolast(){
	if(lasave !== editor.getValue()){
		let now = editor.getValue();
		editor.setValue(lasave);
		editor.clearHistory()
		editor.setValue(now);
		editor.undo();
	}
}
var running = false;
function submitCode() {
	if(running){
		return;
	}
	running = true;
	let inputContent = {
		type: "run-code",
		code: editor.getValue().trimStart().trimEnd(),
		input: edi_input.getValue().trimStart().trimEnd()
	};
	if(!inputContent.code){
		return;
	}
	show("Running");
	savecode();
	saveinput();
	safeFetch(`https://${ip}:/cpp-run`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
		.then(response => response.json())
		.then(data => {
			running = false;
			console.log('服务器返回的数据:', data)
			show(data.stdout, data.stderr, data.stdoutfile, data.stderrfile, data.outsize, data.errsize);
		})
		.catch(error => {
			console.error('错误:', error);
			show("", "something error");
		});
}
var editor = CodeMirror.fromTextArea(document.getElementById("code"), { mode: "text/x-c++src", matchBrackets: true, autoCloseBrackets: true, theme: "default",lineNumbers: true,tabSize: 4,indentUnit: 4,indentWithTabs: true,styleActiveLine: true });
editor.setOption("extraKeys", {"Ctrl-Enter": () => submitCode(editor)});
editor.getWrapperElement().classList.add("code-cm");
var saveele1 = document.getElementById("save1");
var saveele2 = document.getElementById("save2");
var saveele12 = document.getElementById("savetext1");
var saveele22 = document.getElementById("savetext2");
var savebtele1 = document.querySelector(".save-bt1");
var savebtele2 = document.querySelector(".save-bt2");
function save(ele, ele2, ele3) {
	if (!ele || !ele2) return;
	if (ele.fadeTimeout) clearTimeout(ele.fadeTimeout);
	if (ele.fadeInterval) clearInterval(ele.fadeInterval);
	ele.hidden = false;
	ele2.hidden = true;
	ele3.setAttribute("fill-opacity", 1);
	ele.fadeTimeout = setTimeout(() => {
		let opacity = 1;
		ele.fadeInterval = setInterval(() => {
			opacity -= 0.05;
			ele3.setAttribute("fill-opacity", opacity);
			if (opacity <= 0) {
				clearInterval(ele.fadeInterval);
				ele.hidden = true;
				ele2.hidden = false;
				ele3.setAttribute("fill-opacity", 1);
			}
		}, 100);
	}, 500);
}

var edi_input = CodeMirror.fromTextArea(document.getElementById("input"), { mode: "null", theme: "default",lineNumbers: true,tabSize: 4,indentUnit: 4,indentWithTabs: true,styleActiveLine: true });
var edi_output = CodeMirror.fromTextArea(document.getElementById("output"), { mode: "null", theme: "default",lineNumbers: true,tabSize: 4,indentUnit: 4,indentWithTabs: true,styleActiveLine: true, readOnly: true });
var edi_error = CodeMirror.fromTextArea(document.getElementById("error"), { mode: "null", theme: "default",lineNumbers: true,tabSize: 4,indentUnit: 4,indentWithTabs: true,styleActiveLine: true, readOnly: true });
var save_unsave = null, la_unsavecode = null;
edi_input.getWrapperElement().classList.add("code-cm");
edi_output.getWrapperElement().classList.add("code-short-cm");
edi_error.getWrapperElement().classList.add("code-short-cm");
editor.on("keydown", (cm, event) => {
	if(save_unsave){
		clearTimeout(save_unsave);
	}
	if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
		event.preventDefault();
		la_unsavecode = cm.getValue();
		savecode();
		return;
	}
	if(la_unsavecode !== cm.getValue()){
		la_unsavecode = cm.getValue();
	}else{
		return;
	}
	save_unsave = setTimeout(function(){
		save_unsave = null;
		let inputContent = { type: "savecpp-unsave", link, code: cm.getValue() };
		safeFetch(`https://${ip}:/cpp-save`, {
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
		})
		.catch(error => {
			console.error('错误:', error);
		});
	},200);
});
edi_input.on("keydown", (cm, event) => {
	if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
		event.preventDefault();
		saveinput();
	}
});
function savecode(){
	lasave = editor.getValue();
	let inputContent = { type: "savecpp", link, code: lasave };
	safeFetch(`https://${ip}:/cpp-save`, {
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
		if(data.message != "success"){
			alert("Code save failure");
		}else{
			save(saveele1, savebtele1, saveele12);
		}
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
function saveinput(){
	let inputContent = { type: "saveinput", link, code: edi_input.getValue() };
	safeFetch(`https://${ip}:/cpp-save`, {
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
		if(data.message != "success"){
			alert("Input filesave save failure");
		}else{
			save(saveele2, savebtele2, saveele22);
		}
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
function makeonly(){
	let inputContent = { type: "cpro", link };
	return safeFetch(`https://${ip}:/cpp-save`, {
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
			return data.link;
		}else{
			alert("Copy failure");
			return null;
		}
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
var rolink;
function makenonly(){
	let inputContent = { type: "cp", link1: link, link2: uuid.v4() };
	return safeFetch(`https://${ip}:/cpp-save`, {
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
			return inputContent.link2;
		}else{
			alert("Copy failure");
			return null;
		}
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
function cprolink(me){
	makeonly().then((data=>{
		const url = new URL(window.location.href);
		url.searchParams.set("uuid", data);
		copy(me, url.href.toString());
	}))
}
function readcodes(){
	let inputContent = { type: "read", link };
	safeFetch(`https://${ip}:/cpp-save`, {
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
			if(data.readOnly){
				let inputContent2 = { type: "cp", link };
				safeFetch(`https://${ip}:/cpp-save`, {
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
					console.log('服务器返回的数据:', data)
					if(data.message == "success"){
						setParam("uuid", data.link);
					}else{
						alert("Code acquisition failure");
					}
				})
				.catch(error => {
					console.error('错误:', error);
				});
				return;
			}
			editor.setValue(data.cppfile);
			editor.clearHistory();
			if(data.cppfile != data.unsave_cppfile){
				editor.setValue(data.unsave_cppfile);
			}
			lasave = data.cppfile;
			edi_input.setValue(data.inputfile);
			edi_input.clearHistory();
			document.querySelector(".filename").innerText = data.filename + '.cpp';
		}else{
			alert("Code acquisition failure");
		}
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
var tsmele = document.querySelector(".transmit");
function opentsm(){
	tsmele.hidden = false;
}
function closetsm(){
	tsmele.hidden = true;
}
function renameCode() {
	const filename = prompt("New file name");
	if(!filename){
		return;
	}
	let inputContent = { type: "rename", link, filename };
	console.log(inputContent);
	safeFetch(`https://${ip}/cpp-save`, {
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
		console.log("服务器返回的数据:", data);
		if(data.message == 'success'){
			location.reload();
		}
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
function copy(me, text){
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
}