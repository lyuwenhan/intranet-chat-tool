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
function isValidUUIDv4(uuid) {
	const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
	return regex.test(uuid);
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
var  username = "";
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
		outele.classList += "hei4 pla6 place2 bottom";
		outele.hidden = false;
		edi_output.setValue(out);
		edi_output.refresh();
		if(outfile){
			outdlele.innerHTML += ` (${formatSize(outsize)})`;
			outdlele.hidden = false;
			outdlele.onclick=function(){
				safeFetch(`/uploads/${outfile}`)
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
		errele.classList += "hei4 pla6 place2 bottom";
		errele.hidden = false;
		edi_error.setValue(err);
		edi_error.refresh();
		if(errfile){
			errdlele.innerHTML += ` (${formatSize(errsize)})`;
			errdlele.hidden = false;
			errdlele.onclick=function(){
				safeFetch(`/uploads/${errfile}`)
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
					const newWindow = window.open(`/${outfile}`, '_blank', 'noopener,noreferrer');
					if (newWindow) {
						newWindow.opener = null;
					}
					console.error('下载文件时出错:', error);
				});
			}
		}
	}else{
		inele.classList += "hei4 top";
		outele.classList += "hei3 pla4 place2 no";
		errele.classList += "hei3 pla7 place3 bottom";
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
				safeFetch(`/uploads/${outfile}`)
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
				safeFetch(`/uploads/${errfile}`)
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
		input: edi_input.getValue().trimStart().trimEnd(),
		token
	};
	if(!inputContent.code){
		return;
	}
	savecode();
	saveinput();
	safeFetch(`/cpp-run`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(async(blob)=>JSON.parse(await blob.text()))
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
		safeFetch(`/cpp-save`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({ content: inputContent })
		})
		.then(async(blob)=>JSON.parse(await blob.text()))
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
	safeFetch(`/cpp-save`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(async(blob)=>JSON.parse(await blob.text()))
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
	safeFetch(`/cpp-save`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(async(blob)=>JSON.parse(await blob.text()))
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
	return safeFetch(`/cpp-save`, {
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
	return safeFetch(`/cpp-save`, {
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
function cprouuid(me){
	makeonly().then((data=>{
		copy(me, data);
	}))
}
function readcodes(){
	let inputContent = { type: "read", link };
	safeFetch(`/cpp-save`, {
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
			if(data.readOnly){
				let inputContent2 = { type: "cp", link };
				safeFetch(`/cpp-save`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({ content: inputContent2 })
				})
				.then(async(blob)=>JSON.parse(await blob.text()))
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
async function renameCode() {
	const filename = await prompt("Enter your new file name\nYou should not write the \".cpp\"");
	if(filename === false){
		return;
	}
	if(!filename){
		alert("File name cannot be empty");
		return;
	}
	if(filename.length > 100){
		return res.json({ message: 'faild', info: 'Filename too long' });
	}
	if(!/^[\w\-\s]+$/.test(filename)){
		return res.json({ message: 'faild', info: 'Invalid filename' });
	}
	let inputContent = { type: "rename", link, filename };
	console.log(inputContent);
	safeFetch(`/cpp-save`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(async(blob)=>JSON.parse(await blob.text()))
	.then(data => {
		console.log("服务器返回的数据:", data);
		if(data.message == 'success'){
			location.reload();
		}else{
			if(data.info){
				alert(data.info);
			}
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
var token = null;
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
				document.getElementById("logout").hidden = false;
				document.getElementById("changePwd").hidden = false;
			}else{
				document.getElementById("login").hidden = false;
				document.getElementById("sign_up").hidden = false;
				jump();
			}
			readcodes();
		})
		.catch(error => {
			console.error('错误:', error);
		});
	});
	let ws;
	let reconnectDelay = 1000;
	const maxDelay = 30000;

	function connectWS(){
		ws = new WebSocket(`wss://${location.host}`, null, { withCredentials: true });

		ws.onopen = () => {
			console.log("WebSocket connected");
			reconnectDelay = 1000;
			token = uuid.v4();
			ws.send(JSON.stringify({
				type: "init",
				role: "cpprunner",
				token
			}));
		};

		ws.onmessage = (event) => {
			const msg = JSON.parse(event.data);
			switch (msg.type) {
				case 'status':
					show(msg.message);
					console.log("状态更新:", msg.message);
					break;
				case 'result':
					console.log("评测结果:", msg);
					break;
			}
		};

		ws.onclose = (event) => {
			console.warn("WebSocket 断开:", event.code, event.reason);
			retryWS();
		};

		ws.onerror = (err) => {
			console.error("WebSocket 错误:", err);
			ws.close();
		};

		window.cppWs = ws;
	}

	function retryWS(){
		reconnectDelay = Math.min(reconnectDelay * 2, maxDelay);
		console.log(`将在 ${reconnectDelay / 1000} 秒后重连...`);
		setTimeout(() => {
			connectWS();
		}, reconnectDelay);
	}

	connectWS();
});