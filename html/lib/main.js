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
const languageModes = {
	"plain text": [{ mode: "null" }, {  mode: "null" }],
	"c": [{ mode: "text/x-csrc", matchBrackets: true, autoCloseBrackets: true }, {  mode: "text/x-csrc", matchBrackets: true, autoCloseBrackets: true }],
	"cpp": [{ mode: "text/x-c++src", matchBrackets: true, autoCloseBrackets: true }, {  mode: "text/x-c++src", matchBrackets: true, autoCloseBrackets: true }],
	"css": [{ mode: "css", autoCloseBrackets: true, autoCloseTags: true }, {  mode: "css", autoCloseBrackets: true, autoCloseTags: true }],
	"java": [{ mode: "text/x-java", matchBrackets: true, autoCloseBrackets: true }, {  mode: "text/x-java", matchBrackets: true, autoCloseBrackets: true }],
	"json": [{ mode: "javascript", matchBrackets: true, autoCloseBrackets: true }, {  mode: "javascript", matchBrackets: true, autoCloseBrackets: true }],
	"html": [{ mode: "htmlmixed", matchBrackets: true, autoCloseTags: true }, {  mode: "htmlmixed", matchBrackets: true, autoCloseTags: true }],
	"shell": [{ mode: "shell", matchBrackets: true }, {  mode: "shell", matchBrackets: true }],
	"python": [{ mode: "python", matchBrackets: true, autoCloseBrackets: true }, {  mode: "python", matchBrackets: true, autoCloseBrackets: true }],
	"markdown": [{ mode: "markdown" }, {  mode: "markdown" }],
	"javascript": [{ mode: "javascript", matchBrackets: true, autoCloseBrackets: true }, {  mode: "javascript", matchBrackets: true, autoCloseBrackets: true }],
	"yaml": [{ mode: "yaml" }, { mode: "yaml" }],
	"sql": [{ mode: "text/x-sql", matchBrackets: true, autoCloseBrackets: true }, { mode: "text/x-sql", matchBrackets: true, autoCloseBrackets: true }]
};
function tomode(mode, ro = false){
	return Object.assign({}, mode, {theme: "default",lineNumbers: true,tabSize: 4,indentUnit: 4,indentWithTabs: true,styleActiveLine: true, readOnly: ro});
}
var images = document.getElementsByTagName('img');
for (var i = 0; i < images.length; i++) {
	images[i].addEventListener('dragstart', function(event) {
		event.preventDefault();
	});
}
// 获取表单元素和文件输入框
const form = document.getElementById('uploadForm');
const fileInput = document.getElementById('file');
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

// 监听表单提交事件
form.addEventListener('submit', function(e) {
	e.preventDefault(); // 阻止表单的默认提交行为

	// 获取选中的文件
	let formData = new FormData(form);
	let file = formData.get("file");
	let newFile = new File([file], btoa(unescape(encodeURIComponent(file.name))), { type: file.type });

	// 检查文件大小
	if (file.size > MAX_FILE_SIZE) {
		alert('文件大小超过限制！最大允许文件大小为 5MB');
		fileInput.value = '';
		return;
	}
	formData.set("file", newFile);
	formData.append('content', JSON.stringify({type: 'file'}));
	safeFetch(`https://${ip}/upload`, {
		method: 'POST',
		body: formData,
	})
	.then(response => response.json())
	.then(data => {
		console.log('服务器返回的数据:', data)
		if(data.message == "success"){
			reloadd(data);
			alert(`上传成功`);
		}else{
			alert(`上传失败`);
		}
	})
	.catch(error => {
		alert(`上传失败`);
		console.error(error);
	});
	fileInput.value = '';
});
const imgform = document.getElementById('uploadImage');
const imgInput = document.getElementById('img');

// 监听表单提交事件
imgform.addEventListener('submit', function(e) {
	e.preventDefault(); // 阻止表单的默认提交行为

	// 获取选中的文件
	let formData = new FormData(imgform);
	let file = formData.get("image");
	let newFile = new File([file], btoa(unescape(encodeURIComponent(file.name))), { type: file.type });

	// 检查文件大小
	if (file.size > MAX_FILE_SIZE) {
		alert('文件大小超过限制！最大允许文件大小为 5MB');
		imgInput.value = '';
		return;
	}
	formData.set("image", newFile);
	formData.append('content', JSON.stringify({type: 'file'}));
	safeFetch(`https://${ip}/uploadimg`, {
		method: 'POST',
		body: formData,
	})
	.then(response => response.json())
	.then(data => {
		console.log('服务器返回的数据:', data)
		if(data.message == "success"){
			reloadd(data);
			alert(`上传成功`);
		}else{
			alert(`上传失败`);
		}
	})
	.catch(error => {
		alert(`上传失败`);
		console.error(error);
	});
	imgInput.value = '';
});
function formatSize(bytes) {
	const units = ['B', 'KB', 'MB', 'GB', 'TB'];
	let unitIndex = 0;

	// 如果字节数大于当前单位的 75%，就转换为下一个单位
	while (bytes >= 1024 * 0.75 && unitIndex < units.length - 1) {
		bytes /= 1024;
		unitIndex++;
	}

	return `${bytes.toFixed(2)} ${units[unitIndex]}`;
}

var last_data = {chats:[]};
function get_key() {
	var inputContent = { type: "get-key" };
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
var auto_fresh = document.querySelector("#auto-fresh").checked = (localStorage.getItem("auto-fresh") === "true");
document.getElementById("auto-fresh").addEventListener("change", function() {
	localStorage.setItem("auto-fresh", auto_fresh = this.checked);
});
var ip = "", username = "";
window.onload = function () {
	document.getElementById('inputContent').addEventListener('keydown', function(event) {
		if (event.key === "Enter") {
			submitForm();
		}
	});
	document.getElementById('code').addEventListener('keydown', function(event) {
		if (event.key === "Enter" && event.ctrlKey) {
			submitCode();
		}
	});
	let mayip="";
	if(isValidIPv4(window.location.hostname)){
		mayip = window.location.hostname;
	}
	ip = mayip;
	if(!mayip){
		ip = prompt("请输入服务器ipv4", mayip);
		while (!isValidIPv4(ip)) {
			ip = prompt("请输入合法的服务器ipv4", mayip);
		}
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
			location.href = '/login';
		}
		reload();
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
function submitForm() {
	var inputContent = {
		type: "send",
		info: document.getElementById("inputContent").value.replace(/\n+/g, "\n").trimEnd()
	};
	if(!inputContent.info.replace(/\n+/g, "\n").trimEnd()){
		return;
	}
	document.getElementById("inputContent").value = "";
	safeFetch(`https://${ip}/api`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
		.then(response => response.json())
		.then(data => {
			console.log('服务器返回的数据:', data)
			reloadd(data);
		})
		.catch(error => console.error('错误:', error));
}
function submitCode() {
	var inputContent = {
		type: "send-code",
		info: editor.getValue().trimEnd()
	};
	if(!inputContent.info.replace(/\n+/g, "\n").trimEnd()){
		return;
	}
	var lang = document.querySelector("#code-language");
	if(lang && lang.value){
		inputContent.language = lang.value.replace(/\n+/g, "\n").trimStart().trimEnd();
	}
	editor.setValue("");
	editor.clearHistory();
	safeFetch(`https://${ip}/api`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
		.then(response => response.json())
		.then(data => {
			console.log('服务器返回的数据:', data)
			reloadd(data);
		})
		.catch(error => console.error('错误:', error));
}
function show(ele, ele2){
	ele.hidden = false;
	ele2.hidden = true;
}
async function loadImageAsDataURL(url, a) {
	try {
		const res = await safeFetch(url);
		if (!res.ok) throw new Error(`HTTP ${res.status}`);

		const blob = await res.blob();

		// 把 Blob 转为 base64 Data URL
		const base64 = await new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onloadend = () => resolve(reader.result);
		reader.onerror = reject;
		reader.readAsDataURL(blob);
		});

		return base64; // ✅ 返回 data:image/... 形式
	} catch (err) {
		console.warn("❌ 图片加载失败:", err.message);
		return a; // ❌ 返回传入的 a
	}
}
function reloadd(data) {
	if(data.message == "ban"){
		let li = data.chats;
		document.querySelector(".chat").innerHTML = `<a class="ban">${li[0].info}</a>`;
		last_data = "";
		return;
	}
	if(data.message && data.message != "success"){
		return;
	}
	let li = data.chats;
	let l2 = li.slice();
	if(JSON.stringify(last_data.chats) === JSON.stringify(li)){
		return;
	}
	while(last_data.chats.length && JSON.stringify(last_data.chats[0]) == JSON.stringify(l2[0])){
		last_data.chats.shift();
		l2.shift();
	}
	if(last_data.chats.length){
		document.querySelector(".chat").innerHTML = "";
		console.log('聊天记录', li);
	}else{
		li = l2;
		console.log('新增聊天记录', li);
	}
	for (let i = 0; i < li.length; i++) {
		if(li[i].type == "code" && li[i].language){
			document.querySelector(".chat").insertAdjacentHTML(
				"beforeend",
				`<strong>[${li[i].ip}]&nbsp;${(li[i].username || "").padEnd(8, " ")}: </strong>${li[i].language}<br>`
			);
		}else{
			document.querySelector(".chat").insertAdjacentHTML(
				"beforeend",
				`<strong>[${li[i].ip}]&nbsp;${(li[i].username || "").padEnd(8, " ")}: </strong>${li[i].type}<br>`
			);
		}
		if(li[i].type == "code"){
			let ndiv = document.createElement("div");
			ndiv.classList = "well";
			let nele = document.createElement("textarea");
			nele.classList=[`msg-code msg-${i}`];
			nele.value = li[i].info;
			nele.readOnly = true;
			ndiv.appendChild(nele);
			ndiv.style.width = "70%";
			let latele = null, nele1 = null, nele2 = null;
			if(li[i].language == "markdown" && li[i].html){
				nele1 = document.createElement("a");
				nele1.innerHTML = "show preview";
				nele1.classList="bt-grey";
				nele2 = document.createElement("a");
				nele2.innerHTML = "show markdown";
				nele2.classList="bt-grey";
				ndiv.prepend(document.createElement("br"));
				ndiv.prepend(document.createElement("br"));
				ndiv.prepend(nele1);
				ndiv.prepend(nele2);
				latele = document.createElement("div");
				latele.id = "latex";
				latele.innerHTML = DOMPurify.sanitize(li[i].html, {
					FORBID_TAGS: ['style', 'iframe', 'script'],
					FORBID_ATTR: ['onclick','ondblclick','onmousedown','onmouseup','onmouseenter','onmouseleave','onmouseover','onmouseout','onmousemove','oncontextmenu','onkeydown','onkeypress','onkeyup','onfocus','onblur','onchange','oninput','onreset','onsubmit','oninvalid','ondrag','ondragstart','ondragend','ondragenter','ondragleave','ondragover','ondrop','oncopy','oncut','onpaste','ontouchstart','ontouchmove','ontouchend','ontouchcancel','onscroll','onwheel','onresize','onload','onerror','onabort','onbeforeunload','onunload','onplay','onpause','onended','onvolumechange','oncanplay','oncanplaythrough','onwaiting','onseeking','onseeked','ontimeupdate','onanimationstart','onanimationend','onanimationiteration','ontransitionend','onshow','ontoggle','onmessage','onopen','onclose']
				});
				MathJax.typesetPromise([latele]).then(() => {
					ndiv.appendChild(latele);
				});
			}
			document.querySelector(".chat").appendChild(ndiv);
			document.querySelector(".chat").appendChild(document.createElement("br"));
			let cm = CodeMirror.fromTextArea(nele, tomode(languageModes[li[i].language || "plain text"][1]));
			cm.setSize("auto", `calc( ${cm.lineCount() * 1.3 + 2.6}em + 8px)`);
			if(latele){
				const cmele = cm.getWrapperElement();
				show(cmele, latele);
				show(nele1, nele2);
				nele1.onclick = function(){
					show(nele2, nele1);
					show(latele, cmele);
				}
				nele2.onclick = function(){
					show(nele1, nele2);
					show(cmele, latele);
				}
			}
			setTimeout(function(cm) {
				cm.setOption("viewportMargin", Infinity);
			}.bind(null, cm), 5);
		}else if(li[i].type == "file" || li[i].type == "image"){
			let nele = document.createElement("a");
			nele.classList="can-click";
			nele.title="click to download";
			nele.innerHTML=`${li[i].filename}&nbsp;&nbsp;[${formatSize(li[i].size)}]`;
			nele.onclick=function(){
				let run = false;
				safeFetch(`https://${ip}/uploads/test-connect`).then(a=>{
					run = true;
					safeFetch(`https://${ip}/uploads${(li[i].type == "file" ? `` : `/img`)}/download/${li[i].path}`)
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
						a.download = li[i].filename;
						document.body.appendChild(a);
						a.click();
						document.body.removeChild(a);
						URL.revokeObjectURL(url);
					})
					.catch(error => {
						console.error('下载文件时出错:', error);
					});
				});
				setTimeout(function(){
					if(!run){
						location.href = `https://${ip}/uploads/allow-connect?from=` + encodeURIComponent(location.href);
						window.addEventListener('pageshow', function(event) {
							if (event.persisted || performance.getEntriesByType('navigation')[0].type === 'back_forward') {
								safeFetch(`https://${ip}/uploads${(li[i].type == "file" ? `` : `/img`)}/download/${li[i].path}`)
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
									a.download = li[i].filename;
									document.body.appendChild(a);
									a.click();
									document.body.removeChild(a);
									URL.revokeObjectURL(url);
								})
								.catch(error => {
									console.error('下载文件时出错:', error);
								});
							}
							last_data = {chats:[{info: "Not True"}]};
							reload();
						}, {once: true});
					}
				},500);
			}
			document.querySelector(".chat").appendChild(nele);
			document.querySelector(".chat").appendChild(document.createElement("br"));
			if(li[i].type == "image"){
				let nele2 = document.createElement("img");
				nele2.src=`https://${ip}/uploads/img/${li[i].path}`;
				nele2.id="img";
				nele2.title="click to copy the link";
				nele2.onerror=function(){
					nele.innerHTML = `<span style="color:red;font-size:1.1em;">image broked</span>`;
					nele.id = '';
					nele.onclick = null;
					nele.title="";
					nele2.onclick = null;
					nele2.id="noimg";
					nele2.onerror = null;
					nele2.src="data:image/svg+xml,%3Csvg%20viewBox%3D%220%200%20231%20130%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%3E%3Cg%20fill%3D%22none%22%20fill-rule%3D%22evenodd%22%3E%3Cpath%20fill%3D%22%23E3E9F1%22%20d%3D%22M0%200h231v130H0z%22/%3E%3C/g%3E%3Cg%20transform%3D%22translate(0%2C13.5)%22%3E%3Cpath%20d%3D%22M116%2041c0%208.636-5%2015-15%2015s-15-6.364-15-15%205-15%2015-15%2015%206.364%2015%2015z%22%20fill%3D%22%23CDD5DC%22/%3E%3C/g%3E%3Cg%20transform%3D%22translate(0%2C27)%22%3E%3Cpath%20d%3D%22M231%2089l-41.216-37.138c-2.4-2.874-6.624-5-11.712-5.92-1.824-.287-3.648-.46-5.472-.46-3.36%200-6.72.518-9.696%201.552L101.368%2068.53%2077.752%2058.93c-3.264-1.322-7.008-1.954-10.752-1.954-4.992%200-9.888%201.15-13.536%203.39L0%2087v16h231V89z%22%20fill%3D%22%23CDD5DC%22/%3E%3C/g%3E%3C/svg%3E";
				};
				nele2.onclick=function(){
					copy(null, this.src);
				};
				document.querySelector(".chat").appendChild(nele2);
				document.querySelector(".chat").appendChild(document.createElement("br"));
			}
		}else{
			let nele = document.createElement("code");
			nele.class=`msg-text msg-${i}`;
			nele.innerText = li[i].info;
			document.querySelector(".chat").appendChild(nele);
			document.querySelector(".chat").appendChild(document.createElement("br"));
		}
	}
	last_data = data;
	setTimeout(function() {
		Prism.highlightAll();
		var images = document.getElementsByTagName('img');
		for (var i = 0; i < images.length; i++) {
			images[i].addEventListener('dragstart', function(event) {
				event.preventDefault();
			});
		}
	}, 5);
}

function reload() {
	var inputContent = { type: "get" };
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
			reloadd(data);
		})
		.catch(error => {
			console.error('错误:', error);
		});
}
function au_reload(){
	if(auto_fresh){
		reload();
	}
}
setInterval(function(){au_reload()}, 1000);
const renderer = new marked.Renderer();

// 手动 HTML 转义，防止 XSS
const escapeHtml = (code) => {
	return code
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
};

renderer.codespan = function(text) {
	return `<code class='code'>${text.text}</code>`;
};
renderer.code = function(code) {
	if(!code.lang){
		code.lang = "none";
	}
	if(code.lang == 'c++'){
		code.lang = "cpp";
	}
	return `<pre class="line-numbers language-${code.lang}"><code class="language-${code.lang}">${escapeHtml(code.text)}</code></pre>`;
};

marked.setOptions({
	renderer: renderer,
	highlight: function(code, lang) {
		const language = Prism.languages[lang] || Prism.languages.javascript;
		return Prism.highlight(code, language, lang);
	}
});
var edtlang = languageModes[document.querySelector("#code-language").value || "plain text"][0];
var editor = CodeMirror.fromTextArea(document.getElementById("code"), tomode(edtlang));
var mdele = document.querySelector(".md"), prele = document.querySelector(".preview");
var showto = null;
function showmd(text, force){
	text = DOMPurify.sanitize(text, {
		FORBID_TAGS: ['style', 'iframe', 'script'],
		FORBID_ATTR: ['onclick','ondblclick','onmousedown','onmouseup','onmouseenter','onmouseleave','onmouseover','onmouseout','onmousemove','oncontextmenu','onkeydown','onkeypress','onkeyup','onfocus','onblur','onchange','oninput','onreset','onsubmit','oninvalid','ondrag','ondragstart','ondragend','ondragenter','ondragleave','ondragover','ondrop','oncopy','oncut','onpaste','ontouchstart','ontouchmove','ontouchend','ontouchcancel','onscroll','onwheel','onresize','onload','onerror','onabort','onbeforeunload','onunload','onplay','onpause','onended','onvolumechange','oncanplay','oncanplaythrough','onwaiting','onseeking','onseeked','ontimeupdate','onanimationstart','onanimationend','onanimationiteration','ontransitionend','onshow','ontoggle','onmessage','onopen','onclose']
	});
	if(!showto || force){
		mdele.hidden = false;
		prele.innerHTML = text;
		MathJax.typesetPromise([prele]);
		Prism.highlightAll();
		if(!force){
			showto = setTimeout(()=>{
				showmd(text, true);
				showto = null;
			}, 100);
		}
	}else{
		clearTimeout(showto);
		showto = setTimeout(()=>{
			showmd(text, true);
			showto = null;
		}, 100);
	}
}
function unshowmd(){
	mdele.hidden = true;
	prele.innerHTML = "";
	clearTimeout(showto);
	showto=null;
}
function ed_init(){
	editor.setOption("extraKeys", {"Ctrl-Enter": () => submitCode(editor)});
	editor.getWrapperElement().classList.add("code-cm");
	editor.setSize("auto", `calc(${editor.lineCount() * 1.3 + 2.6}em + 8px)`);
	editor.on("change", function (cm) {
		if(edtlang.mode == "markdown"){
			showmd(marked.parse(cm.getValue()))
		}
		cm.setSize("auto", `calc(${cm.lineCount() * 1.3 + 2.6}em + 8px)`);
	});
}
ed_init();
const runele = document.querySelector(".runele");
document.getElementById("code-language").addEventListener("change", function() {
	editor.toTextArea();
	edtlang = languageModes[this.value || "plain text"][0];
	editor = CodeMirror.fromTextArea(document.getElementById("code"), tomode(edtlang));
	ed_init();
	if(edtlang.mode == "markdown"){
		showmd(marked.parse(editor.getValue()));
	}else{
		unshowmd();
	}
	if(edtlang.mode == "text/x-c++src"){
		runele.hidden = false;
	}else{
		runele.hidden = true;
	}
});
function run(){
	let inputContent = { type: "savecpp", link: uuid.v4(), code: editor.getValue() };
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
		console.log('服务器返回的数据:', data)
		if(data.message != "success"){
			alert("代码保存失败");
		}else{
			const currentUrl = new URL(window.location.href);
			currentUrl.pathname = "/cpprunner";
			currentUrl.search = `?uuid=${inputContent.link}`;
			currentUrl.hash = "";
			window.location.href = currentUrl.href;
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
	}else{
		alert("copied");
	}
}