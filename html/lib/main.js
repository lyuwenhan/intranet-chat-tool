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
	return {theme: "default",lineNumbers: true,tabSize: 4,indentUnit: 4,indentWithTabs: true,styleActiveLine: true, readOnly: ro, ...mode};
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
		alert('File size exceeds limit! The maximum allowed file size is 5MB');
		fileInput.value = '';
		return;
	}
	formData.set("file", newFile);
	formData.append('content', JSON.stringify({type: 'file'}));
	safeFetch(`/upload`, {
		method: 'POST',
		body: formData,
	})
	.then(async(blob)=>JSON.parse(await blob.text()))
	.then(data => {
		console.log('服务器返回的数据:', data)
		if(data.message == "success"){
			alert(`Upload success`);
		}else{
			alert(`Upload failure`);
		}
	})
	.catch(error => {
		console.error(error);
		alert(`Upload failure`);
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
		alert('File size exceeds limit! The maximum allowed file size is 5MB');
		imgInput.value = '';
		return;
	}
	formData.set("image", newFile);
	formData.append('content', JSON.stringify({type: 'file'}));
	safeFetch(`/uploadimg`, {
		method: 'POST',
		body: formData,
	})
	.then(async(blob)=>JSON.parse(await blob.text()))
	.then(data => {
		console.log('服务器返回的数据:', data)
		if(data.message == "success"){
			alert(`Upload success`);
		}else{
			alert(`Upload failure`);
		}
	})
	.catch(error => {
		alert(`Upload failure`);
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
var  username = "";
function submitForm() {
	var inputContent = {
		type: "send",
		info: document.getElementById("inputContent").value.replace(/\n+/g, "\n").trimEnd()
	};
	if(!inputContent.info.replace(/\n+/g, "\n").trimEnd()){
		return;
	}
	document.getElementById("inputContent").value = "";
	safeFetch(`/api`, {
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
	.catch(error => console.error('错误:', error));
}
function submitCode() {
	var inputContent = {
		type: "send-code",
		info: (isMob ? editor.value : editor.getValue().trimEnd())
	};
	if(!inputContent.info.replace(/\n+/g, "\n").trimEnd()){
		return;
	}
	var lang = document.getElementById("code-language");
	if(lang && lang.value){
		inputContent.language = lang.value.replace(/\n+/g, "\n").trimStart().trimEnd();
	}
	if(isMob){
		editor.value = "";
	}else{
		editor.setValue("");
		editor.clearHistory();
	}
	safeFetch(`/api`, {
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
	.catch(error => console.error('错误:', error));
}
function show(ele, ele2){
	ele.hidden = false;
	ele2.hidden = true;
}
async function loadImageAsDataURL(url, a) {
	try {
		const blob = await safeFetch(url);

		// 把 Blob 转为 base64 Data URL
		const base64 = await new Promise((resolve, reject) => {
			const reader = new FileReader();
			reader.onloadend = () => resolve(reader.result);
			reader.onerror = reject;
			reader.readAsDataURL(blob);
		});

		return base64;
	} catch (err) {
		console.warn("❌ 图片加载失败:", err.message);
		return a;
	}
}
function reloaddd(data){
	last_data.chats.push(data);
	if(data.type == "code" && data.language){
		document.querySelector(".chat").insertAdjacentHTML(
			"beforeend",
			`<strong>[${data.ip}]&nbsp;${(data.username || "").padEnd(8, " ")}: </strong>${data.language}<br>`
		);
	}else{
		document.querySelector(".chat").insertAdjacentHTML(
			"beforeend",
			`<strong>[${data.ip}]&nbsp;${(data.username || "").padEnd(8, " ")}: </strong>${data.type}<br>`
		);
	}
	if(data.type == "code"){
		let ndiv = document.createElement("div");
		ndiv.classList = "well";
		let nele = document.createElement("textarea");
		nele.classList=[`msg-code msg-${i}`];
		nele.value = data.info;
		nele.readOnly = true;
		ndiv.appendChild(nele);
		ndiv.style.width = "70%";
		let latele = null, nele1 = null, nele2 = null;
		if(data.language == "markdown" && data.html){
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
			latele.innerHTML = DOMPurify.sanitize(data.html, {
				FORBID_TAGS: ['style', 'iframe', 'script'],
				FORBID_ATTR: ['onclick','ondblclick','onmousedown','onmouseup','onmouseenter','onmouseleave','onmouseover','onmouseout','onmousemove','oncontextmenu','onkeydown','onkeypress','onkeyup','onfocus','onblur','onchange','oninput','onreset','onsubmit','oninvalid','ondrag','ondragstart','ondragend','ondragenter','ondragleave','ondragover','ondrop','oncopy','oncut','onpaste','ontouchstart','ontouchmove','ontouchend','ontouchcancel','onscroll','onwheel','onresize','onload','onerror','onabort','onbeforeunload','onunload','onplay','onpause','onended','onvolumechange','oncanplay','oncanplaythrough','onwaiting','onseeking','onseeked','ontimeupdate','onanimationstart','onanimationend','onanimationiteration','ontransitionend','onshow','ontoggle','onmessage','onopen','onclose']
			});
			MathJax.typesetPromise([latele]).then(() => {
				ndiv.appendChild(latele);
			});
		}
		document.querySelector(".chat").appendChild(ndiv);
		document.querySelector(".chat").appendChild(document.createElement("br"));
		let cm = CodeMirror.fromTextArea(nele, tomode(languageModes[data.language || "plain text"][1]));
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
	}else if(data.type == "file" || data.type == "image"){
		let nele = document.createElement("a");
		nele.classList="can-click";
		nele.title="click to download";
		nele.innerHTML=`${data.filename}&nbsp;&nbsp;[${formatSize(data.size)}]`;
		nele.onclick=function(){
			safeFetch(`/uploads${(data.type == "file" ? `` : `/img`)}/download/${data.path}`)
			.then(blob => {
				const url = URL.createObjectURL(blob);
				const a = document.createElement('a');
				a.style.display = 'none';
				a.href = url;
				a.download = data.filename;
				document.body.appendChild(a);
				a.click();
				document.body.removeChild(a);
				URL.revokeObjectURL(url);
			})
			.catch(error => {
				console.error('下载文件时出错:', error);
			});
		}
		document.querySelector(".chat").appendChild(nele);
		document.querySelector(".chat").appendChild(document.createElement("br"));
		if(data.type == "image"){
			let nele2 = document.createElement("img");
			nele2.src=`/uploads/img/${data.path}`;
			nele2.id="img";
			nele2.title="click to copy the link";
			nele2.onerror=function(){
				nele.innerText = 'image broked';
				nele.id = '';
				nele.onclick = null;
				nele.title = '';
				nele.classList = '';
				nele.style = 'color:red;font-size:1.1em;';
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
		nele.innerText = data.info;
		document.querySelector(".chat").appendChild(nele);
		document.querySelector(".chat").appendChild(document.createElement("br"));
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
		reloaddd(li[i]);
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
	safeFetch(`/api`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(async(blob)=>JSON.parse(await blob.text()))
	.then(data => {
		reloadd(data);
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
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
function run(){
	let inputContent = { type: "savecpp", link: uuid.v4(), code: (isMob ? editor.value : editor.getValue()) };
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
			const currentUrl = new URL(window.location.href);
			currentUrl.pathname = "/codeEditor";
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
var role = 'user';
document.addEventListener("DOMContentLoaded", () => {
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
				jump();
			}
			reload();
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
			ws.send(JSON.stringify({
				type: "init",
				role: "chatroom",
			}));
		};

		ws.onmessage = (event) => {
			const msg = JSON.parse(event.data);
			switch (msg.type) {
				case 'chat':
					console.log("新增聊天消息:", msg.info);
					reloaddd(msg.info);
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
	
	var edtlang = languageModes[document.getElementById("code-language").value || "plain text"][0];
	const runele = document.querySelector(".runele");
	if(!isMob){
		window.editor = CodeMirror.fromTextArea(document.getElementById("code"), tomode(edtlang));
		function ed_init(){
			editor.setOption("extraKeys", {"Ctrl-Enter": () => submitCode()});
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
	}else{
		window.editor = document.getElementById("code");
		function ed_init(){
			editor.addEventListener("keydown", (e) => {
				if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
					e.preventDefault();
					submitCode();
				}
				if(edtlang.mode == "markdown"){
					showmd(marked.parse(editor.value));
				}
			});
		}
		ed_init();
		document.getElementById("code-language").addEventListener("change", function() {
			edtlang = languageModes[this.value || "plain text"][0];
			if(edtlang.mode == "markdown"){
				showmd(marked.parse(editor.value));
			}else{
				unshowmd();
			}
			if(edtlang.mode == "text/x-c++src"){
				runele.hidden = false;
			}else{
				runele.hidden = true;
			}
		});
	}
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
});