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
function isValidUsername(username){
	return username && username.length <= 20 && /^\w+$/.test(username);
}
var username = "";
const mainele = document.querySelector(".main");
const tableBody = document.querySelector('#codeTable tbody');
async function open_uuid(uuid, openonly = false){
	if(uuid === false){
		return;
	}
	if(!uuid){
		alert("UUID cannot be empty");
		return;
	}
	if(!isValidUUIDv4(uuid)){
		alert("Invalid UUID");
		return;
	}
	if(!openonly && await confirm(" ", "Copy UUID", "Open in new tab")){
		copy(null, uuid, ()=>{alert('copied')});
	}else{
		window.open(`/codeEditor?uuid=${uuid}`, '_blank');
	}
}
function getCodeList() {
	let inputContent = {
		type: "getList",
	};
	safeFetch(`/cpp-save`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ content: inputContent })
	})
	.then(async(blob)=>JSON.parse(await blob.text()))
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
			let nele = document.createElement("td");
			let nele2 = document.createElement("a");
			nele2.addEventListener('click', function (e) {
				if(e.button === 0){
					e.preventDefault();
					open_uuid(code.uuid);
				}
			});
			nele2.href = `/codeEditor?uuid=${code.uuid}`;
			nele2.innerText = `${code.filename}.cpp`;
			nele2.target = "_blank";
			nele2.className = "bt-grey"
			nele.appendChild(nele2);
			row.appendChild(nele);
			row.insertAdjacentHTML(
				"beforeend", 
				`<td>${updated}</td><td><button onclick="renameCode('${code.uuid}')" class="bt-red">Rename</button>&nbsp;<button onclick="deleteCode('${code.filename}', '${code.uuid}')" class="bt-red">Delete</button></td>`
			);
			tableBody.appendChild(row);
		});
	})
	.catch(error => {
		console.error('错误:', error);
	});
}
async function deleteCode(filename, uuid) {
	if (await confirm(`Are you sure you want to delete the file "${filename}.cpp"?`)) {
		let inputContent = { type: "delete", link: uuid };
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
			}
		})
		.catch(error => {
			console.error('错误:', error);
		});
	}
}
async function renameCode(uuid) {
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
	let inputContent = { type: "rename", link: uuid, filename };
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
				window.name="from-href";
				location.href='/login';
			}
			getCodeList();
		})
		.catch(error => {
			console.error('错误:', error);
		});
	});
});