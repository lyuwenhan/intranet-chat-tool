// Project: Intranet Chat Tool
// Copyright (C) 2025 lyuwenhan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const fs = require("fs");
const crypto = require("crypto");
const readline = require("readline");

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function ask(question) {
    return new Promise(resolve => rl.question(question, answer => resolve(answer.trim())));
}

(async () => {
    console.log("=== Intranet Chat Tool .env Generator ===\n");
    console.log("Tip: Press Enter to use the default or generate automatically.\n");

	let generated = false;
    let sessionPwd = await ask("Enter SESSION password (SESSION_PWD) [leave blank to auto-generate]:\n> ");
    if (!sessionPwd) {
		generated = true;
        sessionPwd = crypto.randomBytes(64).toString("hex");
        console.log("Generated SESSION_PWD: " + sessionPwd);
    }

    let allowRegister = await ask("Allow new user registration? (true/false) [default: true]:\n> ");
    if (!["true", "false"].includes(allowRegister)) {
        allowRegister = "true";
    }

    let allowProxy = await ask("Proxy number (enter 0 if no proxy) [default: 0]:\n> ");
    if (!allowProxy) {
        allowProxy = "0";
    }

    console.log("\nSelect server mode:");
    console.log("1 - HTTPS only (recommended)");
    console.log("2 - HTTP only (for reverse proxy)");
    console.log("3 - HTTP and HTTPS with redirect from HTTP");
    let portMode = await ask("Enter your choice (1/2/3) [default: 1]:\n> ");
    if (!["1", "2", "3"].includes(portMode)) {
        portMode = "1";
    }

    let portConfig = "";
    let portSummary = "";
    if (portMode === "1") {
        portConfig += "PORT=443\nPORT_HTTP=close\n";
        portSummary = "HTTPS only (PORT=443)";
    } else if (portMode === "2") {
        portConfig += "PORT=80\nPORT_HTTP=only\n";
        portSummary = "HTTP only (PORT=80)";
    } else if (portMode === "3") {
        portConfig += "PORT=443\nPORT_HTTP=80\n";
        portSummary = "HTTPS + redirect from HTTP (PORT=443, PORT_HTTP=80)";
    }

    let certPath = "keys/cert.pem";
    let keyPath = "keys/key.pem";
    if (portMode !== "2") {
        const cert = await ask(`Path to SSL certificate [default: ${certPath}]:\n> `);
        const key = await ask(`Path to SSL private key [default: ${keyPath}]:\n> `);
        if (cert) certPath = cert;
        if (key) keyPath = key;
    }

	console.clear();
    console.log("\n===== Summary =====");
    if (generated) {
        console.log("SESSION_PWD   : (auto-generated, hidden)");
    } else {
        console.log("SESSION_PWD   : (provided manually, hidden)");
    }
    console.log("ALLOW_REGISTER:", allowRegister);
    console.log("ALLOW_PROXY   :", allowProxy);
    console.log("Server mode   :", portSummary);
    if (portMode !== "2") {
        console.log("CERT_PATH     :", certPath);
        console.log("KEY_PATH      :", keyPath);
    }
    console.log("====================\n");

    const confirm = await ask("Confirm and write .env file? (Y/n):\n> ");
    if (confirm.toLowerCase() !== "y") {
        console.log("❌ Aborted. No .env file was created.");
        rl.close();
        return;
    }

	const envContent = `
SESSION_PWD=${sessionPwd}
${portConfig}ALLOW_REGISTER=${allowRegister}
ALLOW_PROXY=${allowProxy}
CERT_PATH=${certPath}
KEY_PATH=${keyPath}
`.trim() + "\n";

	fs.writeFileSync(".env", envContent);
	console.clear();
	console.log("✅ .env file has been generated successfully!");
	rl.close();
})();
