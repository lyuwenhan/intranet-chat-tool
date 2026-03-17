[![Intranet Chat Tool Banner](./html/favicon.png)](./html/index.html)
# Intranet Chat Tool / 内网聊天工具

[![License](https://img.shields.io/badge/license-GPLv3-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-intranet-lightgrey?style=flat-square)](#)
[![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)](#)

A secure, extensible chat and code execution tool designed for internal networks.
一个为内网设计的安全、可扩展的聊天与代码执行系统。

---
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 (or any later version)

这个程序是自由软件：你可以在自由软件基金会发布的 GNU 通用公共许可证 第三版（或任何之后版本） 条款下，重新发布（redistribute）和/或修改（modify）它。
---

## 📖 Table of Contents / 目录
- [About / 项目简介](#about--项目简介)
- [Features / 功能特色](#features--功能特色)
- [Directory Structure / 目录结构](#directory-structure--目录结构)
- [Required Files / 必备文件](#required-files--必备文件)
- [Installation / 安装与运行](#installation--安装与运行)
- [License / 授权协议](#license--授权协议)

---

## About / 项目简介

This tool is a lightweight, extensible intranet communication platform featuring:
本工具是一个轻量、可扩展的内网交流平台，特点包括：

- 🧑‍💻 Online C++ execution / 在线 C++ 代码运行
- 💬 Real-time chat system / 实时聊天系统
- 🔐 User login and admin controls / 用户登录与管理权限
- 📁 File/image uploads / 支持文件与图片上传
- 📚 Markdown and MathJax support / 支持 Markdown 与数学公式渲染

---

## Features / 功能特色

- ✔️ Secure HTTPS with custom keys / 自定义 HTTPS 证书保障传输安全
- ✔️ Session-based authentication / 会话认证机制
- ✔️ Code execution logs / 运行与访问日志记录
- ✔️ Modular front-end with CodeMirror / 模块化前端，集成 CodeMirror 编辑器
- ✔️ Easy integration & local deployment / 易集成，可内网部署

---

## Directory Structure / 目录结构

> Partial structure below (detailed in main README):

```
html/               → Web front-end (登录、聊天、管理界面)
judge/              → C++ judging backend (含 judge.exe)
keys/               → HTTPS 证书 (cert.pem, key.pem)
data/               → Data storage (用户、封禁、计数等)
uploads/            → Uploaded content
log/                → System logs
node.js             → Main backend server
.env                → Environment config
```

---

## Required Files / 必备文件

> These files are required to run the system.
> 以下文件为运行本系统的必要条件：

- `html/` - All front-end pages and libraries / 所有前端资源
- `judge/judge.exe` - C++ code runner executable / C++ 判题程序
- `keys/cert.pem` & `keys/key.pem` - HTTPS certificates / HTTPS 证书
- `.env` - Session and port configuration / 会话密码与端口配置
- `node.js` - Main backend logic / 主后端逻辑
- `package.json`, `package-lock.json` - Dependency declarations / 依赖声明文件

---

## Installation / 安装与运行

## 1. Configure the initial environment / 配置初始环境

Please make sure your system has `node.js` (preferably version `v22.14.0`) , `docker` and `g++` installed.
请确认系统已安装 `node.js` (推荐使用 `v22.14.0` 版本) , `docker` 和 `g++`。

```bash
# 1. Install Node dependencies / 安装依赖
npm install

docker build -t judge-runner ./judge/

# for Windows
g++ judge/judge.cpp -o judge/judge.run -O2

#for Linux
g++ judge/judge.cpp -o judge/judge.run -O2
```

## 2. Add .env configuration / 添加环境配置

*You can generate the `.env` file by running the interactive script:*
*🛠️ *你可以运行交互式脚本来生成 `.env` 文件:*

```bash
node create-env.js
```

*Or copy the template `demo.env` into a file named `.env`:*
*或者将 `demo.env` 复制为 `.env` 文件使用:*

# 3. Run the server / 启动后端服务

```bash
node node.js
```

> Make sure `judge/judge.exe` *(Windows)* / `judge/judge.out` *(Linux)* and SSL keys are in place *(if you need https server)* .
> 请确保 `judge/judge.exe` *(Windows)* / `judge/judge.out` *(Linux)* 与 HTTPS 密钥存在 *(如果你需要 https 服务)* 。

---

## Get version updates (only for linux) / 获取版本更新 (仅 linux 可用)

```bash
chmod u+x update.sh
./update.sh
```

> This script resets local changes and pulls the latest code from the remote main branch.
> 为确保本地代码为最新版本，并避免冲突，请定期运行此脚本。

---

## License / 授权协议

This project is licensed under the **GNU General Public License v3.0**
本项目采用 **GNU 通用公共许可证 第三版（GPL v3）** 授权。

> You are free to use, modify, and distribute this software under the terms of the GPL.
> 你可以在 GPL 协议条款下自由使用、修改和传播本软件。

By using or distributing this software, you agree to:
- Provide access to source code when distributing;
- License your modifications under the same GPL license;
- Retain copyright and license notices.

通过使用或分发本软件，你同意：
- 分发时提供源码；
- 派生作品也需遵守 GPL 协议；
- 保留原始的版权与许可证信息。

📄 See [LICENSE](./LICENSE) for the full legal text.
📄 完整协议条款请见 [LICENSE](./LICENSE) 文件。

---

欢迎交流与改进建议！Feel free to contribute or suggest enhancements!
