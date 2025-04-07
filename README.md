[![Intranet Chat Tool Banner](./html/favicon.png)](./html/index.html)
# Intranet Chat Tool / 内网聊天工具

[![License](https://img.shields.io/badge/license-MIT--NC-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-intranet-lightgrey?style=flat-square)](#)
[![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)](#)

A secure, extensible chat and code execution tool designed for internal networks.  
一个为内网设计的安全、可扩展的聊天与代码执行系统。

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

```bash
# 1. Install Node dependencies / 安装依赖
npm install

# 2. Add .env configuration / 添加环境配置
# session_pwd=your_secret_key
# port=443
# port_http=80

# 3. Run the server / 启动后端服务
node node.js
```

> Make sure judge.exe and SSL keys are in place.  
> 请确保 `judge.exe` 与 HTTPS 密钥存在。

---

## License / 授权协议

Custom Non-Commercial License (MIT-Based)
非商业许可证（基于 MIT 协议）
```
© 2025 lyuwenhan

Permission granted for private or educational use only.  
仅允许用于私人或教学用途，禁止任何形式的商业使用。
```

See [LICENSE](./LICENSE) for full terms. / 详见 LICENSE 文件。

---

欢迎交流与改进建议！Feel free to contribute or suggest enhancements!
