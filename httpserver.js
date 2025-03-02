const http = require('http');
const fs = require('fs');
const path = require('path');
const mime = require('mime-types');

// 记录服务器进程 ID
fs.writeFileSync("pid.txt", process.pid.toString() + " ");

// 服务器端口
const PORT = 8000;
const HOST = "0.0.0.0";

// 静态文件目录
const CLIENT_DIR = path.join(__dirname, "html");

// 安全解析请求路径，防止目录遍历攻击
function getSafePath(urlPath) {
    let safeUrlPath = decodeURIComponent(urlPath.split("?")[0]); // 处理 URL 编码和查询参数
    let safePath = path.normalize(path.join(CLIENT_DIR, safeUrlPath));
    if (!safePath.startsWith(CLIENT_DIR) || safePath.includes('\0')) {
        return null;
    }
    return safePath;
}

// 读取文件内容（使用 Promise 以支持 async/await）
async function readFileAsync(filePath) {
    return fs.promises.readFile(filePath);
}

// 处理请求
async function requestHandler(req, res) {
    try {
        // 解析 URL 并获取安全路径
        let safePath = getSafePath(req.url);

        if (!safePath) {
            res.writeHead(403, { "Content-Type": "text/plain" });
            return res.end("403 Forbidden");
        }

        // 获取文件的 Content-Type
        let contentType = mime.lookup(safePath) || "application/octet-stream";

        try {
            // 读取请求的文件
            let fileContent = await readFileAsync(safePath);
            res.writeHead(200, { 
                "Content-Type": contentType,
                "Cache-Control": "public, max-age=3600" // 1 小时缓存
            });
            return res.end(fileContent);
        } catch (err) {
            // 文件不存在，返回 index.html（SPA 支持）
            let fallbackPath = path.join(CLIENT_DIR, "index.html");
            try {
                let fallbackContent = await readFileAsync(fallbackPath);
                res.writeHead(200, { "Content-Type": "text/html" });
                return res.end(fallbackContent);
            } catch (fallbackErr) {
                res.writeHead(404, { "Content-Type": "text/plain" });
                return res.end("404 Not Found");
            }
        }
    } catch (err) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("500 Internal Server Error");
    }
}

// 创建 HTTP 服务器
const server = http.createServer(async (req, res) => {
    // 处理 CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, content-type');

    // 处理 OPTIONS 预检请求
    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        return res.end();
    }

    await requestHandler(req, res);
});

// 启动服务器
server.listen(PORT, HOST, () => {
    console.log(`服务器正在运行: http://${HOST}:${PORT}`);
});
