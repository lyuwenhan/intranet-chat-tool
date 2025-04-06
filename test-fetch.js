const http = require('http');

function sendRequest(url, method, body = {}) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(body);

        // 解析URL
        const urlObj = new URL(url);

        // 配置请求选项
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || 80, // 默认80端口
            path: urlObj.pathname,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': data.length
            }
        };

        // 发送请求
        const req = http.request(options, (res) => {
            let responseData = '';

            // 收集响应数据
            res.on('data', (chunk) => {
                responseData += chunk;
            });

            // 响应结束后处理
            res.on('end', () => {
                try {
                    const jsonResponse = JSON.parse(responseData);
                    resolve(jsonResponse);
                } catch (e) {
                    reject(new Error('无法解析响应数据'));
                }
            });
        });

        // 请求错误处理
        req.on('error', (e) => {
            reject(e);
        });

        // 写入请求数据
        req.write(data);

        // 结束请求
        req.end();
    });
}

// 示例：调用封装函数，发送请求到172.0.40.102:8090
a=""
	sendRequest('http://192.168.40.199:8080', 'POST', {
		content: {
			type: 'send',
			username: 't',
			info: 'Hello, world!',
		}
	})
		.then(res => {
			a= res;
			console.log(a);
		})
		.catch(err => {
			console.error('请求失败:', err);
		});
