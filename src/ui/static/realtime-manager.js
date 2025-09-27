/**
 * 实时请求连接管理器
 * 负责管理与多个代理服务的WebSocket连接和事件分发
 */
class RealTimeManager {
    constructor() {
        this.connections = new Map(); // service -> WebSocket
        this.reconnectAttempts = new Map(); // service -> number
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000; // 起始延迟1秒
        this.listeners = new Set();
        this.isDestroyed = false;

        // 服务配置
        this.services = [
            { name: 'claude', port: 3210 },
            { name: 'codex', port: 3211 }
        ];

        // 连接状态
        this.connectionStatus = new Map();
        this.services.forEach(service => {
            this.connectionStatus.set(service.name, false);
        });
    }

    /**
     * 添加事件监听器
     * @param {Function} callback 事件回调函数
     * @returns {Function} 取消监听的函数
     */
    addListener(callback) {
        if (typeof callback !== 'function') {
            throw new Error('回调函数必须是一个函数');
        }
        this.listeners.add(callback);
        return () => this.listeners.delete(callback);
    }

    /**
     * 连接所有服务
     */
    async connectAll() {
        if (this.isDestroyed) {
            console.warn('管理器已销毁，无法连接服务');
            return;
        }

        console.log('开始连接所有实时服务...');

        for (const service of this.services) {
            this.connect(service.name, service.port);
        }
    }

    /**
     * 连接单个服务
     * @param {string} serviceName 服务名称
     * @param {number} port 端口号
     */
    connect(serviceName, port) {
        if (this.isDestroyed) {
            console.warn(`管理器已销毁，无法连接服务 ${serviceName}`);
            return;
        }

        // 如果已经有连接且状态正常，则跳过
        const existingWs = this.connections.get(serviceName);
        if (existingWs && existingWs.readyState === WebSocket.OPEN) {
            console.log(`${serviceName} WebSocket已连接，跳过重复连接`);
            return;
        }

        // 采用 HttpOnly Cookie 的 JWT，握手会自动携带 Cookie
        const wsUrl = `ws://${window.location.hostname}:${port}/ws/realtime`;
        console.log(`正在连接 ${serviceName} WebSocket: ${wsUrl}`);

        try {
            const ws = new WebSocket(wsUrl);

            // 设置连接超时
            const connectTimeout = setTimeout(() => {
                if (ws.readyState === WebSocket.CONNECTING) {
                    console.error(`${serviceName} WebSocket连接超时`);
                    ws.close();
                    // 连接超时时也触发重连
                    this.scheduleReconnect(serviceName, port);
                }
            }, 5000); // 5秒超时，更快响应

            ws.onopen = () => {
                clearTimeout(connectTimeout);
                console.log(`${serviceName} WebSocket 连接成功`);
                this.connections.set(serviceName, ws);
                this.reconnectAttempts.set(serviceName, 0);
                this.connectionStatus.set(serviceName, true);

                // 发送心跳
                this.startHeartbeat(serviceName, ws);

                // 通知连接成功
                this.notifyListeners({
                    type: 'connection',
                    service: serviceName,
                    status: 'connected'
                });

            };

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);

                    // 过滤心跳消息
                    if (data.type === 'ping') {
                        return;
                    }

                    // 统一分发事件，确保事件带有服务标识
                    this.notifyListeners({
                        ...data,
                        service: serviceName
                    });
                } catch (error) {
                    console.error(`解析 ${serviceName} WebSocket 消息失败:`, error, event.data);
                }
            };

            ws.onclose = (event) => {
                clearTimeout(connectTimeout);
                console.log(`${serviceName} WebSocket 连接关闭`, event.code, event.reason);

                this.connections.delete(serviceName);
                this.connectionStatus.set(serviceName, false);

                // 通知连接断开
                this.notifyListeners({
                    type: 'connection',
                    service: serviceName,
                    status: 'disconnected',
                    code: event.code,
                    reason: event.reason
                });

                // 未鉴权提示与引导
                if (event.code === 1008) {
                    try {
                        window.ElementPlus && window.ElementPlus.ElMessage && window.ElementPlus.ElMessage.warning('需要登录以建立实时连接');
                        setTimeout(() => { window.location.href = '/login'; }, 300);
                    } catch (_) {}
                }

                // 非正常关闭时自动重连
                if (!this.isDestroyed && event.code !== 1000) {
                    this.scheduleReconnect(serviceName, port);
                }
            };

            ws.onerror = (error) => {
                clearTimeout(connectTimeout);
                console.error(`${serviceName} WebSocket 错误:`, error);

                // 通知连接错误
                this.notifyListeners({
                    type: 'connection',
                    service: serviceName,
                    status: 'error',
                    error: error
                });

                // 连接错误时也触发重连
                this.scheduleReconnect(serviceName, port);
            };

        } catch (error) {
            console.error(`创建 ${serviceName} WebSocket 连接失败:`, error);
            this.scheduleReconnect(serviceName, port);
        }
    }

    /**
     * 启动心跳机制
     * @param {string} serviceName 服务名称
     * @param {WebSocket} ws WebSocket连接
     */
    startHeartbeat(serviceName, ws) {
        const heartbeatInterval = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
                try {
                    ws.send('{"type":"ping"}');
                } catch (error) {
                    console.error(`${serviceName} 心跳发送失败:`, error);
                    clearInterval(heartbeatInterval);
                }
            } else {
                clearInterval(heartbeatInterval);
            }
        }, 30000); // 30秒心跳

        // WebSocket关闭时清理心跳
        ws.addEventListener('close', () => {
            clearInterval(heartbeatInterval);
        });
    }

    /**
     * 重连调度
     * @param {string} serviceName 服务名称
     * @param {number} port 端口号
     */
    scheduleReconnect(serviceName, port) {
        if (this.isDestroyed) {
            return;
        }

        const attempts = this.reconnectAttempts.get(serviceName) || 0;
        if (attempts >= this.maxReconnectAttempts) {
            console.error(`${serviceName} 重连次数超限 (${attempts}/${this.maxReconnectAttempts})，停止重连`);
            return;
        }

        // 前3次快速重连，之后使用指数退避
        let delay;
        if (attempts < 3) {
            delay = 2000; // 前3次每2秒重连一次
        } else {
            delay = this.reconnectDelay * Math.pow(2, attempts - 3);
        }

        this.reconnectAttempts.set(serviceName, attempts + 1);

        console.log(`${serviceName} 将在 ${delay}ms 后重连... (尝试 ${attempts + 1}/${this.maxReconnectAttempts})`);

        setTimeout(() => {
            if (!this.isDestroyed) {
                this.connect(serviceName, port);
            }
        }, delay);
    }

    /**
     * 通知所有监听器
     * @param {Object} event 事件对象
     */
    notifyListeners(event) {
        if (this.listeners.size === 0) {
            return;
        }

        this.listeners.forEach(listener => {
            try {
                listener(event);
            } catch (error) {
                console.error('事件监听器执行错误:', error);
            }
        });
    }

    /**
     * 获取连接状态
     * @returns {Object} 各服务的连接状态
     */
    getConnectionStatus() {
        const status = {};
        this.services.forEach(service => {
            const ws = this.connections.get(service.name);
            status[service.name] = ws ? ws.readyState === WebSocket.OPEN : false;
        });
        return status;
    }

    /**
     * 获取连接统计信息
     * @returns {Object} 连接统计
     */
    getConnectionStats() {
        let connected = 0;
        let total = this.services.length;

        this.services.forEach(service => {
            const ws = this.connections.get(service.name);
            if (ws && ws.readyState === WebSocket.OPEN) {
                connected++;
            }
        });

        return {
            connected,
            total,
            services: this.getConnectionStatus()
        };
    }

    /**
     * 手动重连指定服务
     * @param {string} serviceName 服务名称
     */
    reconnectService(serviceName) {
        const service = this.services.find(s => s.name === serviceName);
        if (!service) {
            console.error(`未知服务: ${serviceName}`);
            return;
        }

        const ws = this.connections.get(serviceName);
        if (ws) {
            ws.close();
        }

        // 重置重连计数器，从头开始重连
        this.reconnectAttempts.set(serviceName, 0);
        this.connect(serviceName, service.port);
    }

    /**
     * 手动重连所有服务
     */
    reconnectAll() {
        console.log('手动重连所有服务...');
        // 重置所有服务的重连计数器
        this.services.forEach(service => {
            this.reconnectAttempts.set(service.name, 0);
        });

        this.services.forEach(service => {
            this.reconnectService(service.name);
        });
    }

    /**
     * 销毁管理器
     */
    destroy() {
        console.log('正在销毁RealTimeManager...');
        this.isDestroyed = true;

        // 关闭所有连接
        this.connections.forEach((ws, serviceName) => {
            if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
                console.log(`关闭 ${serviceName} WebSocket连接`);
                ws.close(1000, '管理器销毁');
            }
        });

        // 清理状态
        this.connections.clear();
        this.listeners.clear();
        this.reconnectAttempts.clear();
        this.connectionStatus.clear();

        console.log('RealTimeManager 已销毁');
    }

    /**
     * 获取管理器状态信息
     * @returns {Object} 状态信息
     */
    getStatus() {
        return {
            isDestroyed: this.isDestroyed,
            connections: this.getConnectionStats(),
            listeners: this.listeners.size,
            services: this.services.map(service => ({
                name: service.name,
                port: service.port,
                connected: this.connectionStatus.get(service.name),
                reconnectAttempts: this.reconnectAttempts.get(service.name) || 0
            }))
        };
    }
}

// 导出类供其他模块使用
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RealTimeManager;
}

// 全局命名空间支持（浏览器环境）
if (typeof window !== 'undefined') {
    window.RealTimeManager = RealTimeManager;
}
