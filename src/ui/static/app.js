// Vue 3 + Element Plus CLI Proxy Monitor Application
const { createApp, ref, reactive, onMounted, nextTick, watch } = Vue;
const { ElMessage, ElMessageBox } = ElementPlus;

const app = createApp({
    setup() {
        // 响应式数据
        const loading = ref(false);
        const logsLoading = ref(false);
        const allLogsLoading = ref(false);
        const configSaving = ref(false);
        const filterSaving = ref(false);
        const lastUpdate = ref('加载中...');
        
        // 服务状态数据
        const services = reactive({
            claude: {
                running: false,
                pid: null,
                config: ''
            },
            codex: {
                running: false,
                pid: null,
                config: ''
            }
        });
        
        // 统计数据
        const stats = reactive({
            requestCount: 0,
            configCount: 0,
            filterCount: 0
        });
        
        // 日志数据
        const logs = ref([]);
        const allLogs = ref([]);
        
        // 配置选项
        const claudeConfigs = ref([]);
        const codexConfigs = ref([]);
        
        // 抽屉状态
        const configDrawerVisible = ref(false);
        const filterDrawerVisible = ref(false);
        const logDetailVisible = ref(false);
        const allLogsVisible = ref(false);
        const activeConfigTab = ref('claude');
        const activeLogTab = ref('basic'); // 日志详情Tab状态
        
        // 配置内容
        const configContents = reactive({
            claude: '',
            codex: ''
        });
        const filterContent = ref('');
        const filterRules = ref([]);  // 过滤规则数组

        // 友好表单的配置数据
        const friendlyConfigs = reactive({
            claude: [],  // [{ name, baseUrl, authType, authValue, active }]
            codex: []
        });

        // 配置编辑模式 'interactive' | 'json'
        const configEditMode = ref('interactive');

        // 新增站点编辑状态
        const editingNewSite = reactive({
            claude: false,
            codex: false
        });

        // 新站点数据
        const newSiteData = reactive({
            claude: {
                name: '',
                baseUrl: 'https://',
                authType: 'auth_token',
                authValue: '',
                active: false
            },
            codex: {
                name: '',
                baseUrl: 'https://',
                authType: 'auth_token',
                authValue: '',
                active: false
            }
        });

        // 测试功能相关数据
        const modelSelectorVisible = ref(false);
        const testResultVisible = ref(false);
        const testingConnection = ref(false);
        const testConfig = reactive({
            service: '',
            siteData: null,
            isNewSite: false,
            siteIndex: -1,
            model: '',
            reasoningEffort: ''
        });
        const lastTestResult = reactive({
            success: false,
            status_code: null,
            response_text: '',
            target_url: '',
            error_message: null
        });

        // 新站点测试结果
        const newSiteTestResult = reactive({
            claude: null,
            codex: null
        });

        // 测试响应数据弹窗
        const testResponseDialogVisible = ref(false);
        const testResponseData = ref('');

        // 同步状态控制，防止循环调用
        const syncInProgress = ref(false);
        const selectedLog = ref(null);
        const decodedRequestBody = ref(''); // 解码后的请求体（转换后）
        const decodedOriginalRequestBody = ref(''); // 解码后的原始请求体
        const decodedResponseContent = ref(''); // 解码后的响应内容

        // 实时请求相关数据
        const realtimeRequests = ref([]);
        const realtimeDetailVisible = ref(false);
        const selectedRealtimeRequest = ref(null);
        const connectionStatus = reactive({ claude: false, codex: false });
        const realtimeManager = ref(null);
        const maxRealtimeRequests = 20;

        // 请求状态映射
        const REQUEST_STATUS = {
            PENDING: { text: '已请求', type: 'warning' },
            STREAMING: { text: '接收中', type: 'primary' },
            COMPLETED: { text: '已完成', type: 'success' },
            FAILED: { text: '失败', type: 'danger' }
        };

        const metricKeys = ['input', 'cached_create', 'cached_read', 'output', 'reasoning', 'total'];
        const createEmptyMetrics = () => ({
            input: 0,
            cached_create: 0,
            cached_read: 0,
            output: 0,
            reasoning: 0,
            total: 0
        });
        const createEmptyFormatted = () => {
            const formatted = {};
            metricKeys.forEach(key => {
                formatted[key] = '0';
            });
            return formatted;
        };

        const usageSummary = reactive({
            totals: createEmptyMetrics(),
            formattedTotals: createEmptyFormatted(),
            perService: {}
        });
        const usageDrawerVisible = ref(false);
        const usageDetailsLoading = ref(false);
        const usageDetails = reactive({
            totals: {
                metrics: createEmptyMetrics(),
                formatted: createEmptyFormatted()
            },
            services: {}
        });
        const usageMetricLabels = {
            input: '输入',
            cached_create: '缓存创建',
            cached_read: '缓存读取',
            output: '输出',
            reasoning: '思考',
            total: '总计'
        };
        
        const normalizeUsageBlock = (block) => {
            const isMetricsMap = block && typeof block === 'object' && !Array.isArray(block) && metricKeys.some(key => key in block);
            const metricsSource = isMetricsMap ? block : (block?.metrics || {});
            const formattedSource = block?.formatted || {};
            const displayMetricsSource = block?.displayMetrics || metricsSource;
            const displayFormattedSource = block?.displayFormatted || formattedSource;

            return {
                metrics: Object.assign(createEmptyMetrics(), metricsSource || {}),
                formatted: Object.assign(createEmptyFormatted(), formattedSource || {}),
                displayMetrics: Object.assign(createEmptyMetrics(), displayMetricsSource || {}),
                displayFormatted: Object.assign(createEmptyFormatted(), displayFormattedSource || {}),
            };
        };

        const resetUsageSummary = () => {
            usageSummary.totals = createEmptyMetrics();
            usageSummary.formattedTotals = createEmptyFormatted();
            usageSummary.perService = {};
        };

        const resetUsageDetails = () => {
            usageDetails.totals = normalizeUsageBlock({});
            usageDetails.services = {};
        };

        const formatUsageValue = (value) => {
            const num = Number(value || 0);
            if (!Number.isFinite(num)) {
                return '-';
            }
            const intVal = Math.trunc(num);
            if (intVal >= 1_000_000) {
                const short = Math.floor(intVal / 100_000) / 10;
                return `${intVal} (${short.toFixed(1)}m)`;
            }
            if (intVal >= 1_000) {
                const short = Math.floor(intVal / 100) / 10;
                return `${intVal} (${short.toFixed(1)}k)`;
            }
            return `${intVal}`;
        };

        const getNumeric = (value) => {
            const num = Number(value || 0);
            return Number.isFinite(num) ? num : 0;
        };

        const updateFormattedFromMetrics = (block) => {
            if (!block) {
                return block;
            }
            if (!block.metrics) {
                block.metrics = createEmptyMetrics();
            }
            if (!block.displayMetrics) {
                block.displayMetrics = Object.assign(createEmptyMetrics(), block.metrics);
            }
            if (!block.displayFormatted) {
                block.displayFormatted = createEmptyFormatted();
            }
            metricKeys.forEach(key => {
                block.displayFormatted[key] = formatUsageValue(getNumeric(block.displayMetrics?.[key]));
            });
            block.formatted = block.displayFormatted;
            return block;
        };

        const adjustUsageBlockForService = (service, block) => {
            const normalized = normalizeUsageBlock(block);
            if (!normalized.metrics) {
                return normalized;
            }
            if (service === 'codex') {
                const cachedRead = getNumeric(normalized.metrics.cached_read);
                const adjustedInput = Math.max(0, getNumeric(normalized.metrics.input) - cachedRead);
                const adjustedTotal = Math.max(0, getNumeric(normalized.metrics.total) - cachedRead);
                normalized.displayMetrics.input = adjustedInput;
                normalized.displayMetrics.total = adjustedTotal;
                normalized.displayMetrics.cached_read = getNumeric(normalized.metrics.cached_read);
            } else {
                normalized.displayMetrics = Object.assign(createEmptyMetrics(), normalized.metrics);
            }
            return updateFormattedFromMetrics(normalized);
        };

        const mergeMetricsInto = (target, sourceMetrics) => {
            if (!sourceMetrics) {
                return;
            }
            metricKeys.forEach(key => {
                target[key] = getNumeric(target[key]) + getNumeric(sourceMetrics?.[key]);
            });
        };

        const formatUsageSummary = (usage, serviceOverride = null) => {
            if (!usage || !usage.metrics) {
                return '-';
            }
            const metrics = usage.metrics;
            const service = serviceOverride || usage.service || '';
            const cachedRead = getNumeric(metrics.cached_read);
            const displayInput = service === 'codex'
                ? Math.max(0, getNumeric(metrics.input) - cachedRead)
                : getNumeric(metrics.input);
            const displayTotal = service === 'codex'
                ? Math.max(0, getNumeric(metrics.total) - cachedRead)
                : getNumeric(metrics.total);
            const displayOutput = getNumeric(metrics.output);

            return [
                `IN ${formatUsageValue(displayInput)}`,
                `OUT ${formatUsageValue(displayOutput)}`,
                `Total ${formatUsageValue(displayTotal)}`
            ].join('\n');
        };

        const getUsageFormattedValue = (block, key) => {
            if (!block) return '-';
            const formattedBlock = block.displayFormatted || block.formatted;
            if (formattedBlock && formattedBlock[key]) {
                return formattedBlock[key];
            }
            const metricsSource = block.displayMetrics || block.metrics;
            if (metricsSource) {
                return formatUsageValue(metricsSource[key]);
            }
            return '-';
        };

        const formatChannelName = (name) => {
            if (!name) return '未知';
            return name === 'unknown' ? '未标记' : name;
        };

        // 获取模型选项
        const getModelOptions = (service) => {
            if (service === 'claude') {
                return [
                    { label: 'claude-sonnet-4', value: 'claude-sonnet-4-20250514' },
                    { label: 'claude-opus-4', value: 'claude-opus-4-20250514' },
                    { label: 'claude-opus-4-1', value: 'claude-opus-4-1-20250805' }
                ];
            } else if (service === 'codex') {
                return [
                    { label: 'gpt-5-codex', value: 'gpt-5-codex' },
                    { label: 'gpt-5', value: 'gpt-5' }
                ];
            }
            return [];
        };

        // 测试新增站点连接
        const testNewSiteConnection = (service) => {
            const siteData = newSiteData[service];
            if (!siteData.name || !siteData.baseUrl || !siteData.authValue) {
                ElMessage.warning('请先填写完整的站点信息');
                return;
            }
            showModelSelector(service, siteData, true);
        };

        // 测试现有站点连接
        const testSiteConnection = (service, siteIndex) => {
            const siteData = friendlyConfigs[service][siteIndex];
            if (!siteData.name || !siteData.baseUrl || !siteData.authValue) {
                ElMessage.warning('站点信息不完整');
                return;
            }
            showModelSelector(service, siteData, false, siteIndex);
        };

        // 显示模型选择器
        const showModelSelector = (service, siteData, isNewSite = false, siteIndex = -1) => {
            testConfig.service = service;
            testConfig.siteData = siteData;
            testConfig.isNewSite = isNewSite;
            testConfig.siteIndex = siteIndex;
            testConfig.model = '';

            // 重置测试结果
            Object.assign(lastTestResult, {
                success: false,
                status_code: null,
                response_text: '',
                target_url: '',
                error_message: null
            });

            // 设置默认模型
            const options = getModelOptions(service);
            if (options.length > 0) {
                testConfig.model = options[0].value;
            }

            // 设置默认reasoning effort
            if (service === 'codex') {
                testConfig.reasoningEffort = 'high';
            } else {
                testConfig.reasoningEffort = '';
            }

            modelSelectorVisible.value = true;
        };

        // 取消模型选择
        const cancelModelSelection = () => {
            modelSelectorVisible.value = false;
            testConfig.service = '';
            testConfig.siteData = null;
            testConfig.isNewSite = false;
            testConfig.siteIndex = -1;
            testConfig.model = '';
            testConfig.reasoningEffort = '';
        };

        // 确认模型选择并开始测试
        const confirmModelSelection = async () => {
            if (!testConfig.model) {
                ElMessage.warning('请选择要测试的模型');
                return;
            }

            // 重置测试结果
            Object.assign(lastTestResult, {
                success: false,
                status_code: null,
                response_text: '',
                target_url: '',
                error_message: null
            });

            testingConnection.value = true;
            // 不关闭弹窗，在弹窗中显示测试结果

            try {
                const siteData = testConfig.siteData;
                const requestData = {
                    service: testConfig.service,
                    model: testConfig.model,
                    base_url: siteData.baseUrl
                };

                // 根据认证类型设置认证信息
                if (siteData.authType === 'auth_token') {
                    requestData.auth_token = siteData.authValue;
                } else {
                    requestData.api_key = siteData.authValue;
                }

                // 如果是codex且设置了reasoning effort，添加扩展参数
                if (testConfig.service === 'codex' && testConfig.reasoningEffort) {
                    requestData.extra_params = {
                        reasoning_effort: testConfig.reasoningEffort
                    };
                }

                const result = await fetchWithErrorHandling('/api/test-connection', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(requestData)
                });

                // 将测试结果存储到弹窗显示的变量中
                Object.assign(lastTestResult, result);

                // 同时更新对应的测试结果存储位置
                if (testConfig.isNewSite) {
                    // 新站点测试结果
                    newSiteTestResult[testConfig.service] = { ...result };
                } else {
                    // 现有站点测试结果
                    if (friendlyConfigs[testConfig.service] && friendlyConfigs[testConfig.service][testConfig.siteIndex]) {
                        friendlyConfigs[testConfig.service][testConfig.siteIndex].testResult = { ...result };
                    }
                }

                // 不再显示消息提示，结果已在弹窗中显示

            } catch (error) {
                const errorResult = {
                    success: false,
                    status_code: null,
                    response_text: error.message,
                    target_url: '',
                    error_message: error.message
                };

                // 将错误结果存储到弹窗显示的变量中
                Object.assign(lastTestResult, errorResult);

                // 同时更新对应的测试结果存储位置
                if (testConfig.isNewSite) {
                    newSiteTestResult[testConfig.service] = { ...errorResult };
                } else {
                    if (friendlyConfigs[testConfig.service] && friendlyConfigs[testConfig.service][testConfig.siteIndex]) {
                        friendlyConfigs[testConfig.service][testConfig.siteIndex].testResult = { ...errorResult };
                    }
                }
            } finally {
                testingConnection.value = false;
            }
        };

        // 复制测试结果
        const copyTestResult = async () => {
            try {
                await copyToClipboard(lastTestResult.response_text);
            } catch (error) {
                ElMessage.error('复制失败');
            }
        };

        // 显示测试响应数据
        const showTestResponse = (type, service, index = null) => {
            let responseText = '';
            if (type === 'newSite') {
                responseText = newSiteTestResult[service]?.response_text || '';
            } else if (type === 'site' && index !== null) {
                responseText = friendlyConfigs[service][index]?.testResult?.response_text || '';
            }

            if (responseText) {
                testResponseData.value = responseText;
                testResponseDialogVisible.value = true;
            } else {
                ElMessage.warning('没有响应数据');
            }
        };

        // 复制测试响应数据
        const copyTestResponseData = async () => {
            try {
                await copyToClipboard(testResponseData.value);
            } catch (error) {
                ElMessage.error('复制失败');
            }
        };

        // 格式化服务和渠道组合显示（换行形式）
        const formatServiceWithChannel = (service, channel) => {
            const serviceName = service || '-';
            if (!channel || channel === 'unknown') {
                return serviceName;
            }
            return `${serviceName}\n[${channel}]`;
        };

        // 格式化方法和URL的组合
        const formatMethodWithURL = (method, url) => {
            const methodName = method || 'GET';
            const urlPath = url || '-';
            return `[${methodName}] ${urlPath}`;
        };

        const loadUsageDetails = async () => {
            usageDetailsLoading.value = true;
            try {
                const data = await fetchWithErrorHandling('/api/usage/details');
                const services = {};
                const serviceEntries = Object.entries(data.services || {});
                serviceEntries.forEach(([service, payload]) => {
                    const overallBlock = adjustUsageBlockForService(service, payload?.overall || {});
                    const channels = {};
                    Object.entries(payload?.channels || {}).forEach(([channel, channelPayload]) => {
                        if (!channel || channel === 'unknown') {
                            return;
                        }
                        channels[channel] = adjustUsageBlockForService(service, channelPayload || {});
                    });
                    services[service] = {
                        overall: overallBlock,
                        channels
                    };
                });
                usageDetails.services = services;

                if (serviceEntries.length === 0) {
                    usageDetails.totals = adjustUsageBlockForService('codex', data.totals || {});
                } else {
                    const totalMetrics = createEmptyMetrics();
                    serviceEntries.forEach(([service]) => {
                        mergeMetricsInto(totalMetrics, services[service]?.overall?.displayMetrics || services[service]?.overall?.metrics);
                    });
                    usageDetails.totals = updateFormattedFromMetrics({
                        metrics: Object.assign(createEmptyMetrics(), totalMetrics),
                        displayMetrics: Object.assign(createEmptyMetrics(), totalMetrics),
                        formatted: createEmptyFormatted()
                    });
                }
            } catch (error) {
                resetUsageDetails();
                ElMessage.error('获取Usage详情失败: ' + error.message);
            } finally {
                usageDetailsLoading.value = false;
            }
        };

        const openUsageDrawer = async () => {
            usageDrawerVisible.value = true;
            await loadUsageDetails();
        };

        const closeUsageDrawer = () => {
            usageDrawerVisible.value = false;
        };

        // 清空Token使用数据
        const clearUsageData = async () => {
            try {
                await ElMessageBox.confirm(
                    '确定要清空所有Token使用记录吗？此操作将清空所有日志并重置Token统计数据，不可撤销。',
                    '确认清空Token',
                    {
                        confirmButtonText: '确定',
                        cancelButtonText: '取消',
                        type: 'warning',
                    }
                );

                const result = await fetchWithErrorHandling('/api/usage/clear', {
                    method: 'DELETE'
                });

                if (result.success) {
                    ElMessage.success('Token使用记录已清空');
                    // 刷新页面数据
                    window.location.reload();
                } else {
                    ElMessage.error('清空Token失败: ' + (result.error || '未知错误'));
                }
            } catch (error) {
                if (error !== 'cancel') {
                    ElMessage.error('清空Token失败: ' + error.message);
                }
            }
        };

        // API 请求方法
        const fetchWithErrorHandling = async (url, options = {}) => {
            try {
                const response = await fetch(url, options);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return await response.json();
            } catch (error) {
                console.error(`API请求失败 ${url}:`, error);
                throw error;
            }
        };
        
        // 加载状态数据
        const loadStatus = async () => {
            try {
                const data = await fetchWithErrorHandling('/api/status');
                updateServiceStatus(data);
                updateStats(data);
            } catch (error) {
                ElMessage.error('获取状态失败: ' + error.message);
            }
        };
        
        // 更新服务状态
        const updateServiceStatus = (data) => {
            if (data.services?.claude) {
                Object.assign(services.claude, data.services.claude);
            }
            if (data.services?.codex) {
                Object.assign(services.codex, data.services.codex);
            }
        };
        
        // 更新统计信息
        const updateStats = (data) => {
            stats.requestCount = data.request_count || 0;
            stats.configCount = data.config_count || 0;
            stats.filterCount = data.filter_count || 0;

            const summary = data.usage_summary || null;
            if (summary) {
                const perService = {};
                const totalMetrics = createEmptyMetrics();
                Object.entries(summary.per_service || {}).forEach(([service, payload]) => {
                    if (!service || service === 'unknown') {
                        return;
                    }
                    const adjusted = adjustUsageBlockForService(service, payload || {});
                    perService[service] = adjusted;
                    mergeMetricsInto(totalMetrics, adjusted.displayMetrics || adjusted.metrics);
                });

                ['claude', 'codex'].forEach(service => {
                    if (!perService[service]) {
                        perService[service] = adjustUsageBlockForService(service, {});
                    }
                });

                usageSummary.perService = perService;

                let totalsBlock;
                if (Object.keys(perService).length === 0 && summary.totals) {
                    totalsBlock = adjustUsageBlockForService('codex', summary.totals || {});
                } else {
                    totalsBlock = updateFormattedFromMetrics({
                        metrics: Object.assign(createEmptyMetrics(), totalMetrics),
                        displayMetrics: Object.assign(createEmptyMetrics(), totalMetrics),
                        formatted: createEmptyFormatted()
                    });
                }
                usageSummary.totals = Object.assign(createEmptyMetrics(), totalsBlock.displayMetrics || totalsBlock.metrics);
                usageSummary.formattedTotals = Object.assign(createEmptyFormatted(), totalsBlock.displayFormatted || totalsBlock.formatted);
            } else {
                resetUsageSummary();
            }
        };
        
        // 加载日志
        const loadLogs = async () => {
            logsLoading.value = true;
            try {
                const data = await fetchWithErrorHandling('/api/logs');
                logs.value = Array.isArray(data) ? data : [];
            } catch (error) {
                ElMessage.error('获取日志失败: ' + error.message);
                logs.value = [];
            } finally {
                logsLoading.value = false;
            }
        };
        
        // 加载配置选项
        const loadConfigOptions = async () => {
            try {
                // 加载Claude配置选项
                const claudeData = await fetchWithErrorHandling('/api/config/claude');
                if (claudeData.content) {
                    const configs = JSON.parse(claudeData.content);
                    claudeConfigs.value = Object.keys(configs).filter(key => 
                        key && key !== 'undefined' && configs[key] !== undefined
                    );
                }
                
                // 加载Codex配置选项
                const codexData = await fetchWithErrorHandling('/api/config/codex');
                if (codexData.content) {
                    const configs = JSON.parse(codexData.content);
                    codexConfigs.value = Object.keys(configs).filter(key => 
                        key && key !== 'undefined' && configs[key] !== undefined
                    );
                }
            } catch (error) {
                console.error('加载配置选项失败:', error);
            }
        };
        
        // 主数据加载方法
        const loadData = async () => {
            loading.value = true;
            try {
                await loadConfigOptions();
                await Promise.all([
                    loadStatus(),
                    loadLogs()
                ]);
                updateLastUpdateTime();
            } catch (error) {
                console.error('加载数据失败:', error);
                ElMessage.error('数据加载失败');
            } finally {
                loading.value = false;
            }
        };
        
        // 刷新页面
        const refreshData = () => {
            window.location.reload();
        };
        
        // 更新最后更新时间
        const updateLastUpdateTime = () => {
            const now = new Date();
            const timeString = now.toLocaleTimeString('zh-CN', { hour12: false });
            lastUpdate.value = `最后更新: ${timeString}`;
        };
        
        // 配置切换
        const switchConfig = async (serviceName, configName) => {
            if (!configName) return;
            
            try {
                const result = await fetchWithErrorHandling('/api/switch-config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        service: serviceName,
                        config: configName
                    })
                });
                
                if (result.success) {
                    ElMessage.success(`${serviceName}配置已切换到: ${configName}`);
                    // 更新本地状态，避免不必要的重新加载
                    services[serviceName].config = configName;
                    updateLastUpdateTime();
                } else {
                    ElMessage.error(result.message || '配置切换失败');
                    // 失败时恢复原始配置选择
                    await loadStatus();
                }
            } catch (error) {
                ElMessage.error('配置切换失败: ' + error.message);
                // 错误时恢复原始配置选择
                await loadStatus();
            }
        };
        
        // 配置抽屉相关
        const openConfigDrawer = async () => {
            configDrawerVisible.value = true;
            await loadConfigs();
        };
        
        const closeConfigDrawer = () => {
            configDrawerVisible.value = false;
        };
        
        const loadConfigs = async () => {
            try {
                // 加载Claude配置
                const claudeData = await fetchWithErrorHandling('/api/config/claude');
                const claudeContent = claudeData?.content ?? '{}';
                configContents.claude = claudeContent.trim() ? claudeContent : '{}';
                syncJsonToForm('claude');

                // 加载Codex配置
                const codexData = await fetchWithErrorHandling('/api/config/codex');
                const codexContent = codexData?.content ?? '{}';
                configContents.codex = codexContent.trim() ? codexContent : '{}';
                syncJsonToForm('codex');
            } catch (error) {
                const errorMsg = '// 加载失败: ' + error.message;
                configContents.claude = errorMsg;
                configContents.codex = errorMsg;
                // 错误情况下清空友好表单
                friendlyConfigs.claude = [];
                friendlyConfigs.codex = [];
            }
        };
        
        // 友好表单配置管理方法
        const startAddingSite = (service) => {
            editingNewSite[service] = true;
            newSiteData[service] = {
                name: '',
                baseUrl: 'https://',
                authType: 'auth_token',
                authValue: '',
                active: false
            };
            // 自动聚焦到站点名称输入框
            nextTick(() => {
                const input = document.querySelector('.new-site-name-input input');
                if (input) {
                    input.focus();
                }
            });
        };

        const confirmAddSite = (service) => {
            if (newSiteData[service].name.trim()) {
                // 如果新站点设置为激活，先关闭其他站点
                if (newSiteData[service].active) {
                    friendlyConfigs[service].forEach(site => {
                        site.active = false;
                    });
                }
                // 插入到第一个位置
                friendlyConfigs[service].unshift({...newSiteData[service]});
                editingNewSite[service] = false;
                syncFormToJson(service);
            }
        };

        const cancelAddSite = (service) => {
            editingNewSite[service] = false;
            newSiteData[service] = {
                name: '',
                baseUrl: 'https://',
                authType: 'auth_token',
                authValue: '',
                active: false
            };
        };

        const removeConfigSite = (service, index) => {
            friendlyConfigs[service].splice(index, 1);
            syncFormToJson(service);
        };

        // 处理激活状态变化（单选逻辑）
        const handleActiveChange = (service, activeIndex, newValue) => {
            if (newValue) {
                // 如果激活当前站点，关闭其他站点
                friendlyConfigs[service].forEach((site, index) => {
                    if (index !== activeIndex) {
                        site.active = false;
                    }
                });
            }
            syncFormToJson(service);
        };

        // 从表单同步到JSON
        const syncFormToJson = (service) => {
            if (syncInProgress.value) return;

            try {
                syncInProgress.value = true;
                const jsonObj = {};
                friendlyConfigs[service].forEach(site => {
                    if (site.name && site.name.trim()) {
                        const config = {
                            base_url: site.baseUrl || '',
                            active: site.active || false
                        };

                        // 根据认证类型设置相应字段
                        if (site.authType === 'auth_token') {
                            config.auth_token = site.authValue || '';
                            config.api_key = '';
                        } else {
                            config.api_key = site.authValue || '';
                            config.auth_token = '';
                        }

                        jsonObj[site.name.trim()] = config;
                    }
                });

                configContents[service] = JSON.stringify(jsonObj, null, 2);
            } catch (error) {
                console.error('同步表单到JSON失败:', error);
            } finally {
                // 延迟重置状态，确保watch不会立即触发
                nextTick(() => {
                    syncInProgress.value = false;
                });
            }
        };

        // 从JSON同步到表单
        const syncJsonToForm = (service) => {
            if (syncInProgress.value) return;

            try {
                syncInProgress.value = true;
                const content = configContents[service];
                if (!content || content.trim() === '' || content.trim() === '{}') {
                    friendlyConfigs[service] = [];
                    return;
                }

                const jsonObj = JSON.parse(content);
                const sites = [];

                Object.entries(jsonObj).forEach(([siteName, config]) => {
                    if (config && typeof config === 'object') {
                        // 判断使用哪种认证方式
                        let authType = 'auth_token';
                        let authValue = '';

                        if (config.api_key && config.api_key.trim()) {
                            authType = 'api_key';
                            authValue = config.api_key;
                        } else if (config.auth_token) {
                            authType = 'auth_token';
                            authValue = config.auth_token;
                        }

                        sites.push({
                            name: siteName,
                            baseUrl: config.base_url || '',
                            authType: authType,
                            authValue: authValue,
                            active: config.active || false
                        });
                    }
                });

                friendlyConfigs[service] = sites;
            } catch (error) {
                console.error('同步JSON到表单失败:', error);
                // JSON解析失败时保持现有表单数据不变
            } finally {
                // 延迟重置状态
                nextTick(() => {
                    syncInProgress.value = false;
                });
            }
        };

        const saveConfig = async () => {
            const service = activeConfigTab.value;
            const content = configContents[service];

            if (!content.trim()) {
                ElMessage.warning('配置内容不能为空');
                return;
            }
            
            // 验证JSON格式
            try {
                JSON.parse(content);
            } catch (e) {
                ElMessage.error('JSON格式错误: ' + e.message);
                return;
            }
            
            configSaving.value = true;
            try {
                const result = await fetchWithErrorHandling(`/api/config/${service}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ content })
                });
                
                if (result.success) {
                    ElMessage.success(result.message || '配置保存成功');
                    await loadData();
                } else {
                    ElMessage.error('保存失败: ' + (result.error || '未知错误'));
                }
            } catch (error) {
                ElMessage.error('保存失败: ' + error.message);
            } finally {
                configSaving.value = false;
            }
        };
        
        // 过滤器抽屉相关
        const openFilterDrawer = async () => {
            filterDrawerVisible.value = true;
            await loadFilter();
        };
        
        // 添加过滤规则
        const addFilterRule = () => {
            filterRules.value.push({
                source: '',
                target: '',
                op: 'replace'
            });
        };
        
        // 删除过滤规则
        const removeFilterRule = (index) => {
            filterRules.value.splice(index, 1);
        };
        
        const closeFilterDrawer = () => {
            filterDrawerVisible.value = false;
        };
        
        const loadFilter = async () => {
            try {
                const data = await fetchWithErrorHandling('/api/filter');
                filterContent.value = data.content || '[]';
                
                // 解析JSON并转换为规则数组
                try {
                    let parsedRules = JSON.parse(filterContent.value);
                    if (!Array.isArray(parsedRules)) {
                        parsedRules = [parsedRules];
                    }
                    filterRules.value = parsedRules.map(rule => ({
                        source: rule.source || '',
                        target: rule.target || '',
                        op: rule.op || 'replace'
                    }));
                } catch (e) {
                    // 如果JSON解析失败，初始化为空数组
                    filterRules.value = [];
                }
            } catch (error) {
                filterRules.value = [];
                ElMessage.error('加载过滤规则失败: ' + error.message);
            }
        };
        
        const saveFilter = async () => {
            // 过滤掉空规则
            const validRules = filterRules.value.filter(rule => rule.source && rule.source.trim());
            
            if (validRules.length === 0) {
                const emptyRules = '[]';
                filterContent.value = emptyRules;
            } else {
                // 验证规则
                for (const rule of validRules) {
                    if (!['replace', 'remove'].includes(rule.op)) {
                        ElMessage.error('op 字段必须是 replace 或 remove');
                        return;
                    }
                    if (rule.op === 'replace' && !rule.target) {
                        ElMessage.error('replace 操作必须填写替换后的文本');
                        return;
                    }
                }
                
                // 转换为JSON格式
                const jsonRules = validRules.map(rule => {
                    const obj = {
                        source: rule.source,
                        op: rule.op
                    };
                    if (rule.op === 'replace') {
                        obj.target = rule.target || '';
                    }
                    return obj;
                });
                
                filterContent.value = JSON.stringify(jsonRules, null, 2);
            }
            
            filterSaving.value = true;
            try {
                const result = await fetchWithErrorHandling('/api/filter', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ content: filterContent.value })
                });
                
                if (result.success) {
                    ElMessage.success(result.message || '过滤规则保存成功');
                    await loadData();
                } else {
                    ElMessage.error('保存失败: ' + (result.error || '未知错误'));
                }
            } catch (error) {
                ElMessage.error('保存失败: ' + error.message);
            } finally {
                filterSaving.value = false;
            }
        };
        
        // 工具方法
        const formatTimestamp = (timestamp) => {
            if (!timestamp) return '-';

            try {
                const date = new Date(timestamp);
                const year = date.getFullYear();
                const month = String(date.getMonth() + 1).padStart(2, '0');
                const day = String(date.getDate()).padStart(2, '0');
                const hours = String(date.getHours()).padStart(2, '0');
                const minutes = String(date.getMinutes()).padStart(2, '0');
                const seconds = String(date.getSeconds()).padStart(2, '0');

                return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
            } catch (e) {
                return timestamp;
            }
        };
        
        const truncatePath = (path) => {
            // 不截断URL，显示完整内容
            return path || '-';
        };
        
        const getStatusTagType = (statusCode) => {
            if (!statusCode) return '';
            
            const status = parseInt(statusCode);
            if (status >= 200 && status < 300) return 'success';
            if (status >= 400 && status < 500) return 'warning';
            if (status >= 500) return 'danger';
            return '';
        };
        
        // 日志详情相关方法
        const decodeBodyContent = (encodedContent) => {
            if (!encodedContent) {
                return '';
            }

            try {
                const decodedBytes = atob(encodedContent);
                const decodedText = decodeURIComponent(decodedBytes.split('').map(c =>
                    '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
                ).join(''));

                try {
                    const jsonObj = JSON.parse(decodedText);
                    return JSON.stringify(jsonObj, null, 2);
                } catch {
                    return decodedText;
                }
            } catch (error) {
                console.error('解码请求体失败:', error);
                return '解码失败: ' + error.message;
            }
        };

        const showLogDetail = (log) => {
            selectedLog.value = log;
            activeLogTab.value = 'basic'; // 重置到基本信息tab
            logDetailVisible.value = true;

            decodedRequestBody.value = decodeBodyContent(log.filtered_body);
            decodedOriginalRequestBody.value = decodeBodyContent(log.original_body);
            decodedResponseContent.value = decodeBodyContent(log.response_content);
        };
        
        // 加载所有日志
        const loadAllLogs = async () => {
            allLogsLoading.value = true;
            try {
                const data = await fetchWithErrorHandling('/api/logs/all');
                allLogs.value = Array.isArray(data) ? data : [];
            } catch (error) {
                ElMessage.error('获取所有日志失败: ' + error.message);
                allLogs.value = [];
            } finally {
                allLogsLoading.value = false;
            }
        };
        
        // 查看所有日志
        const viewAllLogs = async () => {
            allLogsVisible.value = true;
            await loadAllLogs();
        };
        
        // 刷新所有日志
        const refreshAllLogs = () => {
            loadAllLogs();
        };
        
        // 格式化请求体JSON
        const formatJsonContent = (bodyRef) => {
            if (!bodyRef.value) {
                ElMessage.warning('没有请求体内容');
                return;
            }

            try {
                const jsonObj = JSON.parse(bodyRef.value);
                bodyRef.value = JSON.stringify(jsonObj, null, 2);
                ElMessage.success('JSON格式化成功');
            } catch (error) {
                ElMessage.error('不是有效的JSON格式');
            }
        };

        const formatFilteredRequestBody = () => formatJsonContent(decodedRequestBody);
        const formatOriginalRequestBody = () => formatJsonContent(decodedOriginalRequestBody);
        const formatResponseContent = () => formatJsonContent(decodedResponseContent);
        
        
        // 对Headers按字母排序
        const getSortedHeaderKeys = (headers) => {
            if (!headers || typeof headers !== 'object') {
                return [];
            }
            return Object.keys(headers).sort((a, b) => {
                // 不区分大小写的字母排序
                return a.toLowerCase().localeCompare(b.toLowerCase());
            });
        };

        // 复制到剪贴板
        const copyToClipboard = async (text) => {
            try {
                await navigator.clipboard.writeText(text);
                ElMessage.success('已复制到剪贴板');
            } catch (error) {
                // 降级方案
                const textArea = document.createElement('textarea');
                textArea.value = text;
                textArea.style.position = 'fixed';
                textArea.style.opacity = '0';
                document.body.appendChild(textArea);
                textArea.select();
                try {
                    document.execCommand('copy');
                    ElMessage.success('已复制到剪贴板');
                } catch (err) {
                    ElMessage.error('复制失败');
                }
                document.body.removeChild(textArea);
            }
        };
        
        // 清空所有日志
        const clearAllLogs = async () => {
            try {
                await ElMessageBox.confirm(
                    '确定要清空所有日志吗？此操作不可撤销。',
                    '确认清空',
                    {
                        confirmButtonText: '确定',
                        cancelButtonText: '取消',
                        type: 'warning',
                    }
                );
                
                const result = await fetchWithErrorHandling('/api/logs', {
                    method: 'DELETE'
                });
                
                if (result.success) {
                    ElMessage.success('日志已清空');
                    // 刷新页面数据
                    window.location.reload();
                } else {
                    ElMessage.error('清空日志失败: ' + (result.error || '未知错误'));
                }
            } catch (error) {
                if (error !== 'cancel') {
                    ElMessage.error('清空日志失败: ' + error.message);
                }
            }
        };
        
        // 添加对JSON内容变化的监听，实现JSON到表单的同步
        // 监听Claude配置JSON变化
        watch(() => configContents.claude, (newValue) => {
            // 延迟执行，避免在同步过程中产生循环调用
            nextTick(() => {
                syncJsonToForm('claude');
            });
        });

        // 监听Codex配置JSON变化
        watch(() => configContents.codex, (newValue) => {
            // 延迟执行，避免在同步过程中产生循环调用
            nextTick(() => {
                syncJsonToForm('codex');
            });
        });

        // 实时请求相关方法
        const initRealTimeConnections = () => {
            try {
                realtimeManager.value = new RealTimeManager();
                const removeListener = realtimeManager.value.addListener(handleRealTimeEvent);

                // 页面卸载时清理
                window.addEventListener('beforeunload', () => {
                    removeListener();
                    if (realtimeManager.value) {
                        realtimeManager.value.destroy();
                    }
                });

                // 延迟连接，等待代理服务启动
                setTimeout(() => {
                    realtimeManager.value.connectAll();
                    console.log('实时连接管理器初始化成功');
                }, 1000); // 延迟1秒再连接
            } catch (error) {
                console.error('初始化实时连接失败:', error);
                ElMessage.error('实时连接初始化失败: ' + error.message);
            }
        };

        const handleRealTimeEvent = (event) => {
            try {
                switch (event.type) {
                    case 'connection':
                        connectionStatus[event.service] = event.status === 'connected';
                        if (event.status === 'connected') {
                            console.log(`${event.service} 实时连接已建立`);
                        } else if (event.status === 'disconnected') {
                            console.log(`${event.service} 实时连接已断开`);
                        } else if (event.status === 'error') {
                            console.log(`${event.service} 实时连接错误:`, event.error);
                        }
                        break;

                    case 'snapshot':
                    case 'started':
                        addRealtimeRequest(event);
                        break;

                    case 'progress':
                        updateRequestProgress(event);
                        break;

                    case 'completed':
                    case 'failed':
                        completeRequest(event);
                        break;

                    default:
                }
            } catch (error) {
                console.error('处理实时事件失败:', error);
            }
        };

        const addRealtimeRequest = (event) => {
            try {
                const existingIndex = realtimeRequests.value.findIndex(r => r.request_id === event.request_id);

                if (existingIndex >= 0) {
                    // 更新现有请求
                    Object.assign(realtimeRequests.value[existingIndex], event);
                } else {
                    // 添加新请求
                    const request = {
                        ...event,
                        responseText: '',
                        displayDuration: event.duration_ms || 0
                    };

                    realtimeRequests.value.unshift(request);

                    // 保持最多显示指定数量的请求
                    if (realtimeRequests.value.length > maxRealtimeRequests) {
                        realtimeRequests.value = realtimeRequests.value.slice(0, maxRealtimeRequests);
                    }
                }
            } catch (error) {
                console.error('添加实时请求失败:', error);
            }
        };

        const updateRequestProgress = (event) => {
            try {
                const request = realtimeRequests.value.find(r => r.request_id === event.request_id);
                if (!request) return;

                // 更新状态和耗时
                if (event.status) {
                    request.status = event.status;
                }
                if (event.duration_ms !== undefined) {
                    request.displayDuration = event.duration_ms;
                }

                // 累积响应文本
                if (event.response_delta) {
                    request.responseText += event.response_delta;

                    // 如果详情抽屉开着且显示当前请求，自动滚动
                    if (realtimeDetailVisible.value &&
                        selectedRealtimeRequest.value?.request_id === event.request_id) {
                        nextTick(() => {
                            scrollResponseToBottom();
                        });
                    }
                }
            } catch (error) {
                console.error('更新请求进度失败:', error);
            }
        };

        const completeRequest = (event) => {
            try {
                const request = realtimeRequests.value.find(r => r.request_id === event.request_id);
                if (!request) return;

                request.status = event.status || (event.type === 'completed' ? 'COMPLETED' : 'FAILED');
                request.displayDuration = event.duration_ms || request.displayDuration;
                request.status_code = event.status_code;
            } catch (error) {
                console.error('完成请求失败:', error);
            }
        };

        // UI辅助方法
        const formatRealtimeTime = (isoString) => {
            try {
                return new Date(isoString).toLocaleTimeString('zh-CN');
            } catch (error) {
                return isoString;
            }
        };

        const getStatusDisplay = (status) => {
            return REQUEST_STATUS[status] || { text: status, type: '' };
        };

        const showRealtimeDetail = (request) => {
            selectedRealtimeRequest.value = request;
            realtimeDetailVisible.value = true;
        };

        const scrollResponseToBottom = () => {
            try {
                const container = document.querySelector('.response-stream-content');
                if (container) {
                    container.scrollTop = container.scrollHeight;
                }
            } catch (error) {
                console.error('滚动响应内容失败:', error);
            }
        };

        const reconnectRealtime = () => {
            if (realtimeManager.value) {
                console.log('手动重连实时服务...');
                console.log('当前连接状态:', realtimeManager.value.getConnectionStatus());
                console.log('管理器状态:', realtimeManager.value.getStatus());

                realtimeManager.value.reconnectAll();
                ElMessage.info('正在重新连接实时服务...');
            }
        };

        // 添加调试功能
        const checkConnectionStatus = () => {
            if (realtimeManager.value) {
                console.log('=== 连接状态调试信息 ===');
                console.log('连接状态:', realtimeManager.value.getConnectionStatus());
                console.log('管理器状态:', realtimeManager.value.getStatus());
                console.log('当前实时请求数量:', realtimeRequests.value.length);
                console.log('实时请求列表:', realtimeRequests.value);
                console.log('========================');
            }
        };

        // 暴露调试功能到全局
        window.debugRealtime = checkConnectionStatus;

        // 组件挂载
        onMounted(() => {
            loadData();
            // 初始化实时连接
            initRealTimeConnections();
        });
        
        return {
            // 响应式数据
            loading,
            logsLoading,
            allLogsLoading,
            configSaving,
            filterSaving,
            lastUpdate,
            services,
            stats,
            logs,
            allLogs,
            claudeConfigs,
            codexConfigs,
            configDrawerVisible,
            filterDrawerVisible,
            logDetailVisible,
            allLogsVisible,
            activeConfigTab,
            activeLogTab,
            configContents,
            filterContent,
            filterRules,
            selectedLog,
            decodedRequestBody,
            decodedOriginalRequestBody,
            usageSummary,
            usageDrawerVisible,
            usageDetails,
            usageDetailsLoading,
            usageMetricLabels,
            metricKeys,
            friendlyConfigs,
            configEditMode,
            editingNewSite,
            newSiteData,
            modelSelectorVisible,
            testResultVisible,
            testingConnection,
            testConfig,
            lastTestResult,
            newSiteTestResult,
            testResponseDialogVisible,
            testResponseData,

            // 方法
            refreshData,
            switchConfig,
            openConfigDrawer,
            closeConfigDrawer,
            saveConfig,
            openFilterDrawer,
            closeFilterDrawer,
            loadFilter,
            saveFilter,
            addFilterRule,
            removeFilterRule,
            formatTimestamp,
            truncatePath,
            getStatusTagType,
            showLogDetail,
            viewAllLogs,
            refreshAllLogs,
            clearAllLogs,
            copyToClipboard,
            formatFilteredRequestBody,
            formatOriginalRequestBody,
            formatResponseContent,
            decodedResponseContent,
            formatUsageValue,
            formatUsageSummary,
            getUsageFormattedValue,
            formatChannelName,
            formatServiceWithChannel,
            formatMethodWithURL,
            openUsageDrawer,
            closeUsageDrawer,
            clearUsageData,
            loadUsageDetails,
            getSortedHeaderKeys,
            startAddingSite,
            confirmAddSite,
            cancelAddSite,
            removeConfigSite,
            handleActiveChange,
            syncFormToJson,
            syncJsonToForm,
            getModelOptions,
            testNewSiteConnection,
            testSiteConnection,
            showModelSelector,
            cancelModelSelection,
            confirmModelSelection,
            copyTestResult,
            showTestResponse,
            testResponseDialogVisible,
            testResponseData,
            copyTestResponseData,

            // 实时请求相关
            realtimeRequests,
            realtimeDetailVisible,
            selectedRealtimeRequest,
            connectionStatus,
            formatRealtimeTime,
            getStatusDisplay,
            showRealtimeDetail,
            reconnectRealtime
        };
    }
});

// 检查Element Plus是否正确加载
console.log('ElementPlus对象:', ElementPlus);
console.log('ElementPlus.version:', ElementPlus.version);

// 使用Element Plus - 包括所有组件和指令
try {
    app.use(ElementPlus);
    console.log('Element Plus 配置成功');
} catch (error) {
    console.error('Element Plus 配置失败:', error);
}

// 挂载应用
app.mount('#app');
