// Vue 3 + Element Plus CLI Proxy Monitor Application
const { createApp, ref, reactive, computed, onMounted, onBeforeUnmount, nextTick, watch } = Vue;
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
        const configMetadata = reactive({
            claude: {},
            codex: {}
        });
        
        // 抽屉状态
        const configDrawerVisible = ref(false);
        const filterDrawerVisible = ref(false);
        const logDetailVisible = ref(false);
        const allLogsVisible = ref(false);
        const activeConfigTab = ref('claude');
        const activeLogTab = ref('basic'); // 日志详情Tab状态
        const showTransformedData = ref(true); // 控制是否显示替换后的数据（默认显示替换后）
        const activeRequestSubTab = ref('headers'); // 请求tab的子tab：'headers' | 'body'
        const activeResponseSubTab = ref('headers'); // 响应tab的子tab：'headers' | 'body'

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

        // 配置编辑模式 'interactive' | 'json' | 'merged'
        const configEditMode = ref('merged');

        // 合并模式的配置数据
        const mergedConfigs = reactive({
            claude: [],  // 每个元素是一个分组
            codex: []
        });

        // 添加站点弹窗相关
        const mergedDialogVisible = ref(false);
        const mergedDialogService = ref('');
        const mergedDialogDraft = reactive({
            baseUrl: 'https://',
            weight: 0,
            authType: 'auth_token',
            entries: []  // [{ name, authValue, active }]
        });
        const mergedDialogMode = ref('add');
        const mergedDialogEditIndex = ref(-1);

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
                active: false,
                weight: 0
            },
            codex: {
                name: '',
                baseUrl: 'https://',
                authType: 'auth_token',
                authValue: '',
                active: false,
                weight: 0
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
        const responseOriginalContent = ref(''); // 原始响应内容
        const parsedResponseContent = ref(''); // 解析后的简要响应内容
        const isResponseContentParsed = ref(true); // 是否显示解析视图
        const isCodexLog = ref(false); // 当前日志是否来自codex
        const isClaudeLog = ref(false); // 当前日志是否来自claude
        const canParseSelectedLog = computed(() => {
            return (isCodexLog.value || isClaudeLog.value) && !!responseOriginalContent.value;
        });

        // 实时请求相关数据
        const realtimeRequests = ref([]);
        const realtimeDetailVisible = ref(false);
        const selectedRealtimeRequest = ref(null);
        const connectionStatus = reactive({ claude: false, codex: false });
        const realtimeManager = ref(null);
        const maxRealtimeRequests = 20;

        // 模型路由管理相关数据
        const routingMode = ref('default'); // 'default' | 'model-mapping' | 'config-mapping'
        const modelMappingDrawerVisible = ref(false);
        const configMappingDrawerVisible = ref(false);
        const activeModelMappingTab = ref('claude'); // 默认选中claude
        const activeConfigMappingTab = ref('claude'); // 默认选中claude
        const routingConfig = reactive({
            mode: 'default',
            modelMappings: {
                claude: [],  // [{ source: 'sonnet4', target: 'opus4' }]
                codex: []
            },
            configMappings: {
                claude: [],  // [{ model: 'sonnet4', config: 'config_a' }]
                codex: []
            }
        });
        const routingConfigSaving = ref(false);

        // 负载均衡相关数据
        const loadbalanceConfig = reactive({
            mode: 'active-first',
            services: {
                claude: {
                    failureThreshold: 3,
                    autoResetMinutes: 10,
                    currentFailures: {},
                    excludedConfigs: [],
                    excludedTimestamps: {},
                    manualDisabledUntil: {}
                },
                codex: {
                    failureThreshold: 3,
                    autoResetMinutes: 10,
                    currentFailures: {},
                    excludedConfigs: [],
                    excludedTimestamps: {},
                    manualDisabledUntil: {}
                }
            }
        });
        const loadbalanceSaving = ref(false);
        const loadbalanceLoading = ref(false);
        const resettingFailures = reactive({ claude: false, codex: false });
        const isLoadbalanceWeightMode = computed(() => loadbalanceConfig.mode === 'weight-based');
        const loadbalanceDisabledNotice = computed(() => isLoadbalanceWeightMode.value ? '负载均衡生效中' : '');
        const PINNED_WEIGHT_START = 1000;
        const pinningState = reactive({
            claude: { loading: false, target: '' },
            codex: { loading: false, target: '' }
        });

        // 响应式布局控制
        const defaultViewport = {
            width: typeof window !== 'undefined' ? window.innerWidth : 1440,
            height: typeof window !== 'undefined' ? window.innerHeight : 900
        };
        const viewport = reactive({ ...defaultViewport });

        const updateViewport = () => {
            if (typeof window === 'undefined') {
                return;
            }
            viewport.width = window.innerWidth;
            viewport.height = window.innerHeight;
        };

        const getDrawerSize = (desktop, tablet = '82%', mobile = '100%') => {
            const width = viewport.width;
            if (width <= 640) {
                return mobile;
            }
            if (width <= 1280) {
                return tablet;
            }
            return desktop;
        };

        const drawerSizes = computed(() => ({
            config: getDrawerSize('600px', '82%', '100%'),
            filter: getDrawerSize('700px', '85%', '100%'),
            logDetail: getDrawerSize('900px', '88%', '100%'),
            allLogs: getDrawerSize('50%', '82%', '100%'),
            usage: getDrawerSize('1000px', '88%', '100%'),
            realtime: getDrawerSize('800px', '85%', '100%'),
            modelMapping: getDrawerSize('60%', '82%', '100%'),
            configMapping: getDrawerSize('60%', '82%', '100%')
        }));

        const dialogSizes = computed(() => ({
            modelSelector: getDrawerSize('400px', '70%', '96%'),
            mergedGroup: getDrawerSize('700px', '90%', '96%')
        }));

        const isMobileViewport = computed(() => viewport.width <= 640);

        // 系统配置
        const systemConfig = reactive({
            logLimit: 50
        });

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
                    { label: 'claude-sonnet-4-5-20250929', value: 'claude-sonnet-4-5-20250929' },
                    { label: 'claude-sonnet-4-20250514', value: 'claude-sonnet-4-20250514' },
                    { label: 'claude-opus-4-20250514', value: 'claude-opus-4-20250514' },
                    { label: 'claude-opus-4-1-20250805', value: 'claude-opus-4-1-20250805' }
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

        // 模型路由管理方法
        const selectRoutingMode = async (mode) => {
            routingMode.value = mode;
            routingConfig.mode = mode;
            await saveRoutingConfig();
            ElMessage.success(`已切换到${getRoutingModeText(mode)}模式`);
        };

        const getRoutingModeText = (mode) => {
            const modeTexts = {
                'default': '默认路由',
                'model-mapping': '模型→模型映射',
                'config-mapping': '模型→配置映射'
            };
            return modeTexts[mode] || mode;
        };

        const openModelMappingDrawer = () => {
            modelMappingDrawerVisible.value = true;
        };

        const openConfigMappingDrawer = () => {
            configMappingDrawerVisible.value = true;
        };

        const closeModelMappingDrawer = () => {
            modelMappingDrawerVisible.value = false;
        };

        const closeConfigMappingDrawer = () => {
            configMappingDrawerVisible.value = false;
        };

        const addModelMapping = (service) => {
            routingConfig.modelMappings[service].push({
                source: '',
                target: '',
                source_type: 'model'
            });
        };

        const removeModelMapping = (service, index) => {
            routingConfig.modelMappings[service].splice(index, 1);
        };

        const addConfigMapping = (service) => {
            routingConfig.configMappings[service].push({
                model: '',
                config: ''
            });
        };

        const removeConfigMapping = (service, index) => {
            routingConfig.configMappings[service].splice(index, 1);
        };

        const saveRoutingConfig = async () => {
            routingConfigSaving.value = true;
            try {
                const result = await fetchWithErrorHandling('/api/routing/config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(routingConfig)
                });

                if (result.success) {
                    ElMessage.success('路由配置保存成功');
                } else {
                    ElMessage.error('路由配置保存失败: ' + (result.error || '未知错误'));
                }
            } catch (error) {
                ElMessage.error('路由配置保存失败: ' + error.message);
            } finally {
                routingConfigSaving.value = false;
            }
        };

        const loadRoutingConfig = async () => {
            try {
                const data = await fetchWithErrorHandling('/api/routing/config');
                if (data.config) {
                    Object.assign(routingConfig, data.config);
                    routingMode.value = data.config.mode || 'default';

                    // 向后兼容性处理：为没有source_type字段的映射添加默认值
                    ['claude', 'codex'].forEach(service => {
                        if (routingConfig.modelMappings[service]) {
                            routingConfig.modelMappings[service].forEach(mapping => {
                                if (!mapping.source_type) {
                                    mapping.source_type = 'model';
                                }
                            });
                        }
                    });
                }
            } catch (error) {
                console.error('加载路由配置失败:', error);
                // 使用默认配置
                routingMode.value = 'default';
                routingConfig.mode = 'default';
            }
        };

        const getLoadbalanceModeText = (mode) => {
            const mapping = {
                'active-first': '按激活状态',
                'weight-based': '按权重'
            };
            return mapping[mode] || mode;
        };

        const normalizeLoadbalanceConfig = (payload = {}) => {
            const normalized = {
                mode: payload.mode === 'weight-based' ? 'weight-based' : 'active-first',
                services: {
                    claude: {
                        failureThreshold: 3,
                        autoResetMinutes: 10,
                        currentFailures: {},
                        excludedConfigs: [],
                        excludedTimestamps: {},
                        manualDisabledUntil: {}
                    },
                    codex: {
                        failureThreshold: 3,
                        autoResetMinutes: 10,
                        currentFailures: {},
                        excludedConfigs: [],
                        excludedTimestamps: {},
                        manualDisabledUntil: {}
                    }
                }
            };

            ['claude', 'codex'].forEach(service => {
                const section = payload.services?.[service] || {};
                const threshold = Number(section.failureThreshold ?? section.failover_count ?? 3);
                normalized.services[service].failureThreshold = Number.isFinite(threshold) && threshold > 0 ? threshold : 3;

                const rawFailures = section.currentFailures || section.current_failures || {};
                const normalizedFailures = {};
                Object.entries(rawFailures || {}).forEach(([name, count]) => {
                    const numeric = Number(count);
                    normalizedFailures[name] = Number.isFinite(numeric) && numeric > 0 ? numeric : 0;
                });
                normalized.services[service].currentFailures = normalizedFailures;

                const excludedList = section.excludedConfigs || section.excluded_configs || [];
                normalized.services[service].excludedConfigs = Array.isArray(excludedList) ? [...excludedList] : [];

                const autoReset = Number(section.autoResetMinutes ?? section.auto_reset_minutes ?? 10);
                normalized.services[service].autoResetMinutes = Number.isFinite(autoReset) && autoReset >= 0
                    ? Math.round(autoReset)
                    : 0;

                const rawTimestamps = section.excludedTimestamps || section.excluded_timestamps || {};
                const normalizedTimestamps = {};
                if (rawTimestamps && typeof rawTimestamps === 'object') {
                    Object.entries(rawTimestamps).forEach(([name, ts]) => {
                        const numeric = Number(ts);
                        if (Number.isFinite(numeric) && numeric > 0 && normalized.services[service].excludedConfigs.includes(name)) {
                            normalizedTimestamps[name] = numeric;
                        }
                    });
                }
                normalized.services[service].excludedTimestamps = normalizedTimestamps;

                const manualDisabled = section.manualDisabledUntil || section.manual_disabled_until || {};
                const normalizedManual = {};
                if (manualDisabled && typeof manualDisabled === 'object') {
                    Object.entries(manualDisabled).forEach(([name, dateStr]) => {
                        if (typeof name !== 'string') {
                            return;
                        }
                        const stringified = (dateStr ?? '').toString().trim();
                        if (stringified) {
                            normalizedManual[name] = stringified;
                        }
                    });
                }
                normalized.services[service].manualDisabledUntil = normalizedManual;
            });

            return normalized;
        };

        const applyLoadbalanceConfig = (normalized) => {
            loadbalanceConfig.mode = normalized.mode;
            ['claude', 'codex'].forEach(service => {
                const svc = normalized.services[service];
                loadbalanceConfig.services[service].failureThreshold = svc.failureThreshold;
                loadbalanceConfig.services[service].currentFailures = Object.assign({}, svc.currentFailures);
                loadbalanceConfig.services[service].excludedConfigs = [...svc.excludedConfigs];
                loadbalanceConfig.services[service].autoResetMinutes = svc.autoResetMinutes;
                loadbalanceConfig.services[service].excludedTimestamps = { ...svc.excludedTimestamps };
                loadbalanceConfig.services[service].manualDisabledUntil = { ...svc.manualDisabledUntil };
            });
        };

        const buildLoadbalancePayload = () => {
            const buildServiceSection = (service) => {
                const section = loadbalanceConfig.services[service] || {};
                const threshold = Number(section.failureThreshold ?? 3);
                const normalizedThreshold = Number.isFinite(threshold) && threshold > 0 ? threshold : 3;
                const failuresPayload = {};
                Object.entries(section.currentFailures || {}).forEach(([name, count]) => {
                    const numeric = Number(count);
                    failuresPayload[name] = Number.isFinite(numeric) && numeric > 0 ? numeric : 0;
                });
                const excludedPayload = Array.isArray(section.excludedConfigs) ? [...section.excludedConfigs] : [];
                const autoReset = Number(section.autoResetMinutes ?? 10);
                const normalizedAutoReset = Number.isFinite(autoReset) && autoReset >= 0 ? Math.round(autoReset) : 0;
                const timestampsPayload = {};
                const rawTimestamps = section.excludedTimestamps || {};
                if (rawTimestamps && typeof rawTimestamps === 'object') {
                    excludedPayload.forEach(name => {
                        const numeric = Number(rawTimestamps[name]);
                        if (Number.isFinite(numeric) && numeric > 0) {
                            timestampsPayload[name] = numeric;
                        }
                    });
                }
                const manualPayload = {};
                const manualDisabled = section.manualDisabledUntil || {};
                if (manualDisabled && typeof manualDisabled === 'object') {
                    Object.entries(manualDisabled).forEach(([name, dateStr]) => {
                        if (typeof name !== 'string') {
                            return;
                        }
                        const stringified = (dateStr ?? '').toString().trim();
                        if (stringified) {
                            manualPayload[name] = stringified;
                        }
                    });
                }
                return {
                    failureThreshold: normalizedThreshold,
                    currentFailures: failuresPayload,
                    excludedConfigs: excludedPayload,
                    autoResetMinutes: normalizedAutoReset,
                    excludedTimestamps: timestampsPayload,
                    manualDisabledUntil: manualPayload
                };
            };

            return {
                mode: loadbalanceConfig.mode,
                services: {
                    claude: buildServiceSection('claude'),
                    codex: buildServiceSection('codex')
                }
            };
        };

        const loadLoadbalanceConfig = async () => {
            loadbalanceLoading.value = true;
            try {
                const data = await fetchWithErrorHandling('/api/loadbalance/config');
                if (data.config) {
                    const normalized = normalizeLoadbalanceConfig(data.config);
                    applyLoadbalanceConfig(normalized);
                }
            } catch (error) {
                console.error('加载负载均衡配置失败:', error);
                ElMessage.error('加载负载均衡配置失败: ' + error.message);
                applyLoadbalanceConfig(normalizeLoadbalanceConfig({}));
            } finally {
                loadbalanceLoading.value = false;
            }
        };

        const saveLoadbalanceConfig = async (showSuccess = true) => {
            loadbalanceSaving.value = true;
            let success = false;
            try {
                const payload = buildLoadbalancePayload();
                const result = await fetchWithErrorHandling('/api/loadbalance/config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(payload)
                });

                if (result.success) {
                    if (showSuccess) {
                        ElMessage.success('负载均衡配置保存成功');
                    }
                    await loadLoadbalanceConfig();
                    success = true;
                } else {
                    ElMessage.error('负载均衡配置保存失败: ' + (result.error || '未知错误'));
                }
            } catch (error) {
                ElMessage.error('负载均衡配置保存失败: ' + error.message);
            } finally {
                loadbalanceSaving.value = false;
            }
            return success;
        };

        const selectLoadbalanceMode = async (mode) => {
            if (loadbalanceConfig.mode === mode) {
                return;
            }
            loadbalanceConfig.mode = mode;
            await saveLoadbalanceConfig(false);
            ElMessage.success(`已切换到${getLoadbalanceModeText(mode)}模式`);
        };

        const getTodayKey = () => {
            const now = new Date();
            const pad = (n) => n.toString().padStart(2, '0');
            return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
        };

        const onAutoResetMinutesChange = async (service, value) => {
            const numeric = Number(value);
            const sanitized = Number.isFinite(numeric) && numeric >= 0 ? Math.round(numeric) : 0;
            loadbalanceConfig.services[service].autoResetMinutes = sanitized;
            const ok = await saveLoadbalanceConfig(false);
            if (ok) {
                ElMessage.success('已更新自动重置间隔');
            }
        };

        const toggleManualDisableForToday = async (service, configName, enabled) => {
            const manualMap = loadbalanceConfig.services[service]?.manualDisabledUntil;
            if (!manualMap) {
                return;
            }
            const todayKey = getTodayKey();
            const previous = { ...manualMap };
            if (enabled) {
                manualMap[configName] = todayKey;
            } else {
                delete manualMap[configName];
            }
            const ok = await saveLoadbalanceConfig(false);
            if (ok) {
                ElMessage.success(enabled ? '已设置今日禁用' : '已取消今日禁用');
            } else {
                // 回滚本地修改
                Object.keys(manualMap).forEach(key => delete manualMap[key]);
                Object.entries(previous).forEach(([key, value]) => {
                    manualMap[key] = value;
                });
            }
        };

        const weightedTargets = computed(() => {
            const result = { claude: [], codex: [] };
            const todayKey = getTodayKey();
            ['claude', 'codex'].forEach(service => {
                const metadata = configMetadata[service] || {};
                const threshold = loadbalanceConfig.services[service]?.failureThreshold || 3;
                const failures = loadbalanceConfig.services[service]?.currentFailures || {};
                const excluded = loadbalanceConfig.services[service]?.excludedConfigs || [];
                const manualDisabled = loadbalanceConfig.services[service]?.manualDisabledUntil || {};
                const list = Object.entries(metadata).map(([name, meta]) => {
                    const weight = Number(meta?.weight ?? 0);
                    return {
                        name,
                        weight: Number.isFinite(weight) ? weight : 0,
                        failures: failures[name] || 0,
                        threshold,
                        excluded: excluded.includes(name),
                        disabledToday: manualDisabled[name] === todayKey,
                        manualDisabledUntil: manualDisabled[name] || '',
                        isActive: services[service].config === name
                    };
                });
                list.sort((a, b) => {
                    if (b.weight !== a.weight) {
                        return b.weight - a.weight;
                    }
                    return a.name.localeCompare(b.name);
                });
                result[service] = list;
            });
            return result;
        });

        const resetLoadbalanceFailures = async (service) => {
            if (resettingFailures[service]) {
                return;
            }
            resettingFailures[service] = true;
            try {
                const result = await fetchWithErrorHandling('/api/loadbalance/reset-failures', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ service })
                });

                if (result.success) {
                    ElMessage.success(result.message || '失败计数已重置');
                    await loadLoadbalanceConfig();
                } else {
                    ElMessage.error('重置失败计数失败: ' + (result.error || '未知错误'));
                }
            } catch (error) {
                ElMessage.error('重置失败计数失败: ' + error.message);
            } finally {
                resettingFailures[service] = false;
            }
        };

        const pinWeightedTarget = async (service, configName) => {
            if (!service || !configName || !pinningState[service]) {
                return;
            }

            if (pinningState[service].loading) {
                return;
            }

            pinningState[service].loading = true;
            pinningState[service].target = configName;

            try {
                let rawContent = configContents[service];
                if (!rawContent || !rawContent.trim()) {
                    const response = await fetchWithErrorHandling(`/api/config/${service}`);
                    rawContent = response?.content ?? '{}';
                }

                let parsedConfig = {};
                try {
                    parsedConfig = rawContent && rawContent.trim() ? JSON.parse(rawContent) : {};
                } catch (error) {
                    throw new Error('当前配置文件格式无效');
                }

                if (!parsedConfig[configName]) {
                    throw new Error('未找到指定配置项');
                }

                const currentOrder = weightedTargets.value[service]?.map(item => item.name) || [];
                const existingNames = Object.keys(parsedConfig);

                const orderedNames = [];
                const seen = new Set();

                if (!seen.has(configName)) {
                    orderedNames.push(configName);
                    seen.add(configName);
                }

                currentOrder.forEach(name => {
                    if (!seen.has(name) && parsedConfig[name]) {
                        orderedNames.push(name);
                        seen.add(name);
                    }
                });

                existingNames.forEach(name => {
                    if (!seen.has(name)) {
                        orderedNames.push(name);
                        seen.add(name);
                    }
                });

                if (orderedNames.length === 0) {
                    throw new Error('没有可更新的配置项');
                }

                const updatedConfig = {};
                orderedNames.forEach((name, index) => {
                    const entry = { ...parsedConfig[name] };
                    entry.weight = Math.max(1, PINNED_WEIGHT_START - index);
                    updatedConfig[name] = entry;
                });

                const newContent = JSON.stringify(updatedConfig, null, 2);
                const saveResult = await fetchWithErrorHandling(`/api/config/${service}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ content: newContent })
                });

                if (!saveResult?.success) {
                    throw new Error(saveResult?.error || saveResult?.message || '配置保存失败');
                }

                configContents[service] = newContent;

                await loadConfigOptions();
                ElMessage.success(`${configName} 已顶置至首位`);
            } catch (error) {
                ElMessage.error(`顶置失败: ${error.message}`);
            } finally {
                pinningState[service].loading = false;
                pinningState[service].target = '';
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
                    const entries = Object.entries(configs).filter(([key, value]) => key && key !== 'undefined' && value !== undefined);
                    claudeConfigs.value = entries.map(([key]) => key);
                    const metadata = {};
                    entries.forEach(([key, value]) => {
                        const weightValue = Number(value?.weight ?? 0);
                        metadata[key] = {
                            weight: Number.isFinite(weightValue) ? weightValue : 0,
                            active: !!value?.active
                        };
                    });
                    configMetadata.claude = metadata;
                } else {
                    claudeConfigs.value = [];
                    configMetadata.claude = {};
                }
                
                // 加载Codex配置选项
                const codexData = await fetchWithErrorHandling('/api/config/codex');
                if (codexData.content) {
                    const configs = JSON.parse(codexData.content);
                    const entries = Object.entries(configs).filter(([key, value]) => key && key !== 'undefined' && value !== undefined);
                    codexConfigs.value = entries.map(([key]) => key);
                    const metadata = {};
                    entries.forEach(([key, value]) => {
                        const weightValue = Number(value?.weight ?? 0);
                        metadata[key] = {
                            weight: Number.isFinite(weightValue) ? weightValue : 0,
                            active: !!value?.active
                        };
                    });
                    configMetadata.codex = metadata;
                } else {
                    codexConfigs.value = [];
                    configMetadata.codex = {};
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
                    loadLogs(),
                    loadRoutingConfig(),
                    loadLoadbalanceConfig()
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
            if (isLoadbalanceWeightMode.value) {
                ElMessage.info('负载均衡权重模式生效，无法手动切换转发目标');
                return;
            }
            
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
                active: false,
                weight: 0
            };
            // 自动聚焦到站点名称输入框
            nextTick(() => {
                const input = document.querySelector('.new-site-name-input input');
                if (input) {
                    input.focus();
                }
            });
        };

        const confirmAddSite = async (service) => {
            if (newSiteData[service].name.trim()) {
                // 如果新站点设置为激活，先关闭其他站点
                if (newSiteData[service].active) {
                    friendlyConfigs[service].forEach(site => {
                        site.active = false;
                    });
                }
                // 加入列表并按照规则重新排序
                const siteWithId = {
                    ...newSiteData[service],
                    __mergedId: generateEntryId()
                };
                friendlyConfigs[service].push(siteWithId);
                sortFriendlyList(service);
                editingNewSite[service] = false;
                syncFormToJson(service);

                // 自动保存配置
                await saveConfigForService(service);
            }
        };

        const cancelAddSite = (service) => {
            editingNewSite[service] = false;
            newSiteData[service] = {
                name: '',
                baseUrl: 'https://',
                authType: 'auth_token',
                authValue: '',
                active: false,
                weight: 0
            };
        };

        const saveInteractiveConfig = async (service) => {
            await saveConfigForService(service);
        };

        const removeConfigSite = async (service, index) => {
            const siteName = friendlyConfigs[service][index]?.name || '未命名站点';
            try {
                await ElMessageBox.confirm(
                    `确定要删除站点 "${siteName}" 吗？此操作不可撤销。`,
                    '确认删除站点',
                    {
                        confirmButtonText: '确定',
                        cancelButtonText: '取消',
                        type: 'warning',
                    }
                );
                
                friendlyConfigs[service].splice(index, 1);
                sortFriendlyList(service);
                syncFormToJson(service);
                
                // 自动保存配置
                await saveConfigForService(service);
                
                ElMessage.success('站点删除成功');
            } catch (error) {
                if (error !== 'cancel') {
                    ElMessage.error('删除站点失败: ' + error.message);
                }
            }
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
            } else {
                friendlyConfigs[service][activeIndex].active = false;
            }
            sortFriendlyList(service);
            syncFormToJson(service);
        };

        // 从表单同步到JSON
        const syncFormToJson = (service) => {
            if (syncInProgress.value) return;

            try {
                syncInProgress.value = true;
                sortFriendlyList(service);
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

                        const weightValue = Number(site.weight ?? 0);
                        config.weight = Number.isFinite(weightValue) ? weightValue : 0;

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

                        let weightValue = Number(config.weight ?? 0);
                        if (!Number.isFinite(weightValue)) {
                            weightValue = 0;
                        }

                        sites.push({
                            name: siteName,
                            baseUrl: config.base_url || '',
                            authType: authType,
                            authValue: authValue,
                            active: config.active || false,
                            weight: weightValue,
                            __mergedId: generateEntryId()
                        });
                    }
                });

                friendlyConfigs[service] = sites;
                sortFriendlyList(service);
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

        // ========== 合并模式相关函数 ==========

        /**
         * URL 校验辅助函数
         */
        const isValidUrl = (str) => {
            try {
                const url = new URL(str);
                return url.protocol === 'http:' || url.protocol === 'https:';
            } catch {
                return false;
            }
        };

        const generateEntryId = () => `merged-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

        const ensureEntryId = (site) => {
            if (!site.__mergedId) {
                site.__mergedId = generateEntryId();
            }
            return site.__mergedId;
        };

        const findFriendlyBySiteId = (service, siteId) => (
            friendlyConfigs[service].find(site => site.__mergedId === siteId)
        );

        const findFriendlyIndexBySiteId = (service, siteId) => (
            friendlyConfigs[service].findIndex(site => site.__mergedId === siteId)
        );

        const normalizeValue = (value) => (value ?? '').toString().trim();

        const getWeightValue = (value) => {
            const num = Number(value);
            return Number.isFinite(num) ? num : 0;
        };

        const compareByName = (left, right) => (
            normalizeValue(left).localeCompare(normalizeValue(right), 'zh-Hans-CN')
        );

        const sortEntryList = (entries = []) => {
            entries.sort((a, b) => {
                if (a.active !== b.active) {
                    return a.active ? -1 : 1;
                }
                return compareByName(a.name, b.name);
            });
        };

        const sortFriendlyList = (service) => {
            friendlyConfigs[service].sort((a, b) => {
                if (a.active !== b.active) {
                    return a.active ? -1 : 1;
                }

                const weightDiff = getWeightValue(b.weight) - getWeightValue(a.weight);
                if (weightDiff !== 0) {
                    return weightDiff;
                }

                const nameCompare = compareByName(a.name, b.name);
                if (nameCompare !== 0) {
                    return nameCompare;
                }

                return compareByName(a.baseUrl, b.baseUrl);
            });
        };

        const sortMergedGroups = (service) => {
            mergedConfigs[service].forEach(group => {
                if (Array.isArray(group.entries)) {
                    sortEntryList(group.entries);
                }
            });

            mergedConfigs[service].sort((a, b) => {
                const aActive = Array.isArray(a.entries) && a.entries.some(entry => entry.active);
                const bActive = Array.isArray(b.entries) && b.entries.some(entry => entry.active);

                if (aActive !== bActive) {
                    return aActive ? -1 : 1;
                }

                const weightDiff = getWeightValue(b.weight) - getWeightValue(a.weight);
                if (weightDiff !== 0) {
                    return weightDiff;
                }

                return compareByName(a.baseUrl, b.baseUrl);
            });
        };

        /**
         * 检测并统一组内的权重和认证方式
         * 返回不一致的字段列表
         */
        const normalizeGroupValues = (service, group) => {
            const inconsistent = [];
            const standardWeight = group.weight;
            const standardAuthType = group.authType;

            group.entries.forEach(entry => {
                // 在 friendlyConfigs 中找到对应项并修正
                const friendlyItem = findFriendlyBySiteId(service, entry.siteId);

                if (friendlyItem) {
                    if (friendlyItem.weight !== standardWeight) {
                        if (!inconsistent.includes('权重')) {
                            inconsistent.push('权重');
                        }
                        friendlyItem.weight = standardWeight;
                    }
                    if (friendlyItem.authType !== standardAuthType) {
                        if (!inconsistent.includes('认证方式')) {
                            inconsistent.push('认证方式');
                        }
                        friendlyItem.authType = standardAuthType;
                    }
                }
            });

            // 如果修正了数据，同步到 JSON
            if (inconsistent.length > 0) {
                syncFormToJson(service);
            }

            return inconsistent;
        };

        /**
         * 判断分组内是否存在激活秘钥
         */
        const isMergedGroupActive = (group) => (
            group && Array.isArray(group.entries) && group.entries.some(entry => entry.active)
        );

        /**
         * 从交互模式配置构建合并视图
         */
        const buildMergedFromFriendly = (service) => {
            const friendly = friendlyConfigs[service];
            const grouped = new Map(); // baseUrl -> group对象

            sortFriendlyList(service);

            // 第一步：按 baseUrl 分组
            friendly.forEach((site, idx) => {
                if (!site.baseUrl || !site.baseUrl.trim()) {
                    console.warn(`站点 ${site.name} 缺少 base_url`);
                    return;
                }

                const key = site.baseUrl.trim();
                if (!grouped.has(key)) {
                    grouped.set(key, {
                        baseUrl: key,
                        weight: site.weight || 0,
                        authType: site.authType || 'auth_token',
                        entries: []
                    });
                }

                const group = grouped.get(key);
                const siteId = ensureEntryId(site);

                group.entries.push({
                    name: site.name,
                    authValue: site.authValue || '',
                    active: site.active || false,
                    derivedId: site.__mergedId || `${site.name}_${idx}`,
                    siteId,
                    lastSyncedName: site.name
                });
            });

            // 第二步：检测并统一组内的 weight 和 authType
            grouped.forEach((group, baseUrl) => {
                const inconsistent = normalizeGroupValues(service, group);
                if (inconsistent.length > 0) {
                    ElMessage.warning(
                        `站点组 ${baseUrl} 内存在不一致的${inconsistent.join('、')}，已自动统一为第一条配置`
                    );
                }
            });

            // 第三步：更新 mergedConfigs
            mergedConfigs[service] = Array.from(grouped.values());
            sortMergedGroups(service);
        };

        /**
         * 从合并视图重建交互模式配置
         * 用于保存前的数据校验和重建
         */
        const rebuildFriendlyFromMerged = (service) => {
            const merged = mergedConfigs[service];
            const newFriendly = [];

            merged.forEach(group => {
                group.entries.forEach(entry => {
                    const siteId = entry.siteId || generateEntryId();
                    entry.siteId = siteId;
                    entry.lastSyncedName = entry.name;
                    newFriendly.push({
                        name: entry.name,
                        baseUrl: group.baseUrl,
                        weight: group.weight,
                        authType: group.authType,
                        authValue: entry.authValue,
                        active: entry.active,
                        __mergedId: siteId
                    });
                });
            });

            friendlyConfigs[service] = newFriendly;
            sortFriendlyList(service);
            syncFormToJson(service);
        };

        /**
         * 应用分组级修改（权重、认证方式、base_url）
         */
        const applyMergedGroupUpdate = (service, groupIndex) => {
            const group = mergedConfigs[service][groupIndex];

            // URL 校验
            if (!isValidUrl(group.baseUrl)) {
                ElMessage.warning('目标地址格式不正确，请输入有效的 HTTP/HTTPS URL');
                return;
            }

            // 更新所有该组的 friendlyConfigs 项
            group.entries.forEach(entry => {
                const friendlyItem = findFriendlyBySiteId(service, entry.siteId);

                if (friendlyItem) {
                    friendlyItem.baseUrl = group.baseUrl;
                    friendlyItem.weight = group.weight;
                    friendlyItem.authType = group.authType;
                }
            });

            sortFriendlyList(service);
            sortMergedGroups(service);
            // 同步到 JSON
            syncFormToJson(service);
        };

        /**
         * 自动生成站点名称
         * 策略：分析同 baseUrl 前缀的现有命名，提取最大递增后缀
         */
        const autoGenerateName = (service, baseUrl) => {
            try {
                const hostname = new URL(baseUrl).hostname;
                const prefix = hostname.split('.')[0]; // 例如 "api" 或 "privnode"

                // 查找所有以该前缀开头的站点名
                const existingNames = friendlyConfigs[service]
                    .filter(site => site.baseUrl === baseUrl)
                    .map(site => site.name);

                // 提取数字后缀
                const numbers = existingNames
                    .map(name => {
                        const match = name.match(/(\d+)$/);
                        return match ? parseInt(match[1]) : 0;
                    })
                    .filter(n => n > 0);

                const maxNum = numbers.length > 0 ? Math.max(...numbers) : 0;
                return `${prefix}-${maxNum + 1}`;

            } catch (e) {
                // URL 解析失败，使用随机名称
                return `site-${Date.now()}`;
            }
        };

        /**
         * 强制单一激活（全局工具方法）
         */
        const enforceSingleActive = (service, targetSiteId) => {
            friendlyConfigs[service].forEach(site => {
                site.active = (site.__mergedId === targetSiteId);
            });

            sortFriendlyList(service);
            // 更新合并视图
            buildMergedFromFriendly(service);
            sortMergedGroups(service);

            // 同步到 JSON
            syncFormToJson(service);
        };

        /**
         * 切换合并模式中的激活状态
         */
        const toggleMergedActive = (service, groupIndex, entryIndex, newValue) => {
            const entry = mergedConfigs[service][groupIndex].entries[entryIndex];

            if (newValue) {
                // 激活当前项时，关闭所有其他项
                ElMessageBox.confirm(
                    '激活此秘钥会自动关闭其他所有站点的激活状态，是否继续？',
                    '提示',
                    { type: 'warning' }
                ).then(() => {
                    enforceSingleActive(service, entry.siteId);
                }).catch(() => {
                    // 用户取消，恢复原状态
                    entry.active = false;
                });
            } else {
                // 关闭当前项
                const friendlyItem = findFriendlyBySiteId(service, entry.siteId);
                if (friendlyItem) {
                    friendlyItem.active = false;
                    sortFriendlyList(service);
                    sortMergedGroups(service);
                    syncFormToJson(service);
                }
            }
        };

        /**
         * 更新秘钥值（同步到 friendlyConfigs）
         */
        const updateMergedEntryAuth = (service, groupIndex, entryIndex) => {
            const group = mergedConfigs[service][groupIndex];
            const entry = group.entries[entryIndex];

            // 在 friendlyConfigs 中找到对应项并更新
            const friendlyItem = findFriendlyBySiteId(service, entry.siteId);

            if (friendlyItem) {
                friendlyItem.authValue = entry.authValue;
                syncFormToJson(service);
            }
        };

        /**
         * 更新站点名称（保持唯一并同步）
         */
        const applyMergedEntryNameUpdate = (service, groupIndex, entryIndex) => {
            const entry = mergedConfigs[service][groupIndex].entries[entryIndex];
            const previousName = entry.lastSyncedName || '';
            const trimmed = (entry.name || '').trim();

            if (!trimmed) {
                ElMessage.warning('站点名称不能为空');
                entry.name = previousName;
                return;
            }

            if (trimmed === previousName) {
                entry.name = trimmed;
                return;
            }

            const hasConflict = friendlyConfigs[service].some(site => (
                site.__mergedId !== entry.siteId && site.name === trimmed
            ));

            if (hasConflict) {
                ElMessage.error(`站点名称 "${trimmed}" 已存在，请使用其他名称`);
                entry.name = previousName;
                return;
            }

            entry.name = trimmed;

            const friendlyItem = findFriendlyBySiteId(service, entry.siteId);
            if (friendlyItem) {
                friendlyItem.name = trimmed;
                entry.lastSyncedName = trimmed;
                sortEntryList(mergedConfigs[service][groupIndex].entries);
                sortFriendlyList(service);
                sortMergedGroups(service);
                syncFormToJson(service);
            } else {
                entry.lastSyncedName = trimmed;
                sortEntryList(mergedConfigs[service][groupIndex].entries);
                sortMergedGroups(service);
            }
        };

        /**
         * 添加秘钥到现有分组
         */
        const addMergedEntry = (service, groupIndex) => {
            const group = mergedConfigs[service][groupIndex];

            // 自动生成站点名称
            const newName = autoGenerateName(service, group.baseUrl);

            const newSiteId = generateEntryId();
            const newEntry = {
                name: newName,
                authValue: '',
                active: false,
                derivedId: newSiteId,
                siteId: newSiteId,
                lastSyncedName: newName
            };

            group.entries.push(newEntry);
            sortEntryList(group.entries);

            // 同步到 friendlyConfigs
            friendlyConfigs[service].push({
                name: newEntry.name,
                baseUrl: group.baseUrl,
                weight: group.weight,
                authType: group.authType,
                authValue: '',
                active: false,
                __mergedId: newSiteId
            });
            sortFriendlyList(service);
            sortMergedGroups(service);
            syncFormToJson(service);
        };

        /**
         * 删除秘钥
         */
        const removeMergedEntry = (service, groupIndex, entryIndex) => {
            const group = mergedConfigs[service][groupIndex];
            const entry = group.entries[entryIndex];

            ElMessageBox.confirm(
                `确定要删除秘钥 "${entry.name}" 吗？`,
                '提示',
                { type: 'warning' }
            ).then(() => {
                // 从合并视图删除
                group.entries.splice(entryIndex, 1);

                // 从 friendlyConfigs 删除
                const friendlyIndex = findFriendlyIndexBySiteId(service, entry.siteId);
                if (friendlyIndex > -1) {
                    friendlyConfigs[service].splice(friendlyIndex, 1);
                }

                // 如果组内没有秘钥了，删除整个分组
                if (group.entries.length === 0) {
                    mergedConfigs[service].splice(groupIndex, 1);
                    ElMessage.info('该站点组已无秘钥，已自动删除');
                }

                sortFriendlyList(service);
                sortMergedGroups(service);
                syncFormToJson(service);
                ElMessage.success('删除成功');

            }).catch(() => {});
        };

        /**
         * 删除整个分组
         */
        const deleteMergedGroup = (service, groupIndex) => {
            const group = mergedConfigs[service][groupIndex];

            ElMessageBox.confirm(
                `确定要删除站点组 "${group.baseUrl}" 及其下所有 ${group.entries.length} 个秘钥吗？`,
                '提示',
                { type: 'warning' }
            ).then(async () => {
                // 删除所有关联的 friendlyConfigs 项
                group.entries.forEach(entry => {
                    const index = findFriendlyIndexBySiteId(service, entry.siteId);
                    if (index > -1) {
                        friendlyConfigs[service].splice(index, 1);
                    }
                });

                // 删除分组
                mergedConfigs[service].splice(groupIndex, 1);

                sortFriendlyList(service);
                sortMergedGroups(service);
                syncFormToJson(service);

                try {
                    await saveConfigForService(service);
                    buildMergedFromFriendly(service);
                    ElMessage.success('站点组删除成功');
                } catch (error) {
                    console.error('删除站点组后保存失败:', error);
                }

            }).catch(() => {});
        };

        /**
         * 切换到合并模式
         */
        const switchToMergedMode = () => {
            configEditMode.value = 'merged';
            buildMergedFromFriendly(activeConfigTab.value);
        };

        /**
         * 保存合并模式配置
         */
        const saveMergedConfig = async (service) => {
            // 1. 校验所有分组
            for (const group of mergedConfigs[service]) {
                // 校验 baseUrl
                if (!isValidUrl(group.baseUrl)) {
                    ElMessage.error(`站点组 ${group.baseUrl} 的地址格式不正确`);
                    return;
                }

                // 校验权重
                if (!Number.isFinite(group.weight) || group.weight < 0) {
                    ElMessage.error(`站点组 ${group.baseUrl} 的权重必须为非负整数`);
                    return;
                }

                // 校验秘钥
                const invalidEntries = group.entries.filter(
                    entry => !entry.authValue || !entry.authValue.trim()
                );
                if (invalidEntries.length > 0) {
                    ElMessage.error(
                        `站点组 ${group.baseUrl} 中有秘钥未填写：${invalidEntries.map(e => e.name).join(', ')}`
                    );
                    return;
                }
            }

            // 2. 从合并视图重建 friendlyConfigs
            rebuildFriendlyFromMerged(service);

            // 3. 调用现有保存逻辑
            await saveConfigForService(service);
        };

        /**
         * 打开添加站点弹窗
         */
        const openMergedDialog = (service) => {
            mergedDialogService.value = service;
            mergedDialogMode.value = 'add';
            mergedDialogEditIndex.value = -1;
            mergedDialogDraft.baseUrl = 'https://';
            mergedDialogDraft.weight = 0;
            mergedDialogDraft.authType = 'auth_token';
            mergedDialogDraft.entries = [
                { name: '', authValue: '', active: false, siteId: null, lastSyncedName: '' }
            ];
            mergedDialogVisible.value = true;
        };

        /**
         * 打开编辑弹窗
         */
        const editMergedGroup = (service, groupIndex) => {
            const group = mergedConfigs[service]?.[groupIndex];
            if (!group) {
                ElMessage.error('未找到对应的站点组');
                return;
            }

            mergedDialogService.value = service;
            mergedDialogMode.value = 'edit';
            mergedDialogEditIndex.value = groupIndex;

            mergedDialogDraft.baseUrl = group.baseUrl;
            mergedDialogDraft.weight = group.weight;
            mergedDialogDraft.authType = group.authType;
            mergedDialogDraft.entries = group.entries.length > 0
                ? group.entries.map(entry => ({
                    name: entry.name,
                    authValue: entry.authValue,
                    active: entry.active,
                    siteId: entry.siteId || null,
                    lastSyncedName: entry.lastSyncedName || entry.name
                }))
                : [{ name: '', authValue: '', active: false, siteId: null, lastSyncedName: '' }];

            sortEntryList(mergedDialogDraft.entries);

            mergedDialogVisible.value = true;
        };

        /**
         * 弹窗中添加秘钥行
         */
        const addDialogEntry = () => {
            mergedDialogDraft.entries.push({
                name: '',
                authValue: '',
                active: false,
                siteId: null,
                lastSyncedName: ''
            });
        };

        /**
         * 弹窗中删除秘钥行
         */
        const removeDialogEntry = (index) => {
            if (mergedDialogDraft.entries.length <= 1) {
                ElMessage.warning('至少保留一个秘钥');
                return;
            }
            mergedDialogDraft.entries.splice(index, 1);
        };

        /**
         * 取消弹窗
         */
        const cancelMergedDialog = () => {
            mergedDialogVisible.value = false;
            mergedDialogMode.value = 'add';
            mergedDialogEditIndex.value = -1;
        };

        /**
         * 提交站点分组
         */
        const submitMergedDialog = async () => {
            const service = mergedDialogService.value;
            const draft = mergedDialogDraft;
            const mode = mergedDialogMode.value;

            if (!service) {
                ElMessage.error('未选择需要保存的服务');
                return;
            }

            if (!isValidUrl(draft.baseUrl)) {
                ElMessage.error('目标地址格式不正确，请输入有效的 HTTP/HTTPS URL');
                return;
            }

            if (!Number.isFinite(draft.weight) || draft.weight < 0) {
                ElMessage.error('权重必须为非负整数');
                return;
            }

            if (!Array.isArray(draft.entries) || draft.entries.length === 0) {
                ElMessage.error('至少保留一个秘钥');
                return;
            }

            draft.entries.forEach(entry => {
                entry.name = (entry.name || '').trim();
                entry.authValue = (entry.authValue || '').trim();
                entry.lastSyncedName = entry.lastSyncedName || entry.name;
            });

            sortEntryList(draft.entries);

            const invalidEntries = draft.entries.filter(entry => !entry.name || !entry.authValue);
            if (invalidEntries.length > 0) {
                ElMessage.error('所有秘钥的站点名称和秘钥值均为必填项');
                return;
            }

            const nameCounts = new Map();
            for (const entry of draft.entries) {
                const count = (nameCounts.get(entry.name) || 0) + 1;
                nameCounts.set(entry.name, count);
                if (count > 1) {
                    ElMessage.error('同一分组内站点名称不能重复');
                    return;
                }
            }

            const entrySiteIds = new Set(
                draft.entries
                    .map(entry => entry.siteId)
                    .filter(Boolean)
            );

            const existingNames = friendlyConfigs[service]
                .filter(site => !entrySiteIds.has(site.__mergedId))
                .map(site => site.name);

            const duplicateEntries = draft.entries.filter(entry => existingNames.includes(entry.name));
            if (duplicateEntries.length > 0) {
                try {
                    await ElMessageBox.confirm(
                        `检测到重复的站点名称：${duplicateEntries.map(e => e.name).join(', ')}。是否自动追加后缀？`,
                        '提示',
                        { type: 'warning' }
                    );

                    duplicateEntries.forEach(entry => {
                        let suffix = 1;
                        let newName = `${entry.name}-${suffix}`;
                        while (
                            existingNames.includes(newName) ||
                            draft.entries.some(other => other !== entry && other.name === newName)
                        ) {
                            suffix++;
                            newName = `${entry.name}-${suffix}`;
                        }
                        existingNames.push(newName);
                        entry.name = newName;
                        entry.lastSyncedName = newName;
                    });

                } catch {
                    return;
                }
            }

            let activeEntry = null;
            draft.entries.forEach(entry => {
                if (entry.active && !activeEntry) {
                    activeEntry = entry;
                } else if (entry.active && activeEntry) {
                    entry.active = false;
                }
            });

            if (mode === 'add') {
                const newSites = draft.entries.map(entry => {
                    const siteId = generateEntryId();
                    entry.siteId = siteId;
                    entry.lastSyncedName = entry.name;
                    return {
                        name: entry.name,
                        baseUrl: draft.baseUrl,
                        weight: draft.weight,
                        authType: draft.authType,
                        authValue: entry.authValue,
                        active: entry.active,
                        __mergedId: siteId
                    };
                });

                friendlyConfigs[service].push(...newSites);
                sortFriendlyList(service);
                sortMergedGroups(service);

                if (activeEntry) {
                    enforceSingleActive(service, activeEntry.siteId);
                } else {
                    syncFormToJson(service);
                }

            } else {
                const groupIndex = mergedDialogEditIndex.value;
                if (groupIndex < 0 || !mergedConfigs[service]?.[groupIndex]) {
                    ElMessage.error('待编辑的站点组不存在');
                    return;
                }

                const originalGroup = mergedConfigs[service][groupIndex];
                const draftSiteIds = new Set(draft.entries.map(entry => entry.siteId).filter(Boolean));

                originalGroup.entries.forEach(entry => {
                    if (!draftSiteIds.has(entry.siteId)) {
                        const friendlyIndex = findFriendlyIndexBySiteId(service, entry.siteId);
                        if (friendlyIndex > -1) {
                            friendlyConfigs[service].splice(friendlyIndex, 1);
                        }
                    }
                });

                draft.entries.forEach(entry => {
                    if (entry.siteId) {
                        const friendlyItem = findFriendlyBySiteId(service, entry.siteId);
                        if (friendlyItem) {
                            friendlyItem.name = entry.name;
                            friendlyItem.baseUrl = draft.baseUrl;
                            friendlyItem.weight = draft.weight;
                            friendlyItem.authType = draft.authType;
                            friendlyItem.authValue = entry.authValue;
                            friendlyItem.active = entry.active;
                            friendlyItem.__mergedId = entry.siteId;
                        }
                    } else {
                        const newSiteId = generateEntryId();
                        entry.siteId = newSiteId;
                        entry.lastSyncedName = entry.name;
                            friendlyConfigs[service].push({
                                name: entry.name,
                                baseUrl: draft.baseUrl,
                                weight: draft.weight,
                                authType: draft.authType,
                                authValue: entry.authValue,
                                active: entry.active,
                                __mergedId: newSiteId
                            });
                        }
                });

                sortFriendlyList(service);
                sortMergedGroups(service);

                if (activeEntry) {
                    enforceSingleActive(service, activeEntry.siteId);
                } else {
                    draft.entries.forEach(entry => {
                        if (entry.siteId) {
                            const friendlyItem = findFriendlyBySiteId(service, entry.siteId);
                            if (friendlyItem) {
                                friendlyItem.active = entry.active;
                            }
                        }
                    });
                    syncFormToJson(service);
                }
            }

            configSaving.value = true;
            try {
                await saveConfigForService(service);
                buildMergedFromFriendly(service);
                ElMessage.success(mode === 'edit' ? '站点分组更新成功' : '站点分组添加成功');
                mergedDialogVisible.value = false;
                mergedDialogMode.value = 'add';
                mergedDialogEditIndex.value = -1;
            } catch (error) {
                ElMessage.error('保存失败: ' + error.message);
            } finally {
                configSaving.value = false;
            }
        };

        // ========== 合并模式相关函数结束 ==========

        const saveConfigForService = async (service) => {
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

        const saveConfig = async () => {
            const service = activeConfigTab.value;
            await saveConfigForService(service);
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

        const PARSED_EMPTY_TEXT = '思考消息：无\n响应消息：无\n工具调用：无';

        const parseResponseLogContent = (rawText, serviceName = '') => {
            const normalizeNewlines = (text) => {
                if (typeof text !== 'string') {
                    return '';
                }
                return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
            };

            const sanitize = (text) => {
                if (!text) {
                    return '';
                }
                const normalized = normalizeNewlines(String(text));
                return normalized
                    .split('\n')
                    .map(line => line.trimEnd())
                    .join('\n')
                    .trim();
            };

            const summarize = (value) => sanitize(value);

            const formatReasoningSummary = (value) => {
                if (!value || typeof value !== 'string') {
                    return '';
                }
                const cleaned = value.replace(/\*\*/g, '').trim();
                if (!cleaned) {
                    return '';
                }
                const parts = cleaned.split(/\n{2,}/);
                if (parts.length > 1) {
                    const rest = parts.slice(1).join('\n\n');
                    return `${sanitize(parts[0])}\n${sanitize(rest)}`.trim();
                }
                return sanitize(cleaned);
            };

            const buildOutput = (entries, errors) => {
                if (!entries.length) {
                    return {
                        success: true,
                        partial: errors.length > 0,
                        text: PARSED_EMPTY_TEXT,
                        errors
                    };
                }

                const labelMap = {
                    reasoning: '思考消息',
                    message: '响应消息',
                    tool: '工具调用'
                };

                const totals = entries.reduce((acc, entry) => {
                    acc[entry.kind] = (acc[entry.kind] || 0) + 1;
                    return acc;
                }, {});

                const seen = {};
                const outputLines = entries.map(entry => {
                    seen[entry.kind] = (seen[entry.kind] || 0) + 1;
                    const suffix = totals[entry.kind] > 1 ? `(${seen[entry.kind]})` : '';
                    if (entry.text && entry.text.includes('\n')) {
                        return `${labelMap[entry.kind]}${suffix}：\n${entry.text}`;
                    }
                    return `${labelMap[entry.kind]}${suffix}：${entry.text ?? ''}`;
                });

                ['reasoning', 'message', 'tool'].forEach(kind => {
                    if (!totals[kind]) {
                        outputLines.push(`${labelMap[kind]}：无`);
                    }
                });

                return {
                    success: true,
                    partial: errors.length > 0,
                    text: outputLines.join('\n'),
                    errors
                };
            };

            const parseSseEvents = (text) => {
                const rawLines = text.split(/\r?\n/);
                const events = [];
                let currentEventName = null;
                let dataLines = [];

                const pushEvent = () => {
                    if (currentEventName && dataLines.length > 0) {
                        events.push({
                            event: currentEventName,
                            data: dataLines.join('\n')
                        });
                    }
                    dataLines = [];
                };

                for (const line of rawLines) {
                    if (line.startsWith('event:')) {
                        pushEvent();
                        currentEventName = line.slice(6).trim();
                    } else if (line.startsWith('data:')) {
                        dataLines.push(line.slice(5).trimStart());
                    } else if (line.trim() === '') {
                        pushEvent();
                        currentEventName = null;
                    } else if (dataLines.length > 0) {
                        dataLines.push(line);
                    }
                }
                pushEvent();

                return events;
            };

            const parseCodexEvents = (events) => {
                const entries = [];
                const errors = [];

                for (const evt of events) {
                    if (evt.event !== 'response.output_item.done' || !evt.data) {
                        continue;
                    }

                    let payload;
                    try {
                        payload = JSON.parse(evt.data);
                    } catch (error) {
                        errors.push(`JSON解析失败: ${error.message}`);
                        continue;
                    }

                    const item = payload?.item;
                    if (!item) {
                        continue;
                    }

                    if (item.type === 'reasoning') {
                        let added = false;
                        if (Array.isArray(item.summary)) {
                            for (const summaryItem of item.summary) {
                                if (summaryItem && typeof summaryItem.text === 'string') {
                                    const formatted = formatReasoningSummary(summaryItem.text);
                                    if (formatted) {
                                        entries.push({ kind: 'reasoning', text: formatted });
                                        added = true;
                                    }
                                }
                            }
                        }
                        if (!added) {
                            if (item.encrypted_content) {
                                entries.push({ kind: 'reasoning', text: '内容已加密，无法解析' });
                            } else {
                                entries.push({ kind: 'reasoning', text: '未提供摘要内容' });
                            }
                        }
                    } else if (item.type === 'message') {
                        const parts = [];
                        if (Array.isArray(item.content)) {
                            for (const fragment of item.content) {
                                if (fragment && typeof fragment.text === 'string') {
                                    parts.push(fragment.text);
                                } else if (fragment?.delta && typeof fragment.delta.text === 'string') {
                                    parts.push(fragment.delta.text);
                                }
                            }
                        }
                        const combined = sanitize(parts.join(' '));
                        if (combined) {
                            entries.push({ kind: 'message', text: combined });
                        }
                    } else if (item.type === 'function_call') {
                        let description = item.name || 'function_call';
                        let argsObject = null;

                        if (typeof item.arguments === 'string') {
                            try {
                                argsObject = JSON.parse(item.arguments);
                            } catch (error) {
                                // 留作原始字符串展示
                            }
                        } else if (item.arguments && typeof item.arguments === 'object') {
                            argsObject = item.arguments;
                        }

                        const segments = [];
                        if (argsObject) {
                            if (Array.isArray(argsObject.command)) {
                                segments.push(`command=${summarize(argsObject.command.join(' '))}`);
                            } else if (argsObject.command) {
                                segments.push(`command=${summarize(argsObject.command)}`);
                            }
                            if (argsObject.workdir) {
                                segments.push(`workdir=${summarize(argsObject.workdir)}`);
                            }
                            if (argsObject.with_escalated_permissions !== undefined) {
                                segments.push(`escalated=${argsObject.with_escalated_permissions}`);
                            }
                            if (argsObject.timeout_ms !== undefined) {
                                segments.push(`timeout=${argsObject.timeout_ms}`);
                            }
                            if (argsObject.justification) {
                                segments.push(`justification=${summarize(argsObject.justification)}`);
                            }

                            const knownKeys = new Set(['command', 'workdir', 'with_escalated_permissions', 'timeout_ms', 'justification']);
                            for (const key of Object.keys(argsObject)) {
                                if (knownKeys.has(key)) continue;
                                const value = argsObject[key];
                                segments.push(`${key}=${typeof value === 'string' ? summarize(value) : summarize(JSON.stringify(value))}`);
                            }
                        } else if (item.arguments) {
                            segments.push(summarize(typeof item.arguments === 'string'
                                ? item.arguments
                                : JSON.stringify(item.arguments)));
                        }

                        if (segments.length > 0) {
                            description += ` | ${segments.join(' | ')}`;
                        }
                        entries.push({ kind: 'tool', text: description });
                    }
                }

                return buildOutput(entries, errors);
            };

            const parseClaudeEvents = (events) => {
                const entries = [];
                const errors = [];
                const activeBlocks = new Map();

                const finalizeBlock = (indexKey, block) => {
                    if (block.type === 'thinking') {
                        const normalized = normalizeNewlines(block.text || '');
                        if (normalized) {
                            entries.push({ kind: 'reasoning', text: normalized });
                        }
                        return;
                    }

                    if (block.type === 'text') {
                        const normalized = normalizeNewlines(block.text || '');
                        if (normalized) {
                            entries.push({ kind: 'message', text: normalized });
                        }
                        return;
                    }

                    if (block.type === 'tool_use') {
                        const toolLines = [];
                        if (block.toolName) {
                            toolLines.push(`名称：${normalizeNewlines(block.toolName)}`);
                        }

                        let toolArgs = null;
                        if (block.partialJson) {
                            try {
                                toolArgs = JSON.parse(block.partialJson);
                            } catch (error) {
                                errors.push(`工具调用JSON解析失败(index=${indexKey}): ${error.message}`);
                                if (block.partialJson.trim()) {
                                    toolLines.push(`原始输入：${normalizeNewlines(block.partialJson)}`);
                                }
                            }
                        }

                        if (!toolArgs && block.inputSnapshot && typeof block.inputSnapshot === 'object' && Object.keys(block.inputSnapshot).length > 0) {
                            toolArgs = block.inputSnapshot;
                        }

                        const formatValue = (value) => {
                            if (value === null || value === undefined) {
                                return '';
                            }
                            if (typeof value === 'string') {
                                return normalizeNewlines(value);
                            }
                            if (typeof value === 'number' || typeof value === 'boolean') {
                                return String(value);
                            }
                            if (Array.isArray(value)) {
                                return normalizeNewlines(value.map(item => (
                                    typeof item === 'string' ? item : JSON.stringify(item)
                                )).join(' '));
                            }
                            try {
                                return normalizeNewlines(JSON.stringify(value));
                            } catch (error) {
                                return normalizeNewlines(String(value));
                            }
                        };

                        if (toolArgs && typeof toolArgs === 'object') {
                            if (Object.prototype.hasOwnProperty.call(toolArgs, 'command')) {
                                const commandValue = Array.isArray(toolArgs.command)
                                    ? toolArgs.command.join(' ')
                                    : toolArgs.command;
                                const formattedCommand = formatValue(commandValue);
                                if (formattedCommand) {
                                    toolLines.push(`命令：${formattedCommand}`);
                                }
                            }

                            for (const key of Object.keys(toolArgs)) {
                                if (key === 'command') {
                                    continue;
                                }
                                const formatted = formatValue(toolArgs[key]);
                                if (formatted) {
                                    toolLines.push(`${key}：${formatted}`);
                                }
                            }
                        }

                        if (toolLines.length) {
                            entries.push({ kind: 'tool', text: toolLines.join('\n') });
                        }
                        return;
                    }
                };

                for (const evt of events) {
                    if (!evt.event || !evt.data) {
                        continue;
                    }

                    let payload;
                    try {
                        payload = JSON.parse(evt.data);
                    } catch (error) {
                        errors.push(`JSON解析失败: ${error.message}`);
                        continue;
                    }

                    if (evt.event === 'content_block_start') {
                        const indexKey = String(payload?.index ?? '');
                        const blockInfo = payload?.content_block || {};
                        if (!indexKey || !blockInfo?.type) {
                            continue;
                        }
                        activeBlocks.set(indexKey, {
                            type: blockInfo.type,
                            text: '',
                            partialJson: '',
                            toolName: blockInfo.name || '',
                            inputSnapshot: blockInfo.input,
                        });
                    } else if (evt.event === 'content_block_delta') {
                        const indexKey = String(payload?.index ?? '');
                        const block = activeBlocks.get(indexKey);
                        if (!block) {
                            continue;
                        }
                        const delta = payload?.delta;
                        if (!delta) {
                            continue;
                        }

                        if (delta.type === 'thinking_delta' && typeof delta.thinking === 'string') {
                            block.text += delta.thinking;
                        } else if (delta.type === 'text_delta' && typeof delta.text === 'string') {
                            block.text += delta.text;
                        } else if (delta.type === 'input_json_delta' && typeof delta.partial_json === 'string') {
                            block.partialJson += delta.partial_json;
                        }
                    } else if (evt.event === 'content_block_stop') {
                        const indexKey = String(payload?.index ?? '');
                        const block = activeBlocks.get(indexKey);
                        if (!block) {
                            continue;
                        }
                        finalizeBlock(indexKey, block);
                        activeBlocks.delete(indexKey);
                    }
                }

                if (activeBlocks.size > 0) {
                    for (const [indexKey, block] of activeBlocks.entries()) {
                        errors.push(`内容块未正常结束(index=${indexKey})`);
                        finalizeBlock(indexKey, block);
                    }
                    activeBlocks.clear();
                }

                return buildOutput(entries, errors);
            };

            if (!rawText || !rawText.trim()) {
                return {
                    success: true,
                    partial: false,
                    text: PARSED_EMPTY_TEXT,
                    errors: []
                };
            }

            try {
                const events = parseSseEvents(rawText);
                const lowerService = (serviceName || '').toLowerCase();
                const hasClaudeBlocks = events.some(evt => evt.event && evt.event.startsWith('content_block'));

                if (lowerService === 'claude' || hasClaudeBlocks) {
                    return parseClaudeEvents(events);
                }

                return parseCodexEvents(events);
            } catch (error) {
                return {
                    success: false,
                    partial: false,
                    text: `解析失败：${error.message}`,
                    errors: [error.message]
                };
            }
        };

        const showLogDetail = (log) => {
            selectedLog.value = log;
            activeLogTab.value = 'basic'; // 重置到基本信息tab
            logDetailVisible.value = true;

            decodedRequestBody.value = decodeBodyContent(log.filtered_body);
            decodedOriginalRequestBody.value = decodeBodyContent(log.original_body);
            responseOriginalContent.value = decodeBodyContent(log.response_content);
            const serviceName = (log?.service || '').toLowerCase();
            isCodexLog.value = serviceName === 'codex';
            isClaudeLog.value = serviceName === 'claude';

            const shouldAttemptParse = (isCodexLog.value || isClaudeLog.value) && !!responseOriginalContent.value;

            if (shouldAttemptParse) {
                const parsedResult = parseResponseLogContent(responseOriginalContent.value, log?.service);
                if (parsedResult.success) {
                    parsedResponseContent.value = parsedResult.text;
                    decodedResponseContent.value = parsedResponseContent.value;
                    isResponseContentParsed.value = true;
                    if (parsedResult.partial) {
                        ElMessage.warning('部分响应解析失败，已展示可用内容');
                        console.warn('响应解析部分失败:', parsedResult.errors);
                    }
                } else {
                    parsedResponseContent.value = '';
                    decodedResponseContent.value = responseOriginalContent.value;
                    isResponseContentParsed.value = false;
                    ElMessage.warning(parsedResult.text || '响应解析失败');
                }
            } else {
                parsedResponseContent.value = '';
                decodedResponseContent.value = responseOriginalContent.value || '';
                isResponseContentParsed.value = false;
            }
        };

        const toggleParsedResponse = () => {
            if (!canParseSelectedLog.value) {
                return;
            }

            if (isResponseContentParsed.value) {
                isResponseContentParsed.value = false;
                decodedResponseContent.value = responseOriginalContent.value;
            } else {
                if (!parsedResponseContent.value) {
                    const parsedResult = parseResponseLogContent(responseOriginalContent.value, selectedLog.value?.service);
                    if (parsedResult.success) {
                        parsedResponseContent.value = parsedResult.text;
                        if (parsedResult.partial) {
                            ElMessage.warning('部分响应解析失败，已展示可用内容');
                            console.warn('响应解析部分失败:', parsedResult.errors);
                        }
                    } else {
                        ElMessage.warning(parsedResult.text || '响应解析失败');
                        return;
                    }
                }

                isResponseContentParsed.value = true;
                decodedResponseContent.value = parsedResponseContent.value || PARSED_EMPTY_TEXT;
            }
        };
        
        // 加载所有日志
        const loadAllLogs = async () => {
            allLogsLoading.value = true;
            try {
                const data = await fetchWithErrorHandling('/api/logs/all');
                const logs = Array.isArray(data) ? data : [];
                // 后端已经根据 logLimit 裁剪，这里直接使用
                allLogs.value = logs;
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

        // 加载系统配置
        const loadSystemConfig = async () => {
            try {
                const data = await fetchWithErrorHandling('/api/system/config');
                if (data.config) {
                    systemConfig.logLimit = data.config.logLimit || 50;
                }
            } catch (error) {
                console.error('加载系统配置失败:', error);
                systemConfig.logLimit = 50;
            }
        };

        // 处理日志条数变更
        const handleLogLimitChange = async (newLimit) => {
            try {
                allLogsLoading.value = true;

                // 保存配置到后端（后端会自动裁剪日志文件）
                const response = await fetch('/api/system/config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ logLimit: newLimit })
                });

                const result = await response.json();

                if (!response.ok) {
                    throw new Error(result.error || '保存配置失败');
                }

                ElMessage.success(`日志条数已设置为 ${newLimit} 条`);

                // 刷新日志列表
                await loadAllLogs();

            } catch (error) {
                ElMessage.error('保存配置失败: ' + error.message);
            } finally {
                allLogsLoading.value = false;
            }
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
                // JSON变化后更新合并视图
                if (configEditMode.value === 'merged') {
                    buildMergedFromFriendly('claude');
                }
            });
        });

        // 监听Codex配置JSON变化
        watch(() => configContents.codex, (newValue) => {
            // 延迟执行，避免在同步过程中产生循环调用
            nextTick(() => {
                syncJsonToForm('codex');
                // JSON变化后更新合并视图
                if (configEditMode.value === 'merged') {
                    buildMergedFromFriendly('codex');
                }
            });
        });

        // 监听配置编辑模式变化
        watch(() => configEditMode.value, (newMode, oldMode) => {
            if (newMode === 'merged') {
                // 进入合并模式：从 friendlyConfigs 构建
                buildMergedFromFriendly(activeConfigTab.value);
            }
        });

        // 监听活动配置Tab变化（在合并模式下）
        watch(() => activeConfigTab.value, (newTab) => {
            if (configEditMode.value === 'merged') {
                buildMergedFromFriendly(newTab);
            }
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

                // 禁用自动连接，改为手动连接模式
                // setTimeout(() => {
                //     realtimeManager.value.connectAll();
                //     console.log('实时连接管理器初始化成功');
                // }, 1000); // 延迟1秒再连接
                console.log('实时连接管理器初始化成功，请手动点击重连按钮连接服务器');
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

                if (isLoadbalanceWeightMode.value) {
                    loadLoadbalanceConfig().catch(err => console.error('刷新负载均衡数据失败:', err));
                }
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

        const disconnectRealtime = () => {
            if (realtimeManager.value) {
                console.log('手动断开实时服务...');
                realtimeManager.value.disconnectAll();
                ElMessage.info('已断开实时服务连接');
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
        onMounted(async () => {
            updateViewport();
            if (typeof window !== 'undefined') {
                window.addEventListener('resize', updateViewport, { passive: true });
            }

            await loadSystemConfig();
            loadData();
            // 初始化实时连接
            initRealTimeConnections();
        });

        onBeforeUnmount(() => {
            if (typeof window !== 'undefined') {
                window.removeEventListener('resize', updateViewport);
            }
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
            drawerSizes,
            dialogSizes,
            isMobileViewport,
            activeConfigTab,
            activeLogTab,
            showTransformedData,
            activeRequestSubTab,
            activeResponseSubTab,
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
            // 合并模式相关
            mergedConfigs,
            mergedDialogVisible,
            mergedDialogService,
            mergedDialogDraft,
            mergedDialogMode,
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
            systemConfig,
            handleLogLimitChange,
            copyToClipboard,
            formatFilteredRequestBody,
            formatOriginalRequestBody,
            formatResponseContent,
            responseOriginalContent,
            isResponseContentParsed,
            toggleParsedResponse,
            isCodexLog,
            isClaudeLog,
            canParseSelectedLog,
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
            saveInteractiveConfig,
            removeConfigSite,
            handleActiveChange,
            syncFormToJson,
            syncJsonToForm,
            // 合并模式相关方法
            isValidUrl,
            buildMergedFromFriendly,
            rebuildFriendlyFromMerged,
            applyMergedGroupUpdate,
            autoGenerateName,
            enforceSingleActive,
            toggleMergedActive,
            updateMergedEntryAuth,
            applyMergedEntryNameUpdate,
            addMergedEntry,
            removeMergedEntry,
            deleteMergedGroup,
            switchToMergedMode,
            saveMergedConfig,
            openMergedDialog,
            editMergedGroup,
            isMergedGroupActive,
            addDialogEntry,
            removeDialogEntry,
            cancelMergedDialog,
            submitMergedDialog,
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
            reconnectRealtime,
            disconnectRealtime,

            // 模型路由管理相关
            routingMode,
            routingConfig,
            routingConfigSaving,
            modelMappingDrawerVisible,
            configMappingDrawerVisible,
            activeModelMappingTab,
            activeConfigMappingTab,
            selectRoutingMode,
            getRoutingModeText,
            openModelMappingDrawer,
            openConfigMappingDrawer,
            closeModelMappingDrawer,
            closeConfigMappingDrawer,
            addModelMapping,
            removeModelMapping,
            addConfigMapping,
            removeConfigMapping,
            saveRoutingConfig,
            loadRoutingConfig,

            // 负载均衡相关
            loadbalanceConfig,
            loadbalanceSaving,
            loadbalanceLoading,
            loadbalanceDisabledNotice,
            isLoadbalanceWeightMode,
            weightedTargets,
            selectLoadbalanceMode,
            onAutoResetMinutesChange,
            toggleManualDisableForToday,
            pinWeightedTarget,
            resetLoadbalanceFailures,
            resettingFailures,
            pinningState
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
