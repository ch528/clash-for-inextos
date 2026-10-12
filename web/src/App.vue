<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'

const page = ref('overview')
const view = ref('loading')
const status = ref(null)
const config = ref(null)
const system = ref(null)
const traffic = ref(null)
const network = ref(null)
const networkSettings = ref({
  tun_enabled: false,
  tun_stack: 'system',
  tun_ipv6: false,
  tun_auto_redirect: false,
  lan_proxy: { enabled: false, mode: 'all', clients: [], bypass_cidrs: [] },
  dns: { enabled: false, ipv6: false, mode: 'recommended', custom_nameservers: [] },
})
const newLANClient = ref({ name: '', ip: '', mac: '', action: 'direct' })
const bypassCIDRText = ref('')
const customDNSText = ref('')
const groups = ref([])
const subscriptions = ref([])
const updateCheck = ref(null)
const updateCheckBusy = ref(false)
const appUpdateStatus = ref(null)
const appUpdateBusy = ref(false)
const appUpdateMessage = ref('')
const logs = ref([])
const logBox = ref(null)
const logSource = ref('app')
const logLevel = ref('all')
const logsPaused = ref(false)
const diagnostics = ref(null)
const diagnosticBusy = ref(false)
const supportBusy = ref(false)
const remoteAccess = ref(null)
const account = ref({ username: '', current_password: '', new_password: '', confirm_password: '' })
const behaviorSettings = ref({ auto_start: true, restart_on_failure: true })
const backupInput = ref(null)
const backupContent = ref('')
const backupPreview = ref(null)
const rates = ref({ upload: 0, download: 0 })
let lastTraffic = null
const busy = ref(false)

const mihomoUpdateBusy = ref(false)
const mihomoUpdateMessage = ref('')
const dashboardUpdateBusy = ref(false)
const dashboardUpdateMessage = ref('')
const geoUpdateBusy = ref(false)
const geoUpdateMessage = ref('')
const message = ref('')
const error = ref('')
const mode = ref('rule')
const selectedGroup = ref('')
const form = ref({ name: '', url: '', enabled: true })
const authForm = ref({ username: '', password: '', confirm: '' })
const setupAllowed = ref(false)
const appearance = ref(localStorage.getItem('inextos-clash-appearance') || 'system')
const density = ref(localStorage.getItem('inextos-clash-density') || 'comfortable')
const delay = ref({})
const events = ref([])
const notificationsOpen = ref(false)
const lastSeenEventID = ref(localStorage.getItem('inextos-clash-last-seen-event') || '0')
const modeLabels = { rule: 'Rule', global: 'Global', direct: 'Direct' }
const remoteAccessLabels = {
  ready: '证书与当前 IPv6 匹配',
  needs_certificate_refresh: '公网 HTTPS 需要更新证书',
  certificate_expired: '证书已过期',
  certificate_not_yet_valid: '证书尚未生效',
  certificate_unavailable: '无法读取 :8844 证书',
  public_ipv6_unavailable: '未检测到全局公网 IPv6',
}
let timer
let eventTimer
let appUpdateTimer
let appUpdatePollStartAt = 0

const selectedGroupData = computed(() => groups.value.find((group) => group.name === selectedGroup.value))
const visibleLogs = computed(() => logs.value.filter((line) => logLevel.value === 'all' || line.toLowerCase().includes(logLevel.value)))
const geoUpdateAvailable = computed(() => updateCheck.value?.components?.some((item) => item.id === 'geo' && item.update_available === true) || false)
const unreadEventCount = computed(() => events.value.filter((item) => BigInt(item.id) > BigInt(lastSeenEventID.value)).length)
const networkCaptureRequested = computed(() => networkSettings.value.tun_enabled || networkSettings.value.lan_proxy.enabled || networkSettings.value.dns.enabled)

function compactVersionLabel(value) {
  if (!value) return '—'
  return value.match(/\bv?\d+\.\d+\.\d+(?:[-+][\w.-]+)?/)?.[0] || value
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
  })
  const data = await response.json().catch(() => ({}))
  if (response.status === 401 && view.value === 'app') expireSession()
  if (!response.ok) throw new Error(data.error || `请求失败 (${response.status})`)
  return data
}

async function initializeAuth() {
  try {
    const status = await api('/api/auth/status')
    if (!status.initialized) {
	  setupAllowed.value = status.setup_allowed
	  view.value = status.setup_allowed ? 'setup' : 'setup-blocked'
      return
    }
    const response = await fetch('/api/auth/me')
    if (response.ok) enterApp()
    else view.value = 'login'
  } catch (err) {
    error.value = err.message
    view.value = 'login'
  }
}

async function createAdministrator() {
  error.value = ''
  message.value = ''
  if (authForm.value.password !== authForm.value.confirm) {
    error.value = '两次输入的密码不一致'
    return
  }
  try {
    await api('/api/auth/setup', {
      method: 'POST',
      body: JSON.stringify({ username: authForm.value.username, password: authForm.value.password }),
    })
    authForm.value = { username: authForm.value.username, password: '', confirm: '' }
    view.value = 'login'
    message.value = '管理员已初始化，请使用刚设置的密码登录'
  } catch (err) { error.value = err.message }
}

async function login() {
  error.value = ''
  message.value = ''
  try {
    await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: authForm.value.username, password: authForm.value.password }) })
    authForm.value.password = ''
    enterApp()
  } catch (err) { error.value = err.message }
}

function enterApp() {
  view.value = 'app'
  applyAppearance()
  loadSubscriptions()
  loadNetwork()
  loadEvents()
  loadApplicationUpdateStatus()
  refresh()
  timer = window.setInterval(refresh, 3000)
  eventTimer = window.setInterval(loadEvents, 30000)
}

function expireSession() {
  if (timer) window.clearInterval(timer)
  if (eventTimer) window.clearInterval(eventTimer)
  if (appUpdateTimer) window.clearTimeout(appUpdateTimer)
  timer = undefined
  eventTimer = undefined
  appUpdateTimer = undefined
  appUpdateBusy.value = false
  notificationsOpen.value = false
  view.value = 'login'
  status.value = null
}

async function logout() {
  try { await api('/api/auth/logout', { method: 'POST' }) } catch (err) { error.value = err.message }
  expireSession()
}

async function checkUpdates() {
  updateCheckBusy.value = true
  error.value = ''
  try { updateCheck.value = await api('/api/updates/check') }
  catch (err) { error.value = err.message }
  finally { updateCheckBusy.value = false }
}

function applicationUpdateActive(state) {
  return ['checking', 'downloading', 'installing'].includes(state)
}

function applicationUpdateTerminal(state) {
  return ['idle', 'no_update', 'succeeded', 'rolled_back', 'failed'].includes(state)
}

async function loadApplicationUpdateStatus() {
  try {
    appUpdateStatus.value = await api('/api/updates/app/status')
    if (applicationUpdateActive(appUpdateStatus.value.state)) {
      appUpdateBusy.value = true
      appUpdatePollStartAt = Date.now()
      pollApplicationUpdate()
    }
  } catch {}
}

async function pollApplicationUpdate() {
  if (appUpdateTimer) window.clearTimeout(appUpdateTimer)
  try {
    appUpdateStatus.value = await api('/api/updates/app/status')
    if (appUpdateStatus.value.state === 'idle' && appUpdateBusy.value) {
      if (Date.now() - appUpdatePollStartAt > 15000) {
        appUpdateBusy.value = false
        appUpdateMessage.value = '更新任务没有启动，请稍后重试。'
        return
      }
      appUpdateMessage.value = '正在启动应用更新…'
      appUpdateTimer = window.setTimeout(pollApplicationUpdate, 1000)
      return
    }
    if (applicationUpdateTerminal(appUpdateStatus.value.state)) {
      appUpdateBusy.value = false
      appUpdatePollStartAt = 0
      appUpdateMessage.value = appUpdateStatus.value.message || ''
      if (['succeeded', 'rolled_back'].includes(appUpdateStatus.value.state)) {
        await checkUpdates()
        await refresh()
      }
      return
    }
    appUpdateBusy.value = true
    appUpdateMessage.value = appUpdateStatus.value.message || '应用更新正在进行。'
  } catch {
    appUpdateMessage.value = '管理服务正在重启，页面会自动重新连接。'
  }
  if (appUpdateBusy.value) appUpdateTimer = window.setTimeout(pollApplicationUpdate, 2500)
}

async function updateApplication() {
  if (!window.confirm('更新会短暂重启 Clash for iNextOS 管理服务，期间页面会断开，完成后可能需要重新登录。网络接管必须关闭；安装失败时会自动恢复当前版本。继续更新？')) return
  appUpdateBusy.value = true
  appUpdatePollStartAt = Date.now()
  appUpdateMessage.value = '正在启动更新…'
  try {
    await api('/api/updates/app', { method: 'POST' })
    appUpdateTimer = window.setTimeout(pollApplicationUpdate, 1000)
  } catch (err) {
    appUpdateBusy.value = false
    appUpdateMessage.value = err.message
  }
}

async function updateMihomo() {
  if (!window.confirm('更新 Mihomo 会短暂停止代理，完成后恢复原来的运行状态。启动失败会自动恢复旧版本。继续更新？')) return
  mihomoUpdateBusy.value = true
  mihomoUpdateMessage.value = '正在下载并验证更新，请等待完成。'
  try {
    await api('/api/updates/mihomo', { method: 'POST' })
    mihomoUpdateMessage.value = 'Mihomo 更新完成，已恢复原来的运行状态。'
    await checkUpdates()
  } catch (err) { mihomoUpdateMessage.value = err.message }
  finally { mihomoUpdateBusy.value = false; await refresh() }
}

async function updateDashboard(rollback = false) {
  if (!window.confirm(rollback ? '恢复上一个 Zashboard 版本？' : '下载并更新 Zashboard？更新后请重新打开面板。')) return
  dashboardUpdateBusy.value = true
  dashboardUpdateMessage.value = rollback ? '正在恢复上一版…' : '正在下载并验证面板…'
  try {
    await api(rollback ? '/api/updates/zashboard/rollback' : '/api/updates/zashboard', { method: 'POST' })
    dashboardUpdateMessage.value = rollback ? '已恢复上一版，请重新打开面板。' : 'Zashboard 更新完成，请重新打开面板。'
    await checkUpdates()
  } catch (err) { dashboardUpdateMessage.value = err.message }
  finally { dashboardUpdateBusy.value = false }
}

async function updateGeo() {
  if (!window.confirm('更新当前配置实际使用的 Geo 数据。Mihomo 运行时会短暂停止并在完成后恢复；网络接管开启时需先关闭。继续？')) return
  geoUpdateBusy.value = true
  geoUpdateMessage.value = '正在下载并校验 Geo 数据…'
  try {
    await api('/api/updates/geo', { method: 'POST' })
    geoUpdateMessage.value = 'Geo 数据更新完成。'
    await checkUpdates()
  } catch (err) { geoUpdateMessage.value = err.message }
  finally { geoUpdateBusy.value = false; await refresh() }
}

async function refresh() {
  const results = await Promise.allSettled([
    api('/api/system'),
    api('/api/mihomo/status'),
    api('/api/mihomo/config'),
    api('/api/mihomo/traffic'),
  ])
  if (results[0].status === 'fulfilled') system.value = results[0].value
  if (results[1].status === 'fulfilled') status.value = results[1].value
  if (results[2].status === 'fulfilled') {
    config.value = results[2].value
    mode.value = config.value.mode || 'rule'
  }
  if (results[3].status === 'fulfilled') {
    const next = results[3].value
    const now = Date.now()
    if (lastTraffic) {
      const seconds = Math.max((now - lastTraffic.at) / 1000, 1)
      rates.value = { upload: Math.max(0, (next.total_upload_bytes - lastTraffic.upload) / seconds), download: Math.max(0, (next.total_download_bytes - lastTraffic.download) / seconds) }
    }
    lastTraffic = { at: now, upload: next.total_upload_bytes, download: next.total_download_bytes }
    traffic.value = next
  }
  if (page.value === 'logs' && !logsPaused.value) await loadLogs()
  const controllerError = status.value?.running && !config.value?.controller_status
    ? 'Mihomo 进程运行中，但 Controller 暂不可用'
    : ''
  error.value = status.value?.error || controllerError || results[1].reason?.message || results[2].reason?.message || ''
}

async function runAction(action) {
  busy.value = true
  error.value = ''
  message.value = ''
  try {
    await api(`/api/mihomo/${action}`, { method: 'POST' })
    message.value = action === 'stop' ? 'Mihomo 已停止' : '操作完成'
    await refresh()
  } catch (err) {
    error.value = err.message
  } finally {
    busy.value = false
  }
}

async function changeMode() {
  try {
    await api('/api/mihomo/mode', { method: 'POST', body: JSON.stringify({ mode: mode.value }) })
    message.value = `模式已切换为 ${modeLabels[mode.value]}`
    error.value = ''
  } catch (err) {
    error.value = err.message
    await refresh()
  }
}

async function loadGroups() {
  try {
    groups.value = await api('/api/mihomo/groups')
    if (!groups.value.some((group) => group.name === selectedGroup.value)) {
      selectedGroup.value = groups.value[0]?.name || ''
    }
  } catch (err) {
    error.value = err.message
  }
}

async function loadSubscriptions() {
  try { subscriptions.value = await api('/api/subscriptions') } catch (err) { error.value = err.message }
}

async function loadNetwork() {
  try {
    network.value = await api('/api/network/status')
    networkSettings.value = {
      tun_enabled: network.value.tun_enabled || false,
      tun_stack: network.value.tun_stack || 'system',
      tun_ipv6: network.value.tun_ipv6 || false,
      tun_auto_redirect: network.value.tun_auto_redirect || false,
      lan_proxy: JSON.parse(JSON.stringify(network.value.lan_proxy || { enabled: false, mode: 'all', clients: [], bypass_cidrs: [] })),
      dns: JSON.parse(JSON.stringify(network.value.dns || { enabled: false, ipv6: false, mode: 'recommended', custom_nameservers: [] })),
    }
    bypassCIDRText.value = networkSettings.value.lan_proxy.bypass_cidrs.join('\n')
    customDNSText.value = networkSettings.value.dns.custom_nameservers.join('\n')
    newLANClient.value.action = networkSettings.value.lan_proxy.mode === 'selected' ? 'proxy' : 'direct'
  } catch (err) { error.value = err.message }
}

function splitNetworkLines(value) {
  return value.split(/[\r\n,;]+/).map((item) => item.trim()).filter(Boolean)
}

function changeLANMode(mode) {
  networkSettings.value.lan_proxy.mode = mode
  if (mode === 'selected') {
    networkSettings.value.lan_proxy.clients = networkSettings.value.lan_proxy.clients.map((client) => ({ ...client, action: 'proxy' }))
    newLANClient.value.action = 'proxy'
  } else {
    newLANClient.value.action = 'direct'
  }
}

function addLANClient() {
  const client = {
    name: newLANClient.value.name.trim(),
    ip: newLANClient.value.ip.trim(),
    mac: newLANClient.value.mac.trim(),
    action: networkSettings.value.lan_proxy.mode === 'selected' ? 'proxy' : newLANClient.value.action,
  }
  if (!client.ip && !client.mac) {
    error.value = '请填写设备 IP 或 MAC 地址'
    return
  }
  const duplicate = networkSettings.value.lan_proxy.clients.some((item) => (client.mac && item.mac?.toLowerCase() === client.mac.toLowerCase()) || (client.ip && item.ip === client.ip))
  if (duplicate) {
    error.value = '该设备已在列表中'
    return
  }
  networkSettings.value.lan_proxy.clients.push(client)
  newLANClient.value = { name: '', ip: '', mac: '', action: networkSettings.value.lan_proxy.mode === 'selected' ? 'proxy' : 'direct' }
  error.value = ''
}

function useLANClient(client) {
  newLANClient.value = {
    name: '',
    ip: client.ip,
    mac: client.mac,
    action: networkSettings.value.lan_proxy.mode === 'selected' ? 'proxy' : 'direct',
  }
}

function removeLANClient(index) {
  networkSettings.value.lan_proxy.clients.splice(index, 1)
}

async function saveNetworkSettings() {
  busy.value = true
  error.value = ''
  try {
    const settings = JSON.parse(JSON.stringify(networkSettings.value))
    settings.lan_proxy.bypass_cidrs = splitNetworkLines(bypassCIDRText.value)
    settings.dns.custom_nameservers = splitNetworkLines(customDNSText.value)
    network.value = await api('/api/network/settings', { method: 'POST', body: JSON.stringify(settings) })
    await loadNetwork()
    message.value = network.value.capture_active ? '网络接管已开启，自动恢复观察期仍在运行' : '网络设置已保存'
    await refresh()
  } catch (err) {
    error.value = err.message
  } finally { busy.value = false }
}

async function addSubscription() {
  busy.value = true
  error.value = ''
  try {
    await api('/api/subscriptions', { method: 'POST', body: JSON.stringify(form.value) })
    form.value = { name: '', url: '', enabled: true }
    message.value = '订阅已保存，请更新并设为当前订阅'
    await loadSubscriptions()
  } catch (err) { error.value = err.message } finally { busy.value = false }
}

async function updateSubscription(item) {
  busy.value = true
  error.value = ''
  try {
    await api(`/api/subscriptions/${item.id}/update`, { method: 'POST' })
    message.value = '订阅已验证并更新'
    await loadSubscriptions()
  } catch (err) { error.value = err.message; await loadSubscriptions() } finally { busy.value = false }
}

async function deleteSubscription(item) {
  if (!window.confirm(`删除订阅“${item.name}”？`)) return
  try {
    await api(`/api/subscriptions/${item.id}`, { method: 'DELETE' })
    await loadSubscriptions()
    message.value = '订阅已删除'
  } catch (err) { error.value = err.message }
}

async function chooseProxy(event) {
  const name = event.target.value
  try {
    await api(`/api/mihomo/proxies/${encodeURIComponent(selectedGroup.value)}`, {
      method: 'POST', body: JSON.stringify({ name }),
    })
    await loadGroups()
    message.value = '节点已切换'
  } catch (err) { error.value = err.message; await loadGroups() }
}

async function testDelay(name) {
  try { delay.value[name] = (await api(`/api/mihomo/delay/${encodeURIComponent(name)}`)).delay }
  catch (err) { error.value = err.message }
}

async function activateSubscription(item) {
  try { await api(`/api/subscriptions/${item.id}/activate`, { method: 'POST' }); await loadSubscriptions(); await loadGroups(); message.value = '当前订阅已切换' }
  catch (err) { error.value = err.message }
}

async function editSubscription(item) {
  const name = window.prompt('订阅名称', item.name)
  if (name === null) return
  try { await api(`/api/subscriptions/${item.id}`, { method: 'PATCH', body: JSON.stringify({ name, enabled: item.enabled, auto_update_hours: Number(item.auto_update_hours || 0) }) }); await loadSubscriptions() }
  catch (err) { error.value = err.message; await loadSubscriptions() }
}

async function setSubscriptionSettings(item, enabled, hours) {
  try { await api(`/api/subscriptions/${item.id}`, { method: 'PATCH', body: JSON.stringify({ name: item.name, enabled, auto_update_hours: Number(hours) }) }); await loadSubscriptions() }
  catch (err) { error.value = err.message; await loadSubscriptions() }
}

async function changeAutoUpdate(item, event) {
  let hours = Number(event.target.value)
  if (event.target.value === 'custom') {
    const value = window.prompt('自定义自动更新间隔（1–720 小时）', String(item.auto_update_hours || 48))
    if (value === null) { event.target.value = String(item.auto_update_hours || 0); return }
    if (!/^\d+$/.test(value.trim())) {
      error.value = '请输入 1–720 之间的整数小时数'
      event.target.value = String(item.auto_update_hours || 0)
      return
    }
    hours = Number(value)
  }
  if (!Number.isInteger(hours) || hours < 0 || hours > 720 || (event.target.value === 'custom' && hours === 0)) {
    error.value = '自动更新间隔必须为关闭或 1–720 小时'
    event.target.value = String(item.auto_update_hours || 0)
    return
  }
  await setSubscriptionSettings(item, item.enabled, hours)
}

async function closeConnection(id) {
  try { await api(`/api/mihomo/connections/${encodeURIComponent(id)}`, { method: 'DELETE' }); await refresh() }
  catch (err) { error.value = err.message }
}

async function closeAllConnections() {
  if (!window.confirm('关闭所有活动连接？')) return
  try { await api('/api/mihomo/connections', { method: 'DELETE' }); await refresh() }
  catch (err) { error.value = err.message }
}

async function saveAccount() {
  try { await api('/api/auth/account', { method: 'POST', body: JSON.stringify(account.value) }); message.value = '账户已更新，请重新登录'; expireSession() }
  catch (err) { error.value = err.message }
}

async function loadBehaviorSettings() {
  try { behaviorSettings.value = await api('/api/settings/behavior') }
  catch (err) { error.value = err.message }
}

async function loadRemoteAccess() {
  try { remoteAccess.value = await api('/api/remote-access') }
  catch (err) { error.value = err.message }
}

async function saveBehaviorSettings() {
  try {
    behaviorSettings.value = await api('/api/settings/behavior', { method: 'POST', body: JSON.stringify(behaviorSettings.value) })
    message.value = 'Mihomo 生命周期设置已保存'
  } catch (err) { error.value = err.message }
}

async function exportBackup() {
  busy.value = true
  error.value = ''
  try {
    if (window.top !== window.self) {
      throw new Error('当前 iNextOS 内部窗口不允许下载文件。请在独立浏览器标签打开 Clash 后再导出。')
    }
    const response = await fetch('/api/backup/export')
    if (response.status === 401) expireSession()
    if (!response.ok) {
      const data = await response.json().catch(() => ({}))
      throw new Error(data.error || `导出失败 (${response.status})`)
    }
    const backup = await response.json()
    backup.appearance = { theme: appearance.value, density: density.value }
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'clash-for-inextos-backup.json'
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 0)
    message.value = '备份已导出；文件包含订阅地址与节点配置，请妥善保管'
  } catch (err) { error.value = err.message } finally { busy.value = false }
}

async function previewBackup(event) {
  const file = event.target.files?.[0]
  backupPreview.value = null
  backupContent.value = ''
  error.value = ''
  if (!file) return
  if (file.size > 64 * 1024 * 1024) {
    error.value = '备份文件超过 64 MB 限制'
    event.target.value = ''
    return
  }
  busy.value = true
  try {
    backupContent.value = await file.text()
    backupPreview.value = await api('/api/backup/preview', { method: 'POST', body: backupContent.value })
    message.value = '备份校验完成，请检查恢复预览'
  } catch (err) {
    backupContent.value = ''
    error.value = err.message
  } finally {
    busy.value = false
    event.target.value = ''
  }
}

async function applyBackup() {
  if (!backupContent.value || !backupPreview.value) return
  busy.value = true
  error.value = ''
  try {
    const result = await api('/api/backup/apply', { method: 'POST', body: backupContent.value })
    if (result.appearance?.theme) appearance.value = result.appearance.theme
    if (result.appearance?.density) density.value = result.appearance.density
    applyAppearance()
    backupContent.value = ''
    backupPreview.value = null
    await Promise.all([loadSubscriptions(), loadNetwork(), refresh()])
    message.value = '恢复完成；Mihomo 保持停止，TUN 已关闭'
  } catch (err) { error.value = err.message } finally { busy.value = false }
}

function cancelBackupPreview() {
  backupContent.value = ''
  backupPreview.value = null
  error.value = ''
}

async function runDiagnostics() {
  diagnosticBusy.value = true
  try { diagnostics.value = await api('/api/diagnostics') } catch (err) { error.value = err.message }
  finally { diagnosticBusy.value = false }
}

async function downloadSupportBundle() {
  supportBusy.value = true
  error.value = ''
  try {
    const response = await fetch('/api/support')
    if (response.status === 401) expireSession()
    if (!response.ok) {
      const data = await response.json().catch(() => ({}))
      throw new Error(data.error || `生成诊断报告失败 (${response.status})`)
    }
    const url = URL.createObjectURL(await response.blob())
    const link = document.createElement('a')
    link.href = url
    link.download = 'clash-for-inextos-support.zip'
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 0)
    message.value = '诊断报告已下载；报告自动排除了账户凭据、订阅地址和私钥。'
  } catch (err) { error.value = err.message }
  finally { supportBusy.value = false }
}

async function loadLogs() {
  if (logsPaused.value) return
  try {
    logs.value = ((await api(logSource.value === 'mihomo' ? '/api/logs/mihomo' : '/api/logs?n=1000')).lines || []).slice(-1000)
    await nextTick()
    if (!logsPaused.value && logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight
  } catch (err) { error.value = err.message }
}

async function loadEvents() {
  try {
    events.value = (await api('/api/events?limit=50')).events || []
    if (!localStorage.getItem('inextos-clash-last-seen-event')) markEventsSeen()
  } catch (err) { error.value = err.message }
}

function markEventsSeen() {
	const latest = events.value[0]?.id || String(BigInt(Date.now()) * 1000000n)
	lastSeenEventID.value = latest
	localStorage.setItem('inextos-clash-last-seen-event', latest)
}

async function toggleNotifications() {
  notificationsOpen.value = !notificationsOpen.value
  if (notificationsOpen.value) {
    await loadEvents()
    markEventsSeen()
  }
}

async function copyLogs() { await navigator.clipboard.writeText(visibleLogs.value.join('\n')); message.value = '已复制日志' }
function clearLogs() { logs.value = []; logsPaused.value = true }

function openPage(next) {
  page.value = next
  error.value = ''
  if (next === 'subscriptions') loadSubscriptions()
  if (next === 'network') loadNetwork()
  if (next === 'logs') loadLogs()
  if (next === 'settings') {
    api('/api/auth/me').then((data) => { account.value.username = data.username || '' }).catch((err) => { error.value = err.message })
    loadBehaviorSettings()
    loadRemoteAccess()
  }
}

function applyAppearance() {
  const resolved = appearance.value === 'system'
    ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    : appearance.value
  document.documentElement.dataset.theme = resolved
  document.documentElement.dataset.density = density.value
  localStorage.setItem('inextos-clash-appearance', appearance.value)
  localStorage.setItem('inextos-clash-density', density.value)
}

async function restoreNetwork() {
  busy.value = true
  error.value = ''
  try {
    network.value = await api('/api/network/restore', { method: 'POST' })
    message.value = '网络代理设置已恢复'
    await loadNetwork()
    await refresh()
  } catch (err) { error.value = err.message } finally { busy.value = false }
}

async function confirmNetwork() {
  busy.value = true
  error.value = ''
  try {
    network.value = await api('/api/network/confirm', { method: 'POST' })
    message.value = '网络测试已确认，自动回滚计时已取消'
  } catch (err) { error.value = err.message } finally { busy.value = false }
}

function bytes(value) {
  let n = Number(value || 0)
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++ }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

function formatExactBytes(value) {
  const amount = BigInt(value || '0')
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB']
  let divisor = 1n
  let unit = 0
  while (amount >= divisor * 1024n && unit < units.length - 1) { divisor *= 1024n; unit++ }
  if (unit === 0) return `${amount} B`
  const tenths = (amount * 10n + divisor / 2n) / divisor
  return `${tenths / 10n}.${tenths % 10n} ${units[unit]}`
}

function subscriptionUsageSummary(usage) {
  if (!usage) return '服务商未提供用量'
  const used = BigInt(usage.upload) + BigInt(usage.download)
  const total = BigInt(usage.total)
  const remaining = total === 0n ? null : (total > used ? total - used : 0n)
  return `已用 ${formatExactBytes(used)} / ${total === 0n ? '不限' : formatExactBytes(total)} · 剩余 ${remaining === null ? '不限' : formatExactBytes(remaining)}`
}

function duration(seconds) {
  const n = Number(seconds || 0)
  if (n < 60) return `${n} 秒`
  if (n < 3600) return `${Math.floor(n / 60)} 分钟`
  return `${Math.floor(n / 3600)} 小时 ${Math.floor((n % 3600) / 60)} 分钟`
}

onMounted(() => {
  initializeAuth()
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (appearance.value === 'system') applyAppearance()
  })
})
onUnmounted(() => { window.clearInterval(timer); window.clearInterval(eventTimer); window.clearTimeout(appUpdateTimer) })
</script>

<template>
  <main v-if="view === 'loading'" class="auth-page"><section class="auth-card"><div class="brand-mark">C</div><h1>Clash for iNextOS</h1><p>正在检查本地登录状态…</p></section></main>

  <main v-else-if="view === 'setup'" class="auth-page">
    <section class="auth-card">
      <div class="brand-mark">C</div><span class="eyebrow">首次使用</span><h1>初始化管理员</h1>
      <p>设置一个管理员账户。密码至少 8 个字符。</p>
      <form class="auth-form" @submit.prevent="createAdministrator">
        <label>用户名<input v-model.trim="authForm.username" pattern="[A-Za-z0-9._-]{3,32}" maxlength="32" autocomplete="username" required /></label>
        <label>管理员密码<input v-model="authForm.password" type="password" autocomplete="new-password" minlength="8" required /></label>
        <label>确认密码<input v-model="authForm.confirm" type="password" autocomplete="new-password" minlength="8" required /></label>
        <small>用户名 3–32 个字符，可使用字母、数字、点、下划线和连字符。密码使用 Argon2id 哈希保存。</small>
        <button class="button primary" type="submit">创建管理员</button>
      </form>
      <div v-if="error" class="auth-error">{{ error }}</div>
    </section>
  </main>

  <main v-else-if="view === 'setup-blocked'" class="auth-page"><section class="auth-card"><div class="brand-mark">C</div><h1>初始化尚未授权</h1><p>请在设备终端执行 <code>sudo inextos-clash setup-open</code>。授权有效期 10 分钟。</p><button class="button primary" @click="initializeAuth">重新检查</button></section></main>

  <main v-else-if="view === 'login'" class="auth-page">
    <section class="auth-card">
      <div class="brand-mark">C</div><span class="eyebrow">安全登录</span><h1>Clash for iNextOS</h1>
      <p>{{ message || '请输入管理员账户继续。' }}</p>
      <form class="auth-form" @submit.prevent="login">
        <label>用户名<input v-model.trim="authForm.username" autocomplete="username" required autofocus /></label>
        <label>管理员密码<input v-model="authForm.password" type="password" autocomplete="current-password" required /></label>
        <button class="button primary" type="submit">登录</button>
      </form>
      <div v-if="error" class="auth-error">{{ error }}</div>
    </section>
  </main>

  <div v-else class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">C</div>
        <div><strong>Clash</strong><span>for iNextOS</span></div>
      </div>
      <div class="nav-caption">管理</div>
      <button class="nav-item" :class="{ active: page === 'overview' }" @click="openPage('overview')"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3.5 10 8.5-7 8.5 7M5.5 9v11h13V9M9.5 20v-6h5v6" /></svg>概览</button>
      <button class="nav-item" :class="{ active: page === 'subscriptions' }" @click="openPage('subscriptions')"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 0 0-14.8-3L3 11M3 4v7h7M4 13a8 8 0 0 0 14.8 3L21 13m0 7v-7h-7" /></svg>订阅</button>
      <button class="nav-item" :class="{ active: page === 'console' }" @click="openPage('console')"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2.5" /><path d="M3 9h18M8 6.5h.01M11 6.5h.01" /></svg>Mihomo 控制台</button>
      <button class="nav-item" :class="{ active: page === 'network' }" @click="openPage('network')"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="2.5" /><circle cx="5" cy="6" r="1.5" /><circle cx="19" cy="6" r="1.5" /><circle cx="5" cy="18" r="1.5" /><circle cx="19" cy="18" r="1.5" /><path d="m10 10-4-3m8 3 4-3m-8 7-4 3m8-3 4 3" /></svg>网络代理</button>
      <button class="nav-item" :class="{ active: page === 'updates' }" @click="openPage('updates')"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16V3m0 0L7 8m5-5 5 5M5 14v6h14v-6" /></svg>更新</button>
      <button class="nav-item" :class="{ active: page === 'settings' }" @click="openPage('settings')"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3" /><path d="m19.4 15 .1.1a1.7 1.7 0 0 1-2.4 2.4l-.1-.1a1.7 1.7 0 0 0-2.9 1.2v.2a1.7 1.7 0 0 1-3.4 0v-.2a1.7 1.7 0 0 0-2.9-1.2l-.1.1a1.7 1.7 0 0 1-2.4-2.4l.1-.1a1.7 1.7 0 0 0-1.2-2.9H4a1.7 1.7 0 0 1 0-3.4h.2a1.7 1.7 0 0 0 1.2-2.9l-.1-.1a1.7 1.7 0 0 1 2.4-2.4l.1.1a1.7 1.7 0 0 0 2.9-1.2V2a1.7 1.7 0 0 1 3.4 0v.2a1.7 1.7 0 0 0 2.9 1.2l.1-.1a1.7 1.7 0 0 1 2.4 2.4l-.1.1a1.7 1.7 0 0 0 1.2 2.9h.2a1.7 1.7 0 0 1 0 3.4h-.2a1.7 1.7 0 0 0-1.2 2.9Z" /></svg>设置</button>
      <button class="nav-item" :class="{ active: page === 'about' }" @click="openPage('about')"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" /><path d="M12 11v5m0-8h.01" /></svg>关于</button>
      <div class="sidebar-footer"><span class="live-dot" :class="{ stopped: !status?.running }"></span>{{ status?.running ? '核心运行中' : status?.process_alive ? 'Controller 异常' : '核心已停止' }}</div>
    </aside>

    <main class="main">
      <header class="topbar">
        <div><span class="eyebrow">iNextOS · NanoPi R5S</span><h1>{{ { overview: '运行概览', subscriptions: '订阅管理', console: 'Mihomo 控制台', network: '网络代理', updates: '更新', settings: '设置', about: '关于' }[page] }}</h1></div>
        <div class="top-actions">
          <span class="status-pill" :class="status?.running ? 'ok' : status?.process_alive ? 'warn' : 'off'"><i></i>{{ status?.running ? '运行中' : status?.process_alive ? 'Controller 异常' : '已停止' }}</span>
          <div class="notification-wrap">
            <button class="icon-button notification-trigger" :aria-label="unreadEventCount ? `系统通知，${unreadEventCount} 条未读` : '系统通知'" :aria-expanded="notificationsOpen" @click.stop="toggleNotifications">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/></svg>
              <span v-if="unreadEventCount" class="notification-count">{{ unreadEventCount > 99 ? '99+' : unreadEventCount }}</span>
            </button>
            <section v-if="notificationsOpen" class="notification-panel" role="dialog" aria-label="系统通知" @click.stop>
              <div class="notification-heading"><strong>系统通知</strong><button class="text-button" @click="loadEvents">刷新</button></div>
              <p v-if="!events.length" class="empty-inline">暂无系统事件</p>
              <ul v-else class="notification-list">
                <li v-for="item in events" :key="item.id" :class="`severity-${item.severity}`">
                  <span class="notification-mark"></span><div><strong>{{ item.message }}</strong><time>{{ new Date(item.time).toLocaleString() }}</time></div>
                </li>
              </ul>
            </section>
          </div>
          <button class="icon-button" aria-label="刷新" @click="refresh">↻</button>
          <button class="button subtle logout-button" @click="logout">退出登录</button>
        </div>
      </header>

      <div v-if="error" class="notice error" role="alert" aria-live="polite"><span aria-hidden="true">!</span><div><strong>{{ status?.process_alive ? 'Controller 暂不可用' : '状态提示' }}</strong><small>{{ error }}</small></div><button aria-label="关闭错误提示" @click="error = ''">×</button></div>
      <div v-if="message" class="notice success" role="status" aria-live="polite"><span aria-hidden="true">✓</span><div><strong>{{ message }}</strong></div><button aria-label="关闭成功提示" @click="message = ''">×</button></div>

      <section v-if="page === 'overview'" class="content">
        <div class="hero-card">
          <div class="hero-copy"><div class="eyebrow pale">安全运行环境</div><h2>Clash for iNextOS</h2><p>Mihomo {{ status?.running ? '正在运行' : '已停止' }} · 管理接口仅绑定本机回环地址</p>
            <div class="hero-actions"><button class="button primary" :disabled="busy" @click="runAction(status?.process_alive ? 'restart' : 'start')">{{ status?.process_alive ? '重启 Mihomo' : '启动 Mihomo' }}</button><button v-if="status?.process_alive" class="button light" :disabled="busy" @click="runAction('stop')">停止</button><a class="button light" href="/dashboard/">打开 Zashboard</a></div>
          </div>
          <div class="hero-orbit"><div class="orbit-ring"></div><div class="orbit-core">C</div><i class="orbit-dot dot-a"></i><i class="orbit-dot dot-b"></i></div>
        </div>

        <div class="section-heading"><div><h2>核心状态</h2><p>本机运行信息与代理入口</p></div><span class="refresh-label">每 3 秒更新</span></div>
        <div class="stats-grid">
          <article class="stat-card"><div class="stat-icon blue">◉</div><span class="stat-label">Mihomo 版本</span><strong class="stat-value" :title="status?.version || null">{{ status?.version ? compactVersionLabel(status.version) : '未安装' }}</strong><small>{{ status?.process_alive ? `PID ${status.pid} · 运行 ${duration(status.uptime_seconds)}` : '尚未启动' }}</small></article>
          <article class="stat-card"><div class="stat-icon violet">⇄</div><span class="stat-label">运行模式</span><select v-model="mode" class="mode-select" :disabled="!config?.controller_status" @change="changeMode"><option value="rule">Rule</option><option value="global">Global</option><option value="direct">Direct</option></select><small>规则模式由 Mihomo Controller 管理</small></article>
          <article class="stat-card"><div class="stat-icon teal">⌁</div><span class="stat-label">当前订阅</span><strong class="stat-value">{{ subscriptions.find((item) => item.current)?.name || '未选择' }}</strong><small>{{ subscriptions.find((item) => item.current)?.last_updated ? `更新于 ${new Date(subscriptions.find((item) => item.current).last_updated).toLocaleString()}` : '在订阅页管理来源' }}</small></article>
          <article class="stat-card"><div class="stat-icon amber">⛨</div><span class="stat-label">网络接管</span><strong class="stat-value">{{ config?.capture_active ? '已启用' : '未启用' }}</strong><small>在网络代理中管理</small></article>
        </div>

        <div class="lower-grid">
          <article class="panel traffic-panel"><div class="panel-heading"><div><h3>流量</h3><p>实时速率与累计用量</p></div><span class="connection-count">{{ traffic?.active_connections || 0 }} 条连接</span></div><div class="traffic-values"><div><span class="traffic-arrow up">↑</span><small>上传</small><strong>{{ bytes(rates.upload) }}/s</strong></div><div><span class="traffic-arrow down">↓</span><small>下载</small><strong>{{ bytes(rates.download) }}/s</strong></div></div><div class="traffic-foot"><span>累计上传 {{ bytes(traffic?.total_upload_bytes) }} · 累计下载 {{ bytes(traffic?.total_download_bytes) }}</span><strong>{{ traffic?.active_connections || 0 }} 条</strong></div></article>
          <article class="panel system-panel"><div class="panel-heading"><div><h3>设备信息</h3><p>系统只读状态</p></div><span class="device-chip">ARM64</span></div><dl><div><dt>设备</dt><dd>{{ system?.device || 'FriendlyElec NanoPi R5S' }}</dd></div><div><dt>系统</dt><dd>iNextOS {{ system?.inextos_version || '—' }}</dd></div><div><dt>内核</dt><dd>{{ system?.kernel || '—' }}</dd></div><div><dt>项目版本</dt><dd :title="status?.version || null">{{ system?.application_version || '—' }} · Mihomo {{ compactVersionLabel(status?.version) }}</dd></div><div><dt>模式</dt><dd>{{ modeLabels[mode] }}</dd></div><div><dt>Zashboard</dt><dd>{{ system?.dashboard_version || '—' }}</dd></div></dl></article>
        </div>
        <div class="footnote"><span>ⓘ</span>节点、策略组、连接和实时日志请在 Mihomo 控制台中管理。</div>
      </section>

      <section v-else-if="page === 'console'" class="content console-content">
        <div class="page-intro"><h2>Zashboard</h2><p>节点、策略组、连接、规则、实时流量与 Mihomo 日志由 Zashboard 提供。</p></div>
        <iframe v-if="status?.running" class="dashboard-frame" src="/dashboard/" title="Zashboard Mihomo 控制台" allow="clipboard-read; clipboard-write"></iframe>
        <article v-else class="panel console-offline" role="status">
          <div>
            <svg viewBox="0 0 48 48" aria-hidden="true"><rect x="6" y="8" width="36" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="2"/><path d="M6 17h36M16 27l5 5 10-10" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"/></svg>
            <strong>Mihomo 已停止</strong>
            <p>启动 Mihomo 后，Zashboard 才能显示节点、策略组和流量信息。</p>
          </div>
        </article>
      </section>

      <section v-else-if="page === 'network'" class="content">
        <div class="page-intro"><p>TUN、LAN 透明代理、DNS 与网络恢复设置。</p></div>
        <article class="panel">
          <div class="panel-heading">
            <div><h3>流量接管</h3><p>启用后保留 4 分钟自动恢复窗口；确认 SSH、管理页面与网络正常后，再确认网络测试。</p></div>
            <span class="record-status">{{ network?.capture_active ? '接管中' : '已关闭' }}</span>
          </div>
          <div class="network-settings-grid">
            <label class="check-label"><input v-model="networkSettings.tun_enabled" type="checkbox" :disabled="busy || network?.capture_active" />启用 TUN</label>
            <label class="network-field">TUN 栈<select v-model="networkSettings.tun_stack" :disabled="busy || network?.capture_active"><option v-for="item in network?.tun_stacks?.length ? network.tun_stacks : ['system', 'gvisor', 'mixed']" :key="item" :value="item">{{ item }}</option></select></label>
            <label class="check-label"><input v-model="networkSettings.tun_ipv6" type="checkbox" :disabled="busy || network?.capture_active" />TUN IPv6</label>
            <label class="check-label"><input :checked="networkSettings.tun_auto_redirect || networkSettings.lan_proxy.enabled || networkSettings.dns.enabled" type="checkbox" :disabled="busy || network?.capture_active || networkSettings.lan_proxy.enabled || networkSettings.dns.enabled" @change="networkSettings.tun_auto_redirect = $event.target.checked" />Auto Redirect</label>
            <label class="check-label"><input v-model="networkSettings.lan_proxy.enabled" type="checkbox" :disabled="busy || network?.capture_active" />启用 LAN 透明代理</label>
            <label class="network-field">接管范围<select :value="networkSettings.lan_proxy.mode" :disabled="busy || network?.capture_active" @change="changeLANMode($event.target.value)"><option value="all">全部 LAN 设备</option><option value="selected">仅指定设备</option></select></label>
            <label class="check-label"><input v-model="networkSettings.dns.enabled" type="checkbox" :disabled="busy || network?.capture_active" />启用 DNS 接管</label>
            <label class="network-field">DNS 上游<select v-model="networkSettings.dns.mode" :disabled="busy || network?.capture_active"><option value="recommended">推荐上游</option><option value="custom">自定义 IP</option></select></label>
            <label class="check-label"><input v-model="networkSettings.dns.ipv6" type="checkbox" :disabled="busy || network?.capture_active" />DNS 允许 IPv6</label>
          </div>
          <div class="network-settings-notes">
            <p class="network-info-note">TUN：IPv4 启用 · MTU 1500 · Auto Route 启用 · Strict Route 关闭。</p>
            <p v-if="networkSettings.tun_enabled && !networkSettings.dns.enabled" class="network-info-note">TUN 启用时会为路由器本机启用 Mihomo DNS，保持域名解析正常；“DNS 接管”仍单独控制 LAN 客户端。</p>
            <p v-if="networkSettings.lan_proxy.enabled || networkSettings.dns.enabled" class="network-info-note">LAN 或 DNS 接管需要 Auto Redirect，启用期间会自动保持开启。</p>
            <p v-if="!network?.tun_supported" class="network-info-note network-error-note">网络权限服务不可用，当前不能启用接管功能。</p>
            <p v-if="network?.capture_active && !network?.tun_test_confirmed" class="network-note">自动恢复计时运行中。关闭接管后才能修改规则。</p>
            <p v-else-if="network?.helper_status" class="network-info-note">{{ network.helper_status === 'supported' ? '网络权限服务已就绪' : network.helper_status }}</p>
            <small>TUN 栈 {{ networkSettings.tun_stack }} · 路由器管理网段和私有地址默认直连。</small>
          </div>
        </article>

        <article v-if="networkSettings.lan_proxy.enabled" class="panel">
          <div class="panel-heading"><div><h3>LAN 设备</h3><p>客户端名称仅用于识别；地址可从当前邻居列表添加，也可手动填写。</p></div></div>
          <div class="network-client-form">
            <label class="network-field">名称<input v-model="newLANClient.name" maxlength="80" placeholder="例如：客厅电视" :disabled="busy || network?.capture_active" /></label>
            <label class="network-field">IP 地址<input v-model="newLANClient.ip" inputmode="decimal" placeholder="192.168.100.20" :disabled="busy || network?.capture_active" /></label>
            <label class="network-field">MAC 地址<input v-model="newLANClient.mac" placeholder="02:00:00:00:00:01" :disabled="busy || network?.capture_active" /></label>
            <label v-if="networkSettings.lan_proxy.mode === 'all'" class="network-field">处理方式<select v-model="newLANClient.action" :disabled="busy || network?.capture_active"><option value="proxy">代理</option><option value="direct">直连</option></select></label>
            <button class="button subtle" :disabled="busy || network?.capture_active" @click="addLANClient">添加设备</button>
          </div>
          <div v-if="networkSettings.lan_proxy.clients.length" class="network-client-list">
            <div v-for="(client, index) in networkSettings.lan_proxy.clients" :key="client.mac + client.ip" class="network-client-row">
              <strong>{{ client.name || '未命名设备' }}</strong>
              <span>{{ client.ip || '无 IP' }} · {{ client.mac || '无 MAC' }}</span>
              <select v-if="networkSettings.lan_proxy.mode === 'all'" v-model="client.action" :disabled="busy || network?.capture_active"><option value="proxy">代理</option><option value="direct">直连</option></select>
              <span v-else class="record-status">代理</span>
              <button class="text-button danger-text" :disabled="busy || network?.capture_active" @click="removeLANClient(index)">移除</button>
            </div>
          </div>
          <div class="network-inline">
            <strong>发现的 LAN 设备</strong>
            <p v-if="network?.lan_clients_error" class="empty-inline">{{ network.lan_clients_error }}</p>
            <div v-else-if="network?.lan_clients?.length" class="network-client-list">
              <div v-for="client in network.lan_clients" :key="client.interface + client.ip" class="network-client-row">
                <span>{{ client.ip }} · {{ client.mac }} · {{ client.interface }}</span>
                <button class="text-button" :disabled="busy || network?.capture_active" @click="useLANClient(client)">填入设备</button>
              </div>
            </div>
            <p v-else class="empty-inline">暂未发现 LAN 设备；也可以手动添加。</p>
          </div>
        </article>

        <article class="panel">
          <div class="panel-heading"><div><h3>高级路由绕过</h3><p>添加始终直连的 IP 或 CIDR；路由器管理地址、局域网和常见私有网段已自动绕过。</p></div></div>
          <label class="network-field">直连 IP / CIDR<textarea v-model="bypassCIDRText" rows="3" placeholder="每行一个 IP 或 CIDR，例如 192.168.100.0/24" :disabled="busy || network?.capture_active"></textarea></label>
        </article>

        <article v-if="networkSettings.dns.mode === 'custom'" class="panel">
          <div class="panel-heading"><div><h3>自定义 DNS 上游</h3><p>填写 IP 地址；支持路由器或局域网 DNS。</p></div></div>
          <label class="network-field">DNS 服务器<textarea v-model="customDNSText" rows="3" placeholder="例如 192.168.100.1，每行一个" :disabled="busy || network?.capture_active"></textarea></label>
        </article>

        <article class="panel network-actions">
          <button class="button primary" :disabled="busy || network?.capture_active || (networkCaptureRequested && !network?.tun_supported)" @click="saveNetworkSettings">{{ busy ? '保存中…' : '保存网络设置' }}</button>
          <button class="button subtle" :disabled="busy || !network?.capture_active" @click="restoreNetwork">关闭接管并恢复网络</button>
          <button v-if="network?.capture_active && !network?.tun_test_confirmed" class="button primary" :disabled="busy || !network?.desired_running" @click="confirmNetwork">确认网络正常</button>
        </article>
      </section>

      <section v-else-if="page === 'updates'" class="content">
        <div class="page-intro"><h2>更新中心</h2><p>检查官方稳定版发布信息，手动更新 Mihomo。</p></div>
        <article class="panel update-panel">
          <div class="panel-heading"><div><h3>组件版本</h3><p>{{ updateCheck?.checked_at ? `检查于 ${new Date(updateCheck.checked_at).toLocaleString()}` : '尚未检查' }}</p></div><button class="button primary" :disabled="updateCheckBusy" @click="checkUpdates">{{ updateCheckBusy ? '检查中…' : '检查更新' }}</button></div>
          <div v-if="updateCheck?.components?.length" class="table-wrap"><table><thead><tr><th>组件</th><th>当前</th><th>最新稳定版</th><th>发布日期</th><th>状态</th></tr></thead><tbody><tr v-for="item in updateCheck.components" :key="item.id"><td>{{ item.name }}</td><td>{{ item.current || '—' }}</td><td>{{ item.latest || '—' }}</td><td>{{ item.release_date ? new Date(item.release_date).toLocaleDateString() : '—' }}</td><td><span class="record-status">{{ item.update_available === true ? '有更新' : item.update_available === false ? '已是最新' : item.status === 'source_unconfigured' ? '未配置发布源' : item.status === 'release_invalid' ? '发布包无效' : item.status === 'not_in_use' ? '当前未使用' : item.status === 'source_unavailable' ? '发布源暂不可用' : item.status === 'in_use_missing' ? 'Geo 数据缺失' : item.status === 'installed_version_untracked' ? '版本未跟踪' : item.status === 'usage_unknown' ? '使用状态未知' : item.status === 'version_unavailable' ? '无法比较版本' : item.status === 'no_stable_release' ? '没有稳定版' : '未检查' }}</span></td></tr></tbody></table></div>
          <div class="update-actions-grid">
            <div class="row-actions update-action-row"><button class="button primary" :disabled="appUpdateBusy || updateCheckBusy || network?.capture_active || !updateCheck?.components?.some(item => item.id === 'app' && item.update_available === true)" @click="updateApplication">{{ appUpdateBusy ? '更新中…' : '更新应用' }}</button><p v-if="appUpdateStatus?.state !== 'succeeded' && (appUpdateMessage || appUpdateStatus?.message)" role="status">{{ appUpdateMessage || appUpdateStatus?.message }}</p></div>
            <div class="row-actions update-action-row"><button class="button primary" :disabled="mihomoUpdateBusy || updateCheckBusy || !updateCheck?.components?.some(item => item.id === 'mihomo' && item.update_available === true)" @click="updateMihomo">{{ mihomoUpdateBusy ? '更新中…' : '更新 Mihomo' }}</button><p v-if="mihomoUpdateMessage" role="status">{{ mihomoUpdateMessage }}</p></div>
            <div class="row-actions update-action-row"><button class="button primary" :disabled="dashboardUpdateBusy || mihomoUpdateBusy || geoUpdateBusy || updateCheckBusy || !updateCheck?.components?.some(item => item.id === 'zashboard' && item.update_available === true)" @click="updateDashboard()">{{ dashboardUpdateBusy ? '处理中…' : '更新 Zashboard' }}</button><button class="button subtle" :disabled="dashboardUpdateBusy || mihomoUpdateBusy || geoUpdateBusy" @click="updateDashboard(true)">恢复上一版面板</button><p v-if="dashboardUpdateMessage" role="status">{{ dashboardUpdateMessage }}</p></div>
            <div class="row-actions update-action-row"><button class="button primary" :disabled="geoUpdateBusy || mihomoUpdateBusy || dashboardUpdateBusy || updateCheckBusy || !geoUpdateAvailable" @click="updateGeo">{{ geoUpdateBusy ? '更新中…' : '更新 Geo 数据' }}</button><p v-if="geoUpdateMessage" role="status">{{ geoUpdateMessage }}</p></div>
          </div>
          <p class="empty-inline update-note">应用包来自 Clash for iNextOS GitHub 稳定版，下载前会校验 SHA-256 和 ARM64 包版本。安装时保留现有设置并重启管理服务，页面会短暂断开；失败时会自动恢复上一版。更新期间请关闭网络接管。</p>
        </article>
      </section>

      <section v-else-if="page === 'connections'" class="content"><div class="page-intro"><h2>活动连接</h2><p>来自 Mihomo Controller 的当前连接。</p></div><article class="panel"><div class="panel-heading"><h3>{{ connections?.connections?.length || 0 }} 条连接</h3><button class="button subtle" @click="closeAllConnections">关闭全部</button></div><div class="table-wrap"><table><thead><tr><th>来源</th><th>目标</th><th>规则</th><th>代理链</th><th>上传</th><th>下载</th><th></th></tr></thead><tbody><tr v-for="item in connections?.connections || []" :key="item.id"><td>{{ item.metadata?.sourceIP }}:{{ item.metadata?.sourcePort }}</td><td>{{ item.metadata?.host || item.metadata?.destinationIP }}:{{ item.metadata?.destinationPort }}</td><td>{{ item.rule }}</td><td>{{ (item.chains || []).join(' → ') }}</td><td>{{ bytes(item.upload) }}</td><td>{{ bytes(item.download) }}</td><td><button class="text-button danger-text" @click="closeConnection(item.id)">关闭</button></td></tr></tbody></table></div><div v-if="!connections?.connections?.length" class="empty-inline">暂无活动连接</div></article></section>

      <section v-else-if="page === 'subscriptions'" class="content">
        <div class="page-intro"><p>订阅地址保存在设备上。更新通过配置测试后才可切换为当前订阅。</p></div>
        <article class="panel form-panel"><div class="panel-heading"><div><h3>添加订阅</h3><p>仅接受解析到公网地址的 HTTP 或 HTTPS URL</p></div></div><form class="subscription-form" @submit.prevent="addSubscription"><label>名称<input v-model.trim="form.name" maxlength="80" required placeholder="例如：主订阅" /></label><label>订阅地址<input v-model.trim="form.url" type="url" required autocomplete="off" placeholder="https://example.com/…" /></label><label class="check-label"><input v-model="form.enabled" type="checkbox" />启用下载</label><button class="button primary" :disabled="busy">保存订阅</button></form></article>
        <article class="panel subscriptions-panel"><div class="panel-heading"><div><h3>已保存订阅</h3><p>{{ subscriptions.length }} 条记录</p></div><button class="button subtle" @click="loadSubscriptions">刷新</button></div>
          <div v-if="subscriptions.length" class="table-wrap"><table class="subscriptions-table"><thead><tr><th>名称</th><th>订阅地址</th><th>状态</th><th>节点</th><th>用量与到期</th><th>最近更新</th><th>下次更新</th><th>自动更新</th><th>操作</th></tr></thead><tbody><tr v-for="item in subscriptions" :key="item.id"><td class="name-cell">{{ item.name }} <strong v-if="item.current">当前</strong></td><td class="url-cell">{{ item.url }}</td><td><span class="record-status">{{ item.status }}</span></td><td>{{ item.node_count || 0 }}</td><td><small>{{ subscriptionUsageSummary(item.usage) }}</small><small v-if="item.usage?.expire">到期 {{ new Date(item.usage.expire).toLocaleDateString() }}</small><small v-else-if="item.usage">未提供到期时间</small></td><td>{{ item.last_updated ? new Date(item.last_updated).toLocaleString() : '—' }}</td><td>{{ item.next_update ? new Date(item.next_update).toLocaleString() : '—' }}</td><td><select :value="item.auto_update_hours || 0" @change="changeAutoUpdate(item, $event)"><option value="0">关闭</option><option value="6">6 小时</option><option value="12">12 小时</option><option value="24">24 小时</option><option v-if="![0, 6, 12, 24].includes(item.auto_update_hours || 0)" :value="item.auto_update_hours">{{ item.auto_update_hours }} 小时（自定义）</option><option value="custom">自定义…</option></select></td><td><div class="subscription-actions"><button class="text-button" @click="editSubscription(item)">编辑</button><button class="text-button" @click="setSubscriptionSettings(item, !item.enabled, item.auto_update_hours || 0)">{{ item.enabled ? '禁用' : '启用' }}</button><button class="text-button" :disabled="busy || !item.enabled" @click="updateSubscription(item)">更新</button><button class="text-button" :disabled="!item.enabled || !item.node_count || item.current" @click="activateSubscription(item)">设为当前</button><button class="text-button danger-text" @click="deleteSubscription(item)">删除</button></div></td></tr></tbody></table></div>
          <div v-else class="empty-inline">还没有订阅记录</div>
        </article>
      </section>

      <section v-else-if="page === 'logs'" class="content"><div class="page-intro"><h2>运行日志</h2><p>最多显示 1000 行；清空仅影响此页面。</p></div><article class="panel logs-panel"><div class="panel-heading"><div><h3>日志</h3><p>{{ visibleLogs.length }} 行</p></div><div class="row-actions"><select v-model="logSource" @change="loadLogs"><option value="app">App</option><option value="mihomo">Mihomo</option></select><select v-model="logLevel"><option value="all">全部级别</option><option value="info">Info</option><option value="warn">Warning</option><option value="error">Error</option></select><button class="button subtle" @click="logsPaused = !logsPaused">{{ logsPaused ? '继续滚动' : '暂停滚动' }}</button><button class="button subtle" @click="loadLogs">刷新</button><button class="button subtle" @click="clearLogs">清空 UI</button><button class="button subtle" @click="copyLogs">复制</button></div></div><pre v-if="visibleLogs.length" ref="logBox">{{ visibleLogs.join('\n') }}</pre><div v-else class="empty-inline">暂无日志</div></article></section>

      <section v-else-if="page === 'settings'" class="content">
        <div class="page-intro"><p>核心生命周期、管理员账户、界面外观、备份与高级连接信息。</p></div>
        <article class="panel">
          <div class="panel-heading"><div><h3>公网 HTTPS</h3><p>检查当前 WAN IPv6 与 :8844 证书 SAN 是否匹配。</p></div><button class="button subtle" :disabled="busy" @click="loadRemoteAccess">刷新状态</button></div>
          <dl class="remote-access-data"><div><dt>当前公网 IPv6</dt><dd>{{ remoteAccess?.current_public_ipv6 || '未检测到' }}</dd></div><div><dt>证书状态</dt><dd>{{ remoteAccessLabels[remoteAccess?.certificate_status] || '尚未检查' }}</dd></div><div v-if="remoteAccess?.certificate_not_after"><dt>证书到期</dt><dd>{{ new Date(remoteAccess.certificate_not_after).toLocaleString() }}</dd></div></dl>
          <p v-if="remoteAccess?.certificate_status === 'needs_certificate_refresh'" class="empty-inline remote-access-note">需要重新签发与当前公网 IPv6 匹配的证书；此页只检查状态，暂不执行签发。</p>
        </article>
        <article class="panel">
          <div class="panel-heading"><div><h3>诊断与支持</h3><p>诊断检查运行状态；报告会自动排除凭据、订阅 URL、原始配置和私钥。</p></div><div class="row-actions"><button class="button subtle" :disabled="diagnosticBusy" @click="runDiagnostics">{{ diagnosticBusy ? '检查中…' : '运行诊断' }}</button><button class="button primary" :disabled="supportBusy" @click="downloadSupportBundle">{{ supportBusy ? '生成中…' : '下载诊断报告' }}</button></div></div>
          <div v-if="diagnostics" class="diag-grid"><div v-for="(value, key) in diagnostics" :key="key"><span>{{ key }}</span><strong>{{ value }}</strong></div></div>
        </article>
        <article class="panel">
          <div class="panel-heading"><div><h3>核心生命周期</h3><p>启动和异常恢复偏好。</p></div></div>
          <div class="subscription-form lifecycle-form"><label class="check-label"><input v-model="behaviorSettings.auto_start" type="checkbox" />设备启动时恢复 Mihomo</label><label class="check-label"><input v-model="behaviorSettings.restart_on_failure" type="checkbox" />Mihomo 意外退出后自动恢复</label><button class="button primary" @click="saveBehaviorSettings">保存生命周期设置</button></div>
        </article>
        <article class="panel">
          <div class="panel-heading"><div><h3>外观</h3><p>外观偏好保存在此浏览器中。</p></div></div>
          <div class="row-actions appearance-controls"><label>主题<select v-model="appearance" @change="applyAppearance"><option value="system">跟随系统</option><option value="light">浅色</option><option value="dark">深色</option></select></label><label>密度<select v-model="density" @change="applyAppearance"><option value="comfortable">舒适</option><option value="compact">紧凑</option></select></label></div>
        </article>
        <article class="panel form-panel">
          <div class="panel-heading"><div><h3>备份与恢复</h3><p>备份包含应用偏好、LAN 设备名单、DNS 设置、订阅地址与节点配置；文件可能包含订阅令牌和节点凭据。</p></div></div>
          <div class="row-actions backup-controls"><button class="button subtle" :disabled="busy" @click="exportBackup">导出配置</button><label>导入备份<input ref="backupInput" type="file" accept="application/json,.json" :disabled="busy" @change="previewBackup" /></label></div>
          <p class="empty-inline backup-note">管理员密码哈希、Controller secret 和 TLS 私钥不会导出。恢复预览通过后，点击“应用恢复”；应用时要求 Mihomo 已停止，并会保持 TUN、LAN 代理和 DNS 接管关闭。</p>
          <div v-if="backupPreview" class="panel backup-preview system-panel">
            <div class="panel-heading"><div><h4>恢复预览</h4><p>当前订阅将被备份中的 {{ backupPreview.subscription_count }} 条记录替换。</p></div></div>
            <dl><div><dt>当前订阅</dt><dd>{{ backupPreview.current_subscription || '未选择' }}</dd></div><div><dt>节点总数</dt><dd>{{ backupPreview.total_nodes }}</dd></div><div><dt>Mihomo 模式</dt><dd>{{ backupPreview.mode }}</dd></div><div><dt>TUN 栈偏好</dt><dd>{{ backupPreview.tun_stack }}</dd></div><div><dt>设备启动自动恢复</dt><dd>{{ backupPreview.auto_start ? '开启' : '关闭' }}</dd></div><div><dt>异常退出自动恢复</dt><dd>{{ backupPreview.restart_on_failure ? '开启' : '关闭' }}</dd></div><div><dt>浏览器外观</dt><dd>{{ backupPreview.appearance?.theme || '不变' }} · {{ backupPreview.appearance?.density || '不变' }}</dd></div><div><dt>网络状态</dt><dd>Mihomo 停止 · TUN、LAN 代理与 DNS 接管关闭</dd></div></dl>
            <div class="row-actions"><button class="button subtle" :disabled="busy" @click="cancelBackupPreview">取消</button><button class="button primary" :disabled="busy" @click="applyBackup">应用恢复</button></div>
          </div>
        </article>
        <article class="panel form-panel">
          <div class="panel-heading"><div><h3>管理员账户</h3><p>修改用户名或密码时需输入当前密码。SSH 可执行 sudo inextos-clash passwd 重置密码。</p></div></div>
          <form class="subscription-form account-form" @submit.prevent="saveAccount"><label>用户名<input v-model.trim="account.username" pattern="[A-Za-z0-9._-]{3,32}" required /></label><label>当前密码<input v-model="account.current_password" type="password" required /></label><label>新密码<input v-model="account.new_password" type="password" minlength="8" placeholder="不修改可留空" /></label><label>确认新密码<input v-model="account.confirm_password" type="password" /></label><button class="button primary">保存账户</button></form>
        </article>
        <details class="panel advanced-panel"><summary>高级连接信息</summary><dl><div><dt>Backend</dt><dd>127.0.0.1:{{ config?.backend_port ?? '—' }}</dd></div><div><dt>Controller</dt><dd>127.0.0.1:{{ config?.controller_port ?? '—' }}</dd></div><div><dt>Mixed Port</dt><dd>127.0.0.1:{{ config?.mixed_port ?? '—' }}</dd></div><div><dt>Dashboard</dt><dd>/dashboard/</dd></div></dl></details>
      </section>

      <section v-else-if="page === 'about'" class="content about-content"><div class="page-intro"><p>版本、运行环境与开源许可。</p></div><article class="panel system-panel"><dl><div><dt>Clash for iNextOS</dt><dd>{{ system?.application_version }}</dd></div><div><dt>Mihomo</dt><dd>{{ status?.version }}</dd></div><div><dt>Zashboard</dt><dd>{{ system?.dashboard_version }}</dd></div><div><dt>Upstream commit</dt><dd>{{ system?.upstream_revision }}</dd></div><div><dt>iNextOS</dt><dd>{{ system?.inextos_version }}</dd></div><div><dt>Debian</dt><dd>{{ system?.debian_version }}</dd></div><div><dt>Kernel</dt><dd>{{ system?.kernel }}</dd></div><div><dt>Architecture</dt><dd>{{ system?.architecture }}</dd></div><div><dt>Hardware</dt><dd>{{ system?.device }}</dd></div><div><dt>Build</dt><dd>{{ system?.build_date || '—' }}</dd></div></dl></article><article class="panel license-panel"><p><a href="/licenses/THIRD_PARTY_LICENSES.md">第三方许可</a></p></article></section>
    </main>
  </div>
</template>
