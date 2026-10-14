/**
 * Google 登入 + Apps Script JSON API。
 *
 * - auth：用 Google Identity Services 取得 ID token（存在 localStorage，到期前自動續用）。
 * - api.run：與 google.script.run 相同的寫法
 *   （withSuccessHandler / withFailureHandler / 呼叫伺服器函式），改走 fetch。
 * - dashboardCache：記住上次的首頁資料，讓頁面打開時能立刻顯示。
 */
(function () {
  const CONFIG = window.APP_CONFIG;
  const KEY_PREFIX = 'ts_';
  const TOKEN_KEY = KEY_PREFIX + 'idToken';
  const EMAIL_KEY = KEY_PREFIX + 'lastEmail';
  const DASH_PREFIX = KEY_PREFIX + 'dash_';
  const LOGIN_DELAY_MS = 1200; // 給自動登入一點時間，避免登入框一閃而過

  /* ---------- storage（私密視窗等情況可能丟錯，一律包起來） ---------- */
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } },
    clearAll() {
      try {
        Object.keys(localStorage).filter(k => k.startsWith(KEY_PREFIX)).forEach(k => localStorage.removeItem(k));
      } catch (e) { /* ignore */ }
    }
  };

  /* ---------- auth ---------- */
  function decodeJwt(token) {
    try {
      const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      const bytes = Uint8Array.from(atob(part), c => c.charCodeAt(0));
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch (e) {
      return null;
    }
  }

  function isFresh(token) {
    const p = token && decodeJwt(token);
    return Boolean(p && p.exp * 1000 > Date.now() + 60 * 1000);
  }

  let token = store.get(TOKEN_KEY);
  if (!isFresh(token)) token = null;
  let waiters = [];
  let gisInitialized = false;
  let loginTimer = null;

  function onCredential(response) {
    const p = decodeJwt(response.credential);
    if (!p) return;
    token = response.credential;
    store.set(TOKEN_KEY, token);
    store.set(EMAIL_KEY, String(p.email || '').toLowerCase());
    hideLogin();
    const pending = waiters;
    waiters = [];
    pending.forEach(resolve => resolve(token));
  }

  function whenGisReady(fn) {
    if (window.google && google.accounts && google.accounts.id) {
      if (!gisInitialized) {
        google.accounts.id.initialize({
          client_id: CONFIG.clientId,
          callback: onCredential,
          auto_select: true,
          hd: CONFIG.domain,
          login_hint: store.get(EMAIL_KEY) || undefined,
          cancel_on_tap_outside: false,
          use_fedcm_for_prompt: true
        });
        gisInitialized = true;
      }
      fn();
    } else {
      setTimeout(() => whenGisReady(fn), 100);
    }
  }

  function requestSignIn(message) {
    whenGisReady(() => {
      google.accounts.id.prompt();
      renderLoginButton();
    });
    clearTimeout(loginTimer);
    if (message) showLogin(message);
    else loginTimer = setTimeout(() => showLogin(''), LOGIN_DELAY_MS);
  }

  function getToken() {
    if (isFresh(token)) return Promise.resolve(token);
    token = null;
    return new Promise(resolve => {
      waiters.push(resolve);
      if (waiters.length === 1) requestSignIn('');
    });
  }

  function invalidateToken() {
    token = null;
    try { localStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ }
  }

  /* ---------- 登入畫面 ---------- */
  function renderLoginButton() {
    const holder = document.getElementById('googleSignInButton');
    if (!holder || holder.dataset.rendered) return;
    google.accounts.id.renderButton(holder, { theme: 'filled_blue', size: 'large', text: 'signin_with', locale: 'zh-TW' });
    holder.dataset.rendered = '1';
  }

  function showLogin(message) {
    const box = document.getElementById('loginOverlay');
    if (!box) return;
    document.getElementById('loginMessage').textContent = message || '';
    document.getElementById('loginMessage').style.display = message ? 'block' : 'none';
    box.classList.add('show');
  }

  function hideLogin() {
    clearTimeout(loginTimer);
    const box = document.getElementById('loginOverlay');
    if (box) box.classList.remove('show');
  }

  function logout() {
    if (window.google && google.accounts && google.accounts.id) google.accounts.id.disableAutoSelect();
    store.clearAll();
    location.reload();
  }

  /* ---------- API ---------- */
  const MIME_BY_EXT = { pdf: 'application/pdf', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png' };

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).split(',')[1] || '');
      reader.onerror = () => reject(new Error('無法讀取檔案。'));
      reader.readAsDataURL(file);
    });
  }

  async function serializeArg(arg) {
    if (!(arg instanceof HTMLFormElement)) return arg;
    const out = {};
    for (const [key, value] of new FormData(arg).entries()) {
      if (value instanceof File) {
        const ext = (value.name.split('.').pop() || '').toLowerCase();
        out.file = { name: value.name, mimeType: value.type || MIME_BY_EXT[ext] || '', base64: await fileToBase64(value) };
      } else {
        out[key] = value;
      }
    }
    return out;
  }

  async function post(action, args) {
    const idToken = await getToken();
    let res;
    try {
      res = await fetch(CONFIG.apiUrl, {
        method: 'POST',
        // text/plain 是「簡單請求」，不會觸發 CORS 預檢（Apps Script 不支援 OPTIONS）。
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
        body: JSON.stringify({ action, idToken, args })
      });
    } catch (e) {
      throw new Error('網路連線失敗，請稍後再試。');
    }
    let data;
    try {
      data = await res.json();
    } catch (e) {
      throw new Error('伺服器回應格式不正確（HTTP ' + res.status + '）。');
    }
    return data;
  }

  async function call(action, rawArgs) {
    const args = await Promise.all(rawArgs.map(serializeArg));
    let data = await post(action, args);
    if (!data.ok && data.code === 'AUTH') {
      // token 失效或帳號不對：清掉後請使用者重新登入，再重試一次。
      invalidateToken();
      const retry = new Promise(resolve => waiters.push(resolve));
      requestSignIn(data.error);
      await retry;
      data = await post(action, args);
      if (!data.ok && data.code === 'AUTH') {
        invalidateToken();
        showLogin(data.error);
      }
    }
    if (!data.ok) throw new Error(data.error || '發生未知錯誤');
    return data.result;
  }

  function makeRunner(onSuccess, onFailure) {
    return new Proxy({}, {
      get(_, name) {
        if (name === 'withSuccessHandler') return fn => makeRunner(fn, onFailure);
        if (name === 'withFailureHandler') return fn => makeRunner(onSuccess, fn);
        return (...args) => {
          call(String(name), args).then(
            result => { if (onSuccess) onSuccess(result); },
            error => { if (onFailure) onFailure(error); else console.error(error); }
          );
        };
      }
    });
  }

  /* ---------- 首頁快取 ---------- */
  const dashboardCache = {
    read() {
      const email = store.get(EMAIL_KEY);
      if (!email) return null;
      try { return JSON.parse(store.get(DASH_PREFIX + email) || 'null'); } catch (e) { return null; }
    },
    save(data) {
      if (!data || !data.success || !data.user || !data.user.email) return;
      const copy = Object.assign({}, data);
      delete copy._diagnostics;
      store.set(DASH_PREFIX + String(data.user.email).toLowerCase(), JSON.stringify(copy));
    }
  };

  window.auth = { logout, getToken };
  window.api = { get run() { return makeRunner(null, null); } };
  window.dashboardCache = dashboardCache;
})();
