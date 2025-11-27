(function () {
    const clientId = 'teste';
    const clientSecret = '123456';
    const storageKey = 'auth-server-session';
    const state = { session: null, principal: null, heartbeat: null };

    const qs = (selector) => document.querySelector(selector);

    const loginCard = qs('#login-card');
    const sessionCard = qs('#session-card');
    const loginForm = qs('#login-form');
    const loginBtn = qs('#login-btn');
    const messageBox = qs('#message');
    const userEl = qs('#current-user');
    const scopesEl = qs('#current-scopes');
    const expiresEl = qs('#expires-at');
    const tokenStatusEl = qs('#token-status');
    const validateBtn = qs('#validate-btn');
    const pingBtn = qs('#ping-btn');
    const logoutBtn = qs('#logout-btn');
    const resultEl = qs('#resource-result');

    const basicHeader = () => 'Basic ' + btoa(`${clientId}:${clientSecret}`);

    function setMessage(text, type = 'info') {
        if (!messageBox) return;
        messageBox.classList.remove('hidden', 'message-info', 'message-error');
        messageBox.textContent = text;
        messageBox.classList.add(type === 'error' ? 'message-error' : 'message-info');
    }

    function clearMessage() {
        if (!messageBox) return;
        messageBox.textContent = '';
        messageBox.classList.add('hidden');
    }

    function showLogin(msg) {
        if (msg) setMessage(msg, 'error'); else clearMessage();
        loginCard.classList.remove('hidden');
        sessionCard.classList.add('hidden');
        if (resultEl) resultEl.textContent = 'Use o botão para testar um endpoint protegido.';
        stopHeartbeat();
    }

    function showSession() {
        loginCard.classList.add('hidden');
        sessionCard.classList.remove('hidden');
        clearMessage();
    }

    function saveSession(tokenResponse) {
        const expiresAt = Date.now() + (tokenResponse.expires_in || 0) * 1000;
        const session = { ...tokenResponse, expiresAt };
        localStorage.setItem(storageKey, JSON.stringify(session));
        state.session = session;
        return session;
    }

    function loadSession() {
        try {
            return JSON.parse(localStorage.getItem(storageKey));
        } catch (e) {
            return null;
        }
    }

    function clearSession() {
        localStorage.removeItem(storageKey);
        state.session = null;
        state.principal = null;
    }

    function formatDate(ts) {
        if (!ts) return '–';
        return new Date(ts).toLocaleString('pt-BR');
    }

    function normalizeScopes(scope) {
        if (Array.isArray(scope)) return scope;
        if (typeof scope === 'string') return scope.split(/\s+/).filter(Boolean);
        return [];
    }

    async function requestToken(params) {
        const body = new URLSearchParams(params);
        const resp = await fetch('oauth/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': basicHeader()
            },
            body
        });

        if (!resp.ok) {
            const errorText = await resp.text();
            throw new Error(errorText || 'Erro ao gerar token');
        }
        const data = await resp.json();
        return saveSession(data);
    }

    async function login(username, password) {
        return requestToken({
            grant_type: 'password',
            username,
            password
        });
    }

    async function refreshToken(refreshToken) {
        return requestToken({
            grant_type: 'refresh_token',
            refresh_token: refreshToken
        });
    }

    async function introspectToken(accessToken) {
        const body = new URLSearchParams();
        body.append('token', accessToken);
        const resp = await fetch('oauth/check_token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': basicHeader()
            },
            body
        });

        if (!resp.ok) {
            throw new Error('Token inválido ou expirado.');
        }
        return resp.json();
    }

    async function ensureValidSession(options = { validate: true }) {
        let session = loadSession();
        if (!session) {
            throw new Error('Sessão expirada.');
        }

        const nearExpiry = session.expiresAt && session.expiresAt - Date.now() < 15000;
        if (nearExpiry && session.refresh_token) {
            session = await refreshToken(session.refresh_token);
        }

        if (session.expiresAt && session.expiresAt <= Date.now()) {
            clearSession();
            throw new Error('Token expirado.');
        }

        state.session = session;
        if (options.validate) {
            state.principal = await introspectToken(session.access_token);
        }
        return { session, principal: state.principal };
    }

    async function apiFetch(path, options = {}) {
        await ensureValidSession({ validate: false });
        const headers = new Headers(options.headers || {});
        headers.set('Authorization', `Bearer ${state.session.access_token}`);
        return fetch(path, { ...options, headers })
            .then(async (resp) => {
                if (resp.status === 401) {
                    clearSession();
                    showLogin('Sessão expirada. Faça login novamente.');
                    throw new Error('Não autorizado');
                }
                return resp;
            });
    }

    function renderSession(principal) {
        const scopes = normalizeScopes(principal?.scope);
        userEl.textContent = principal?.user_name || principal?.username || 'desconhecido';
        scopesEl.textContent = scopes.length ? scopes.join(', ') : '—';
        expiresEl.textContent = formatDate(state.session?.expiresAt);
        tokenStatusEl.textContent = 'válido';
        tokenStatusEl.style.background = 'rgba(52, 211, 153, 0.18)';
        showSession();
    }

    function startHeartbeat() {
        stopHeartbeat();
        state.heartbeat = setInterval(async () => {
            if (!state.session) return;
            const threshold = state.session.expiresAt - Date.now();
            if (threshold < 20000 && state.session.refresh_token) {
                try {
                    await refreshToken(state.session.refresh_token);
                    expiresEl.textContent = formatDate(state.session?.expiresAt);
                } catch (e) {
                    clearSession();
                    showLogin('Não foi possível renovar o token.');
                }
            }
        }, 10000);
    }

    function stopHeartbeat() {
        if (state.heartbeat) {
            clearInterval(state.heartbeat);
            state.heartbeat = null;
        }
    }

    async function handleLogin(evt) {
        evt.preventDefault();
        const formData = new FormData(loginForm);
        const username = formData.get('username');
        const password = formData.get('password');

        loginBtn.disabled = true;
        setMessage('Validando credenciais...');

        try {
            await login(username, password);
            const { principal } = await ensureValidSession();
            renderSession(principal);
            setMessage('Login realizado com sucesso.');
            startHeartbeat();
        } catch (err) {
            clearSession();
            setMessage(err.message || 'Falha no login', 'error');
        } finally {
            loginBtn.disabled = false;
        }
    }

    async function handleValidate(evt) {
        evt.preventDefault();
        try {
            const { principal } = await ensureValidSession();
            renderSession(principal);
            setMessage('Token válido.', 'info');
        } catch (err) {
            clearSession();
            showLogin(err.message || 'Token inválido.');
        }
    }

    async function handlePing(evt) {
        evt.preventDefault();
        resultEl.textContent = 'Chamando /manager/ok ...';
        try {
            const resp = await apiFetch('manager/ok');
            const text = await resp.text();
            resultEl.textContent = text || '(resposta vazia)';
        } catch (err) {
            resultEl.textContent = err.message || 'Erro ao chamar recurso.';
        }
    }

    function handleLogout(evt) {
        if (evt) evt.preventDefault();
        clearSession();
        showLogin('Sessão encerrada.');
    }

    async function bootstrap() {
        if (loginForm) loginForm.addEventListener('submit', handleLogin);
        if (validateBtn) validateBtn.addEventListener('click', handleValidate);
        if (pingBtn) pingBtn.addEventListener('click', handlePing);
        if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

        const existing = loadSession();
        if (!existing) {
            showLogin();
            return;
        }

        try {
            const { principal } = await ensureValidSession();
            renderSession(principal);
            setMessage('Sessão restaurada.', 'info');
            startHeartbeat();
        } catch (err) {
            clearSession();
            showLogin();
        }
    }

    bootstrap();
})();
