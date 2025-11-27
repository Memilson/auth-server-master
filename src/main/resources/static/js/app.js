(function () {
    const config = {
        clientId: 'teste',
        clientSecret: '123456',
        storageKey: 'auth-server-session',
        refreshSkewMs: 20000
    };

    const qs = (selector) => document.querySelector(selector);

    const dom = {
        loginCard: qs('#login-card'),
        sessionCard: qs('#session-card'),
        loginForm: qs('#login-form'),
        loginBtn: qs('#login-btn'),
        messageBox: qs('#message'),
        user: qs('#current-user'),
        scopes: qs('#current-scopes'),
        expires: qs('#expires-at'),
        tokenStatus: qs('#token-status'),
        validateBtn: qs('#validate-btn'),
        pingBtn: qs('#ping-btn'),
        logoutBtn: qs('#logout-btn'),
        result: qs('#resource-result')
    };

    const state = { session: null, principal: null, refreshTimer: null };

    const basicHeader = () => 'Basic ' + btoa(`${config.clientId}:${config.clientSecret}`);

    function setMessage(text, type = 'info') {
        if (!dom.messageBox) return;
        dom.messageBox.classList.remove('hidden', 'message-info', 'message-error');
        dom.messageBox.textContent = text;
        dom.messageBox.classList.add(type === 'error' ? 'message-error' : 'message-info');
    }

    function clearMessage() {
        if (!dom.messageBox) return;
        dom.messageBox.textContent = '';
        dom.messageBox.classList.add('hidden');
    }

    function showLogin(msg) {
        if (msg) {
            setMessage(msg, 'error');
        } else {
            clearMessage();
        }
        dom.loginCard.classList.remove('hidden');
        dom.sessionCard.classList.add('hidden');
        resetResult();
        cancelRefresh();
    }

    function showSession() {
        dom.loginCard.classList.add('hidden');
        dom.sessionCard.classList.remove('hidden');
        clearMessage();
    }

    function resetResult() {
        if (dom.result) {
            dom.result.textContent = 'Use o botão para testar um endpoint protegido.';
        }
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

    function saveSession(tokenResponse) {
        const expiresAt = Date.now() + (tokenResponse.expires_in || 0) * 1000;
        const session = { ...tokenResponse, expiresAt };
        localStorage.setItem(config.storageKey, JSON.stringify(session));
        state.session = session;
        scheduleRefresh();
        return session;
    }

    function loadSession() {
        try {
            const raw = localStorage.getItem(config.storageKey);
            if (!raw) return null;
            const parsed = JSON.parse(raw);
            state.session = parsed;
            return parsed;
        } catch (err) {
            return null;
        }
    }

    function clearSession() {
        localStorage.removeItem(config.storageKey);
        state.session = null;
        state.principal = null;
    }

    function cancelRefresh() {
        if (state.refreshTimer) {
            clearTimeout(state.refreshTimer);
            state.refreshTimer = null;
        }
    }

    function scheduleRefresh() {
        cancelRefresh();
        const session = state.session;
        if (!session?.refresh_token || !session.expiresAt) return;
        const msUntilRefresh = Math.max(0, session.expiresAt - Date.now() - config.refreshSkewMs);
        state.refreshTimer = setTimeout(async () => {
            try {
                await refreshToken();
                dom.expires.textContent = formatDate(state.session?.expiresAt);
                scheduleRefresh();
            } catch (err) {
                logout('Não foi possível renovar o token.');
            }
        }, msUntilRefresh);
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

    function login(username, password) {
        return requestToken({
            grant_type: 'password',
            username,
            password
        });
    }

    function refreshToken() {
        if (!state.session?.refresh_token) {
            throw new Error('Nenhum refresh token disponível.');
        }
        return requestToken({
            grant_type: 'refresh_token',
            refresh_token: state.session.refresh_token
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
        const data = await resp.json();
        if (data && data.error) {
            throw new Error('Token inválido ou expirado.');
        }
        return data;
    }

    async function ensureValidSession(options = { validate: false }) {
        let session = state.session || loadSession();
        if (!session) {
            throw new Error('Sessão expirada.');
        }

        if (session.expiresAt && session.expiresAt <= Date.now()) {
            clearSession();
            throw new Error('Token expirado.');
        }

        const nearExpiry = session.refresh_token && session.expiresAt - Date.now() < config.refreshSkewMs;
        if (nearExpiry) {
            session = await refreshToken();
        } else {
            state.session = session;
            scheduleRefresh();
        }

        if (options.validate) {
            state.principal = await introspectToken(session.access_token);
        }
        return session;
    }

    async function validateAndRender() {
        const session = await ensureValidSession({ validate: true });
        renderSession(state.principal, session);
        return session;
    }

    async function apiFetch(path, options = {}) {
        const session = await ensureValidSession({ validate: false });
        const headers = new Headers(options.headers || {});
        headers.set('Authorization', `Bearer ${session.access_token}`);
        const resp = await fetch(path, { ...options, headers });
        if (resp.status === 401) {
            logout('Sessão expirada. Faça login novamente.');
            throw new Error('Não autorizado');
        }
        return resp;
    }

    function renderSession(principal, session = state.session) {
        const scopes = normalizeScopes(principal?.scope);
        dom.user.textContent = principal?.user_name || principal?.username || 'desconhecido';
        dom.scopes.textContent = scopes.length ? scopes.join(', ') : '—';
        dom.expires.textContent = formatDate(session?.expiresAt);
        dom.tokenStatus.textContent = 'válido';
        dom.tokenStatus.style.background = 'rgba(52, 211, 153, 0.18)';
        showSession();
    }

    async function handleLogin(evt) {
        evt.preventDefault();
        const formData = new FormData(dom.loginForm);
        const username = formData.get('username');
        const password = formData.get('password');

        dom.loginBtn.disabled = true;
        setMessage('Validando credenciais...');

        try {
            await login(username, password);
            await validateAndRender();
            setMessage('Login realizado com sucesso.');
        } catch (err) {
            clearSession();
            showLogin(err.message || 'Falha no login');
        } finally {
            dom.loginBtn.disabled = false;
        }
    }

    async function handleValidate(evt) {
        evt.preventDefault();
        try {
            await validateAndRender();
            setMessage('Token válido.', 'info');
        } catch (err) {
            clearSession();
            showLogin(err.message || 'Token inválido.');
        }
    }

    async function handlePing(evt) {
        evt.preventDefault();
        dom.result.textContent = 'Chamando /manager/ok ...';
        try {
            const resp = await apiFetch('manager/ok');
            const text = await resp.text();
            dom.result.textContent = text || '(resposta vazia)';
        } catch (err) {
            dom.result.textContent = err.message || 'Erro ao chamar recurso.';
        }
    }

    function logout(message) {
        clearSession();
        showLogin(message || 'Sessão encerrada.');
    }

    function handleLogout(evt) {
        if (evt) evt.preventDefault();
        logout();
    }

    async function bootstrap() {
        if (dom.loginForm) dom.loginForm.addEventListener('submit', handleLogin);
        if (dom.validateBtn) dom.validateBtn.addEventListener('click', handleValidate);
        if (dom.pingBtn) dom.pingBtn.addEventListener('click', handlePing);
        if (dom.logoutBtn) dom.logoutBtn.addEventListener('click', handleLogout);

        const existing = loadSession();
        if (!existing) {
            showLogin();
            return;
        }

        try {
            await validateAndRender();
            setMessage('Sessão restaurada.', 'info');
        } catch (err) {
            logout();
        }
    }

    bootstrap();
})();
