// Myki Extension Popup - communicates with native host via background script

let vaultUnlocked = false;
let credentials = [];
const CLIPBOARD_CLEAR_MS = 30000;

document.addEventListener('DOMContentLoaded', () => {
    const unlockView = document.getElementById('unlock-view');
    const vaultView = document.getElementById('vault-view');
    const masterPasswordInput = document.getElementById('master-password');
    const unlockBtn = document.getElementById('unlock-btn');
    const lockBtn = document.getElementById('lock-btn');
    const credentialList = document.getElementById('credential-list');
    const searchInput = document.getElementById('search');
    const statusEl = document.getElementById('native-status');

    function nativeCall(payload) {
        return new Promise((resolve, reject) => {
            chrome.runtime.sendMessage({ type: 'native_call', payload }, (response) => {
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                    return;
                }
                if (response.success) resolve(response.data);
                else reject(new Error(response.error));
            });
        });
    }

    async function checkNativeConnection() {
        try {
            const data = await nativeCall({ command: 'ping' });
            statusEl.textContent = 'Connected';
            statusEl.style.color = '#22C55E';
            return true;
        } catch (e) {
            statusEl.textContent = 'Desktop app not running';
            statusEl.style.color = '#EF4444';
            return false;
        }
    }

    async function unlockVault(password) {
        const result = await nativeCall({ command: 'unlock', password });
        return result.status === 'unlocked';
    }

    async function loadCredentials() {
        try {
            credentials = await nativeCall({ command: 'list' });
            return true;
        } catch (e) {
            return false;
        }
    }

    function renderCredentials(filter) {
        credentialList.innerHTML = '';
        const q = (filter || '').toLowerCase();
        const filtered = credentials.filter(c =>
            c.title.toLowerCase().includes(q) ||
            c.username.toLowerCase().includes(q)
        );
        if (filtered.length === 0) {
            credentialList.innerHTML = '<li class="credential-item empty">No credentials found</li>';
            return;
        }
        filtered.forEach(c => {
            const li = document.createElement('li');
            li.className = 'credential-item';
            li.innerHTML = `
                <div class="item-info">
                    <strong>${escapeHtml(c.title)}</strong>
                    <span>${escapeHtml(c.username)}</span>
                </div>
            `;
            li.addEventListener('click', async () => {
                try {
                    const result = await nativeCall({ command: 'get_password', id: c.id });
                    await navigator.clipboard.writeText(result.password);
                    showToast(`Password for ${c.title} copied`);
                    setTimeout(() => navigator.clipboard.writeText(''), CLIPBOARD_CLEAR_MS);
                } catch (e) {
                    showToast('Failed to copy password');
                }
            });
            credentialList.appendChild(li);
        });
    }

    function showToast(msg) {
        const el = document.createElement('div');
        el.style.cssText = 'position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:#059669;color:white;padding:8px 16px;border-radius:8px;font-size:13px;z-index:100';
        el.textContent = msg;
        document.body.appendChild(el);
        setTimeout(() => el.remove(), 2000);
    }

    function escapeHtml(text) {
        const d = document.createElement('div');
        d.textContent = text;
        return d.innerHTML;
    }

    // Check native connection on load
    checkNativeConnection();

    unlockBtn.addEventListener('click', async () => {
        const pwd = masterPasswordInput.value;
        if (!pwd) { showToast('Enter your master password'); return; }
        unlockBtn.disabled = true;
        unlockBtn.textContent = 'Unlocking...';

        try {
            const ok = await unlockVault(pwd);
            if (ok) {
                vaultUnlocked = true;
                await loadCredentials();
                unlockView.classList.add('hidden');
                vaultView.classList.remove('hidden');
                renderCredentials();
            } else {
                showToast('Invalid password');
            }
        } catch (e) {
            showToast('Failed: ' + e.message);
        }
        unlockBtn.disabled = false;
        unlockBtn.textContent = 'Unlock';
    });

    lockBtn.addEventListener('click', async () => {
        try { await nativeCall({ command: 'lock' }); } catch (_) {}
        vaultUnlocked = false;
        credentials = [];
        vaultView.classList.add('hidden');
        unlockView.classList.remove('hidden');
        masterPasswordInput.value = '';
    });

    let searchTimer = null;
    searchInput.addEventListener('input', (e) => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => renderCredentials(e.target.value), 300);
    });

    masterPasswordInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') unlockBtn.click();
    });
});
