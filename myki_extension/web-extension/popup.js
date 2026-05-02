// Popup logic for Myki Extension

document.addEventListener('DOMContentLoaded', () => {
  const unlockBtn = document.getElementById('unlock-btn');
  const lockBtn = document.getElementById('lock-btn');
  const unlockView = document.getElementById('unlock-view');
  const vaultView = document.getElementById('vault-view');
  const masterPasswordInput = document.getElementById('master-password');
  const credentialList = document.getElementById('credential-list');
  const searchInput = document.getElementById('search');

  // Track vault lock state
  let vaultUnlocked = false;
  let credentials = [];

  // Load credentials from storage or empty array
  async function loadCredentials() {
    try {
      const result = await chrome.storage.local.get('credentials');
      credentials = result.credentials || [];
    } catch (error) {
      console.error('Failed to load credentials:', error);
      credentials = [];
    }
  }

  function renderCredentials(filter = '') {
    credentialList.innerHTML = '';

    if (!vaultUnlocked) {
      credentialList.innerHTML = '<li class="credential-item locked">Vault is locked</li>';
      return;
    }

    const filtered = credentials.filter(c =>
      c.title.toLowerCase().includes(filter.toLowerCase()) ||
      c.username.toLowerCase().includes(filter.toLowerCase())
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
      li.addEventListener('click', () => {
        // Copy password to clipboard
        if (c.password) {
          navigator.clipboard.writeText(c.password).then(() => {
            alert(`Password for ${c.title} copied to clipboard`);
          }).catch(err => {
            console.error('Failed to copy:', err);
          });
        }
      });
      credentialList.appendChild(li);
    });
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // Handle Unlock
  unlockBtn.addEventListener('click', async () => {
    const password = masterPasswordInput.value;

    if (!password) {
      alert('Please enter your master password');
      return;
    }

    // Attempt to validate master password via Tauri command
    try {
      // Check with backend - this would call the actual vault unlock
      // For now, we'll require actual authentication
      const isValid = await validateMasterPassword(password);

      if (isValid) {
        vaultUnlocked = true;
        await loadCredentials();
        unlockView.classList.add('hidden');
        vaultView.classList.remove('hidden');
        renderCredentials();
      } else {
        alert('Invalid Master Password');
      }
    } catch (error) {
      console.error('Unlock error:', error);
      alert('Failed to unlock vault. Please try again.');
    }
  });

  async function validateMasterPassword(password) {
    // This would communicate with the Tauri backend
    // For now, return false to require proper authentication
    // The actual implementation would call unlock_vault command
    return false;
  }

  // Handle Search
  searchInput.addEventListener('input', (e) => {
    renderCredentials(e.target.value);
  });

  // Handle Lock
  lockBtn.addEventListener('click', () => {
    vaultUnlocked = false;
    credentials = [];
    unlockView.classList.remove('hidden');
    vaultView.classList.add('hidden');
    masterPasswordInput.value = '';
    searchInput.value = '';
  });
});
