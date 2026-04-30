// Popup logic for Myki Extension

document.addEventListener('DOMContentLoaded', () => {
  const unlockBtn = document.getElementById('unlock-btn');
  const lockBtn = document.getElementById('lock-btn');
  const unlockView = document.getElementById('unlock-view');
  const vaultView = document.getElementById('vault-view');
  const masterPasswordInput = document.getElementById('master-password');
  const credentialList = document.getElementById('credential-list');
  const searchInput = document.getElementById('search');

  // Sample data to simulate a decrypted vault
  const sampleCredentials = [
    { id: '1', title: 'GitHub', username: 'dev_user', url: 'github.com' },
    { id: '2', title: 'Google', username: 'user@gmail.com', url: 'google.com' },
    { id: '3', title: 'Twitter', username: '@myki_fan', url: 'twitter.com' },
    { id: '4', title: 'LinkedIn', username: 'professional_dev', url: 'linkedin.com' }
  ];

  function renderCredentials(filter = '') {
    credentialList.innerHTML = '';
    const filtered = sampleCredentials.filter(c => 
      c.title.toLowerCase().includes(filter.toLowerCase()) ||
      c.username.toLowerCase().includes(filter.toLowerCase())
    );

    filtered.forEach(c => {
      const li = document.createElement('li');
      li.className = 'credential-item';
      li.innerHTML = `
        <div class="item-info">
          <strong>${c.title}</strong>
          <span>${c.username}</span>
        </div>
      `;
      li.addEventListener('click', () => {
        // Simulate copying password
        console.log('Copying password for:', c.title);
        alert(`Password for ${c.title} copied to clipboard (simulated)`);
      });
      credentialList.appendChild(li);
    });
  }

  // Handle Unlock
  unlockBtn.addEventListener('click', () => {
    const password = masterPasswordInput.value;
    if (password === 'password') { // Simple simulation
      unlockView.classList.add('hidden');
      vaultView.classList.remove('hidden');
      renderCredentials();
    } else {
      alert('Invalid Master Password! (Try "password")');
    }
  });

  // Handle Search
  searchInput.addEventListener('input', (e) => {
    renderCredentials(e.target.value);
  });

  // Handle Lock
  lockBtn.addEventListener('click', () => {
    unlockView.classList.remove('hidden');
    vaultView.classList.add('hidden');
    masterPasswordInput.value = '';
    searchInput.value = '';
  });
});
