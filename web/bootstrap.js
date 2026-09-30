(() => {
  const token = new URLSearchParams(location.hash.slice(1)).get('token');
  history.replaceState(null, '', location.pathname);
  if (!token) return;
  const status = document.getElementById('status');
  status.textContent = 'Connecting to your local session…';
  fetch('/session', {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token })
  }).then(response => {
    if (!response.ok) throw new Error('Session unavailable');
    location.replace('/');
  }).catch(() => {
    status.textContent = 'This link has expired or was already used. Restart envrune ui for a new local session.';
  });
})();
