document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await fetch('/api/account/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
        })
    });
    if (res.ok) {
        const d = await res.json();
        sessionStorage.setItem('access_token', d.accessToken);
        sessionStorage.setItem('role', d.role);
        window.location.href = '/admin.html';
    } else {
        document.getElementById('error').textContent = 'Invalid username or password.';
    }
});