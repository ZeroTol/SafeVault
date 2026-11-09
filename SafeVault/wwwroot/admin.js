(async () => {
    const out   = document.getElementById('out');
    const token = sessionStorage.getItem('access_token');

    if (!token) { out.innerHTML = '<p>Not logged in. <a href="/login.html">Login</a>.</p>'; return; }

    const res = await fetch('/api/admin/dashboard', {
        headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.status === 401)      out.innerHTML = '<p>Session expired. <a href="/login.html">Login again</a>.</p>';
    else if (res.status === 403) out.innerHTML = '<p><b>403 Forbidden</b> — Admin role required.</p>';
    else if (res.ok)             out.innerHTML = '<pre>' + JSON.stringify(await res.json(), null, 2) + '</pre>';
    else                         out.innerHTML = '<p>Error ' + res.status + '</p>';
})();