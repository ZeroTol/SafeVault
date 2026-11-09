(async () => {
    const out   = document.getElementById('out');
    const token = sessionStorage.getItem('access_token');

    // Never use innerHTML with dynamic data: build nodes and set textContent.
    const showMessage = (text, linkText, href) => {
        out.replaceChildren(document.createTextNode(text));
        if (linkText) {
            const a = document.createElement('a');
            a.href = href;
            a.textContent = linkText;
            out.append(' ', a, '.');
        }
    };

    if (!token) { showMessage('Not logged in.', 'Login', '/login.html'); return; }

    const res = await fetch('/api/admin/dashboard', {
        headers: { 'Authorization': 'Bearer ' + token }
    });

    if (res.status === 401)      showMessage('Session expired.', 'Login again', '/login.html');
    else if (res.status === 403) showMessage('403 Forbidden — Admin role required.');
    else if (res.ok)             out.textContent = JSON.stringify(await res.json(), null, 2);
    else                         showMessage('Error ' + res.status);
})();
