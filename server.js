async function loginUser(event) {
    event.preventDefault();

    const username = document.getElementById('neumorphic-username').value;
    const password = document.getElementById('neumorphic-password').value;

    // Verifikasi data yang dimasukkan
    if (!username || !password) {
        alert('Please fill in both fields');
        return;
    }

    const response = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username: username,
            password: password,
        }),
    });

    const data = await response.json();

    if (data.success) {
        localStorage.setItem('token', data.token);  // Simpan token di localStorage
        window.location.href = 'x.html';  // Arahkan ke x.html setelah login berhasil
    } else {
        alert('Login failed: ' + data.message);
    }
}
