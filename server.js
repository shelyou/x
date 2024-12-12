let selectedLanguage = '';
let selectedServer = '';
let selectedOrganization = '';

function selectLanguage(event) {
    event.preventDefault();
    selectedLanguage = document.getElementById('language').value;
    document.getElementById('language-selection').style.display = 'none';
    document.getElementById('server-selection').style.display = 'block';
}

function selectServer(event) {
    event.preventDefault();
    selectedServer = document.getElementById('server').value;
    document.getElementById('server-selection').style.display = 'none';
    document.getElementById('organization-selection').style.display = 'block';
}

function selectOrganization(event) {
    event.preventDefault();
    selectedOrganization = document.getElementById('organization').value;
    document.getElementById('organization-selection').style.display = 'none';
    document.getElementById('login-form').style.display = 'block';
}

async function loginUser(event) {
    event.preventDefault();
    const username = document.getElementById('neumorphic-username').value;
    const password = document.getElementById('neumorphic-password').value;

    // Simulate login API call
    const response = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username,
            password,
            selectedLanguage,
            selectedServer,
            selectedOrganization
        }),
    });

    const result = await response.json();

    if (result.success) {
        alert('Login successful!');
    } else {
        alert('Login failed. Please try again.');
    }
}
