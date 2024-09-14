const handleResponse = (response, text) => {
    if (!response.ok) {
        throw new (text || 'Request failed');
    }
    return response.text();
};

const fetchWithToken = async (url, options = {}) => {
    const token = localStorage.getItem('token');
    
    if (!token) throw new Error('No token found');

    const response = await fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    });

    return response;
};

const register = async () => {
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    const role = document.getElementById('register-role').value;

    try {
        const response = await fetch('http://localhost:3000/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password, role })
        });

        const result = await handleResponse(response, 'Registration successful.');
        document.getElementById('response').textContent = `Registered successfully. Token: ${result}`;
    } catch (error) {
        document.getElementById('response').textContent = `Error: ${error.message}`;
    }
};

const login = async () => {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    try {
        const response = await fetchWithToken('http://localhost:3000/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        const result = await response.json();
        localStorage.setItem('token', result.token);
        document.getElementById('response').textContent = `Logged in successfully. Token: ${result.token}`;
    } catch (error) {
        document.getElementById('response').textContent = `Error: ${error.message}`;
    }
};

const updateRole = async () => {
    const adminToken = document.getElementById('admin-token').value;
    const username = document.getElementById('update-username').value;
    const role = document.getElementById('update-role').value;

    try {
        const response = await fetch('http://localhost:3000/update-role', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ adminToken, username, role })
        });

        const message = await handleResponse(response, 'Role update successful.');
        document.getElementById('response').textContent = message;
    } catch (error) {
        document.getElementById('response').textContent = `Error: ${error.message}`;
    }
};
