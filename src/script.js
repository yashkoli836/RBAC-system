const registerUser = async () => {
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
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.errors.map(e => e.msg).join(', '));
        }

        const data = await response.json();
        localStorage.setItem('token', data.token);
        document.getElementById('response').textContent = `Registered successfully. Token: ${data.token}`;
    } catch (error) {
        document.getElementById('response').textContent = `Error: ${error.message}`;
    }
};

const loginUser = async () => {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    try {
        const response = await fetch('http://localhost:3000/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.errors.map(e => e.msg).join(', '));
        }

        const data = await response.json();
        localStorage.setItem('token', data.token);
        document.getElementById('response').textContent = `Logged in successfully. Token: ${data.token}`;
    } catch (error) {
        document.getElementById('response').textContent = `Error: ${error.message}`;
    }
};

const fetchContent = async (route) => {
    const token = localStorage.getItem('token');

    try {
        const response = await fetch(`http://localhost:3000${route}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.status === 401) {
            throw new Error('Unauthorized: Invalid or missing token');
        }
        if (response.status === 403) {
            throw new Error('Forbidden: Insufficient permissions');
        }

        const data = await response.text();
        document.getElementById('response').textContent = data;
    } catch (error) {
        document.getElementById('response').textContent = `Error: ${error.message}`;
    }
};
