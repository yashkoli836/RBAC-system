const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const bodyParser = require('body-parser');
const { check, validationResult } = require('express-validator');
const app = express();

const SECRET_KEY = 'your_secret_key'; // Replace with a strong secret key
const users = []; // In-memory user storage for demonstration

app.use(cors());
app.use(bodyParser.json());

// Serve static files from the 'src' directory
app.use(express.static('src'));

// Middleware to check JWT and roles
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const authorizeRole = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.sendStatus(403);
    next();
};

// Logging Middleware
const logRequest = (req, res, next) => {
    const { method, originalUrl } = req;
    const userRole = req.user ? req.user.role : 'Guest';
    const statusCode = res.statusCode;
    const accessStatus = statusCode === 200 ? 'Successful' : 'Failed';

    console.log(`[${new Date().toISOString()}] ${method} ${originalUrl} - Role: ${userRole} - Status: ${accessStatus}`);
    next();
};

// Apply logging middleware to protected routes
app.use('/user', authenticateJWT, logRequest);
app.use('/admin', authenticateJWT, logRequest);

// Registration Route with Validation and Sanitization
app.post('/register', [
    check('username').isAlphanumeric().withMessage('Username must be alphanumeric').trim().escape(),
    check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    check('role').isIn(['Admin', 'User', 'Guest']).withMessage('Role must be Admin, User, or Guest')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, role } = req.body;

    // Check if user already exists
    const existingUser = users.find(user => user.username === username);
    if (existingUser) {
        return res.status(400).send('User already exists');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user
    users.push({ username, password: hashedPassword, role });

    // Create JWT token
    const token = jwt.sign({ username, role }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ token });
});

// Login Route with Validation and Sanitization
app.post('/login', [
    check('username').isAlphanumeric().withMessage('Username must be alphanumeric').trim().escape(),
    check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    // Find user
    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).send('Invalid credentials');
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).send('Invalid credentials');
    }

    // Create JWT token
    const token = jwt.sign({ username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ token });
});

// Role Update Route
app.post('/update-role', [
    check('adminToken').isString().withMessage('Admin token is required'),
    check('username').isAlphanumeric().withMessage('Username must be alphanumeric').trim().escape(),
    check('role').isIn(['Admin', 'User', 'Guest']).withMessage('Role must be Admin, User, or Guest')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { adminToken, username, role } = req.body;

    // Verify admin token
    try {
        const adminPayload = jwt.verify(adminToken, SECRET_KEY);
        if (adminPayload.role !== 'Admin') {
            return res.status(403).send('Access denied');
        }

        // Find user and update role
        const user = users.find(user => user.username === username);
        if (!user) {
            return res.status(404).send('User not found');
        }

        user.role = role;
        res.send('Role updated successfully');
    } catch (err) {
        res.status(401).send('Invalid admin token');
    }
});

// Public Route
app.get('/public', (req, res) => {
    res.send('Public content');
});

// User Route
app.get('/user', authenticateJWT, authorizeRole(['User', 'Admin']), (req, res) => {
    res.send('User content');
});

// Admin Route
app.get('/admin', authenticateJWT, authorizeRole(['Admin']), (req, res) => {
    res.send('Admin content');
});

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
