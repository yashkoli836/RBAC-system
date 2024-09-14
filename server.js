const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const bodyParser = require('body-parser');
const { check, validationResult } = require('express-validator');
const app = express();

const SECRET_KEY = 'my_secret_key'; 
const users = []; 

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('src'));

// Middleware to check JWT 
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
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

// Registration Route with Validation 
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

    const existingUser = users.find(user => user.username === username);
    if (existingUser) {
        return res.status(400).send('User already exists');
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({ username, password: hashedPassword, role });

    const token = jwt.sign({ username, role }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ token });
});

// Login Route with Validation 
app.post('/login', [
    check('username').isAlphanumeric().withMessage('Username must be alphanumeric').trim().escape(),
    check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).send('Invalid credentials');
    }

 
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).send('Invalid credentials');
    }

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

    try {
        const adminPayload = jwt.verify(adminToken, SECRET_KEY);
        
        if (adminPayload.role !== 'Admin') {
            return res.status(403).send('Access denied');
        }
        const user = users.find(user => user.username === username);
        if (!user) {
            return res.status(404).send('User not found');
        }

        user.role = role;
        res.send('Role updated successfully');
    } catch (err) {
        return res.status(401).send('Invalid admin token');
    }
});

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401); 

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403); 

        req.user = user;
        next();
    });
};

const authorizeRole = (roles) => {
    return (req, res, next) => {
        if (roles.includes(req.user.role)) {
            next();
        } else {
            res.sendStatus(403); 
        }
    };
};

app.get('/admin', authenticateToken, authorizeRole(['Admin']), (req, res) => {
    res.send('Admin route');
});

app.get('/user', authenticateToken, authorizeRole(['User', 'Admin']), (req, res) => {
    res.send('User route');
});

app.get('/public', (req, res) => {
    res.send('Public route');
});

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
