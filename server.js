const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const ipRangeCheck = require('ip-range-check');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
app.use(express.json());

// Membatasi jumlah percakapan login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 menit
    max: 5, // Max 5 percakapan login
    message: 'Too many login attempts, please try again later.'
});

// Middleware untuk memverifikasi token JWT
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    
    if (!token) return res.status(403).json({ success: false, message: 'No token provided' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
        req.user = user;
        next();
    });
}

// Rate limiting dan IP Blocking
app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    // Daftar IP yang diizinkan
    const allowedIps = ['192.168.1.1', '123.45.67.89'];
    const userIp = req.ip;

    if (!ipRangeCheck(userIp, allowedIps)) {
        return res.status(403).json({ success: false, message: 'Forbidden IP address' });
    }

    // Mock user data (dari database seharusnya)
    const mockUser = {
        username: 'user',
        passwordHash: '$2a$10$w6hUzOwF9j/CcV6fmpQ/Ty4hQpDkDguM7HJub92WXZrl6uqlCwZNe' // Hash password 'password'
    };

    if (username === mockUser.username) {
        const isMatch = await bcrypt.compare(password, mockUser.passwordHash);
        if (isMatch) {
            // Buat JWT
            const token = jwt.sign({ username: mockUser.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
            return res.json({ success: true, token });
        } else {
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }
    } else {
        return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
});

// Endpoint untuk memverifikasi token
app.post('/verify-token', authenticateToken, (req, res) => {
    res.json({ success: true, message: 'Token is valid' });
});

// Start server
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
