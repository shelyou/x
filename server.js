const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Dummy credentials
const DUMMY_USER = {
    email: '1@onion',
    password: '1',
};

// Login endpoint
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (email === DUMMY_USER.email && password === DUMMY_USER.password) {
        res.json({
            success: true,
            token: 'example-token', // Replace with real token generation
        });
    } else {
        res.json({
            success: false,
            message: 'Invalid email or password.',
        });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
