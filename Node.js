const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const bodyParser = require('body-parser');

const users = [
    { username: 'admin', passwordHash: '$2b$10$abcd1234...' }  // Contoh password yang di-hash
];

app.use(bodyParser.json());

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(400).json({ success: false, message: 'User not found' });
    }

    bcrypt.compare(password, user.passwordHash, (err, result) => {
        if (err || !result) {
            return res.status(400).json({ success: false, message: 'Invalid password' });
        }

        const token = jwt.sign({ username: user.username }, 'secretKey', { expiresIn: '1h' });
        res.json({ success: true, token: token });
    });
});

app.listen(3000, () => console.log('Server started on port 3000'));
