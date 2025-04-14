const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const app = express();
app.use(express.json());

const SECRET = process.env.JWT_SECRET || 'my_secret';
const users = [];

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    req.user = user;

    next();
  });
}

function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) return res.sendStatus(403);

    next();
  };
}

app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({ username, password: hashedPassword, role: role || 'user' });

  res.json({ message: 'User registered' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user) return res.status(400).json({ message: 'User not found' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(403).json({ message: 'Invalid password' });

  const token = jwt.sign({ username: user.username, role: user.role }, SECRET);

  res.json({ token });
});

app.get('/dashboard', authenticateToken, (req, res) => {
  res.send(`Hello ${req.user.username}, welcome to your dashboard!`);
});

app.get('/admin', authenticateToken, authorizeRole('admin'), (req, res) => {
  res.send('Welcome to the admin panel.');
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
