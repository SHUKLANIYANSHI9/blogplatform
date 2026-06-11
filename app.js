const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

let users = [];
let posts = [];
let nextUserId = 1;
let nextPostId = 1;
const SECRET = 'mysecret';

// Register
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (users.find(u => u.email === email)) {
        return res.status(400).json({ message: 'User already exists' });
    }
    const hashed = await bcrypt.hash(password, 10);
    const user = { id: nextUserId++, email, password: hashed };
    users.push(user);
    const token = jwt.sign({ userId: user.id }, SECRET);
    res.json({ token, user: { id: user.id, email } });
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ userId: user.id }, SECRET);
    res.json({ token, user: { id: user.id, email } });
});

// Middleware to check token
function auth(req, res, next) {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token' });
    try {
        const decoded = jwt.verify(token, SECRET);
        req.userId = decoded.userId;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
}

// Create post
app.post('/api/posts', auth, (req, res) => {
    const { title, content } = req.body;
    const post = {
        id: nextPostId++,
        title,
        content,
        authorId: req.userId,
        createdAt: new Date()
    };
    posts.push(post);
    res.status(201).json(post);
});

// Get all posts
app.get('/api/posts', (req, res) => {
    res.json(posts);
});

// Get single post
app.get('/api/posts/:id', (req, res) => {
    const post = posts.find(p => p.id === parseInt(req.params.id));
    if (!post) return res.status(404).json({ message: 'Post not found' });
    res.json(post);
});

// Delete post
app.delete('/api/posts/:id', auth, (req, res) => {
    const index = posts.findIndex(p => p.id === parseInt(req.params.id) && p.authorId === req.userId);
    if (index === -1) return res.status(404).json({ message: 'Post not found' });
    posts.splice(index, 1);
    res.json({ message: 'Post deleted' });
});

const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));