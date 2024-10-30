// backend/src/app.js
import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { pool } from './db.js';

dotenv.config();

const app = express();
app.use(express.json());

const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Middleware d'authentification
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.userId = decoded.userId;
    next();
  });
};

// Route d'inscription
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id',
      [name, email, hashedPassword]
    );
    res.json({ userId: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ message: 'Error registering user' });
  }
});

// Route de connexion
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = generateToken(user.id);
      res.json({ token });
    } else {
      res.status(400).json({ message: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Routes d'événements
app.get('/events', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM events');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching events' });
  }
});

app.post('/events', authenticateToken, async (req, res) => {
  const { title, description } = req.body;
  try {
    await pool.query('INSERT INTO events (title, description) VALUES ($1, $2)', [
      title,
      description,
    ]);
    res.status(201).json({ message: 'Event created' });
  } catch (err) {
    res.status(500).json({ message: 'Error creating event' });
  }
});

app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));
