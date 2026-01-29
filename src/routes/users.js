const express = require('express');
const router = express.Router();
const pool = require('../db');

// 1. جلب جميع الموظفين (مع اسم العيادة)
router.get('/', async (req, res) => {
  try {
    const query = `
      SELECT users.id, users.name, users.email, users.role, clinics.name as clinic_name 
      FROM users 
      LEFT JOIN clinics ON users.clinic_id = clinics.id
      ORDER BY users.id DESC
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error fetching users' });
  }
});

// 2. إضافة موظف جديد (دكتور، سكرتيرة، إلخ)
router.post('/', async (req, res) => {
  const { name, email, password, role, clinic_id } = req.body;

  try {
    // التحقق من التكرار
    const check = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (check.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const newUser = await pool.query(
      'INSERT INTO users (name, email, password, role, clinic_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, email, password, role, clinic_id]
    );
    res.json(newUser.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error creating user' });
  }
});

module.exports = router;

module.exports = router;
