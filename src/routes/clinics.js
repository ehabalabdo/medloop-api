const express = require('express');
const router = express.Router();
const pool = require('../db');

// 1. جلب العيادات
router.get('/', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clinics ORDER BY id ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 2. إضافة عيادة جديدة
router.post('/', async (req, res) => {
  const { name, type, phone } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO clinics (name, type, phone) VALUES ($1, $2, $3) RETURNING *',
      [name, type, phone]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error adding clinic' });
  }
});

module.exports = router;
