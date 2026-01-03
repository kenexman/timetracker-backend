// server.js - Project Tracker Backend API (MySQL Version)
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// Database Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'project_tracker',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test database connection
pool.getConnection()
  .then(connection => {
    console.log('✓ Connected to MySQL database');
    connection.release();
  })
  .catch(err => {
    console.error('❌ Error connecting to MySQL database:', err.message);
  });

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ==================== AUTH ENDPOINTS ====================

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const [users] = await pool.query(
      'SELECT * FROM users WHERE email = ? AND is_active = TRUE',
      [email]
    );
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = users[0];
    
    // For production, verify password:
    // const validPassword = await bcrypt.compare(password, user.password_hash);
    // if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Register (for adding new users)
app.post('/api/auth/register', authenticateToken, async (req, res) => {
  try {
    const { name, email, password, hourly_rate, role } = req.body;
    
    // Only admins can create users
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const password_hash = await bcrypt.hash(password, 10);
    
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password_hash, hourly_rate, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, password_hash, hourly_rate || 0, role || 'agent']
    );
    
    res.json({ id: result.insertId, message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== USER ENDPOINTS ====================

// Get all users
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, name, email, hourly_rate, role, is_active FROM users ORDER BY name'
    );
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user performance
app.get('/api/users/:id/performance', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM user_performance WHERE user_id = ?',
      [req.params.id]
    );
    res.json(rows[0] || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update user
app.patch('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { name, email, hourly_rate, role } = req.body;
    const updates = [];
    const values = [];
    
    if (name) { updates.push('name = ?'); values.push(name); }
    if (email) { updates.push('email = ?'); values.push(email); }
    if (hourly_rate !== undefined) { updates.push('hourly_rate = ?'); values.push(hourly_rate); }
    if (role) { updates.push('role = ?'); values.push(role); }
    
    values.push(req.params.id);
    
    await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
      values
    );
    
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== PROJECT ENDPOINTS ====================

// Get all projects
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const { status, client_id } = req.query;
    
    let query = `
      SELECT p.*, c.name as client_name 
      FROM projects p
      LEFT JOIN clients c ON p.client_id = c.id
      WHERE 1=1
    `;
    const params = [];
    
    if (status) {
      query += ' AND p.status = ?';
      params.push(status);
    }
    
    if (client_id) {
      query += ' AND p.client_id = ?';
      params.push(client_id);
    }
    
    query += ' ORDER BY p.created_at DESC';
    
    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get project P&L
app.get('/api/projects/:id/pnl', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM project_pnl WHERE project_id = ?',
      [req.params.id]
    );
    res.json(rows[0] || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get project details with team
app.get('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    const [projects] = await pool.query(
      `SELECT p.*, c.name as client_name 
       FROM projects p
       LEFT JOIN clients c ON p.client_id = c.id
       WHERE p.id = ?`,
      [req.params.id]
    );
    
    if (projects.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    const [team] = await pool.query(
      `SELECT pa.*, u.name as user_name, u.email
       FROM project_assignments pa
       JOIN users u ON pa.user_id = u.id
       WHERE pa.project_id = ?`,
      [req.params.id]
    );
    
    const project = projects[0];
    project.team = team;
    
    res.json(project);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create project
app.post('/api/projects', authenticateToken, async (req, res) => {
  try {
    const { name, client_id, project_code, billing_type, hourly_rate, fixed_budget, status, color } = req.body;
    
    const [result] = await pool.query(
      `INSERT INTO projects (name, client_id, project_code, billing_type, hourly_rate, fixed_budget, status, color)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, client_id, project_code, billing_type, hourly_rate, fixed_budget, status || 'active', color || '#4CAF50']
    );
    
    res.json({ id: result.insertId, message: 'Project created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update project
app.patch('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    const { name, status, hourly_rate, end_date } = req.body;
    const updates = [];
    const values = [];
    
    if (name) { updates.push('name = ?'); values.push(name); }
    if (status) { updates.push('status = ?'); values.push(status); }
    if (hourly_rate !== undefined) { updates.push('hourly_rate = ?'); values.push(hourly_rate); }
    if (end_date) { updates.push('end_date = ?'); values.push(end_date); }
    
    values.push(req.params.id);
    
    await pool.query(
      `UPDATE projects SET ${updates.join(', ')} WHERE id = ?`,
      values
    );
    
    res.json({ message: 'Project updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== TIME ENTRY ENDPOINTS ====================

// Get time entries
app.get('/api/time-entries', authenticateToken, async (req, res) => {
  try {
    const { user_id, project_id, start_date, end_date, billable } = req.query;
    
    let query = `
      SELECT te.*, u.name as user_name, p.name as project_name
      FROM time_entries te
      JOIN users u ON te.user_id = u.id
      JOIN projects p ON te.project_id = p.id
      WHERE 1=1
    `;
    const params = [];
    
    if (user_id) {
      query += ' AND te.user_id = ?';
      params.push(user_id);
    }
    
    if (project_id) {
      query += ' AND te.project_id = ?';
      params.push(project_id);
    }
    
    if (start_date) {
      query += ' AND te.entry_date >= ?';
      params.push(start_date);
    }
    
    if (end_date) {
      query += ' AND te.entry_date <= ?';
      params.push(end_date);
    }
    
    if (billable !== undefined) {
      query += ' AND te.billable = ?';
      params.push(billable === 'true' ? 1 : 0);
    }
    
    query += ' ORDER BY te.entry_date DESC, te.created_at DESC LIMIT 1000';
    
    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create time entry
app.post('/api/time-entries', authenticateToken, async (req, res) => {
  try {
    const { user_id, project_id, description, hours, entry_date, billable, hourly_rate } = req.body;
    
    const [result] = await pool.query(
      `INSERT INTO time_entries (user_id, project_id, description, hours, entry_date, billable, hourly_rate)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [user_id, project_id, description, hours, entry_date, billable ? 1 : 0, hourly_rate]
    );
    
    res.json({ id: result.insertId, message: 'Time entry created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Bulk import time entries (from desktop tracker)
app.post('/api/time-entries/import', authenticateToken, async (req, res) => {
  try {
    const { entries } = req.body;
    
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      let imported = 0;
      const errors = [];
      
      for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        try {
          await connection.query(
            `INSERT INTO time_entries (user_id, project_id, description, hours, entry_date, billable, hourly_rate, source)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'desktop_tracker')`,
            [entry.user_id, entry.project_id, entry.description, entry.hours, entry.entry_date, entry.billable ? 1 : 0, entry.hourly_rate]
          );
          imported++;
        } catch (err) {
          errors.push({ index: i, error: err.message });
        }
      }
      
      await connection.commit();
      res.json({ imported, errors });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== INVOICE ENDPOINTS ====================

// Get all invoices
app.get('/api/invoices', authenticateToken, async (req, res) => {
  try {
    const { client_id, status } = req.query;
    
    let query = `
      SELECT i.*, c.name as client_name, p.name as project_name
      FROM invoices i
      JOIN clients c ON i.client_id = c.id
      LEFT JOIN projects p ON i.project_id = p.id
      WHERE 1=1
    `;
    const params = [];
    
    if (client_id) {
      query += ' AND i.client_id = ?';
      params.push(client_id);
    }
    
    if (status) {
      query += ' AND i.status = ?';
      params.push(status);
    }
    
    query += ' ORDER BY i.issue_date DESC';
    
    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create invoice from time entries
app.post('/api/invoices/from-time', authenticateToken, async (req, res) => {
  try {
    const { client_id, project_id, start_date, end_date, tax_rate } = req.body;
    
    // Get unbilled time entries
    const [entries] = await pool.query(
      `SELECT te.*, u.name as user_name
       FROM time_entries te
       JOIN users u ON te.user_id = u.id
       WHERE te.project_id = ?
       AND te.entry_date BETWEEN ? AND ?
       AND te.billable = TRUE
       AND te.billed = FALSE`,
      [project_id, start_date, end_date]
    );
    
    if (entries.length === 0) {
      return res.status(400).json({ error: 'No unbilled entries found' });
    }
    
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Calculate totals
      const subtotal = entries.reduce((sum, entry) => sum + (entry.hours * entry.hourly_rate), 0);
      const tax_amount = subtotal * (tax_rate / 100);
      const total = subtotal + tax_amount;
      
      // Generate invoice number
      const invoice_number = 'INV-' + Date.now();
      
      // Create invoice
      const [invoiceResult] = await connection.query(
        `INSERT INTO invoices (invoice_number, client_id, project_id, subtotal, tax_rate, tax_amount, total, issue_date, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, CURDATE(), 'draft')`,
        [invoice_number, client_id, project_id, subtotal, tax_rate, tax_amount, total]
      );
      
      const invoice_id = invoiceResult.insertId;
      
      // Group entries by user/description for line items
      const lineItems = {};
      entries.forEach(entry => {
        const key = `${entry.user_name} - ${entry.description || 'Time worked'}`;
        if (!lineItems[key]) {
          lineItems[key] = { hours: 0, rate: entry.hourly_rate };
        }
        lineItems[key].hours += parseFloat(entry.hours);
      });
      
      // Insert line items
      for (const description in lineItems) {
        const item = lineItems[description];
        const amount = item.hours * item.rate;
        await connection.query(
          `INSERT INTO invoice_items (invoice_id, description, quantity, rate, amount)
           VALUES (?, ?, ?, ?, ?)`,
          [invoice_id, description, item.hours, item.rate, amount]
        );
      }
      
      // Mark time entries as billed
      const entry_ids = entries.map(e => e.id);
      await connection.query(
        `UPDATE time_entries SET billed = TRUE, invoice_id = ? WHERE id IN (?)`,
        [invoice_id, entry_ids]
      );
      
      await connection.commit();
      res.json({ id: invoice_id, invoice_number, message: 'Invoice created successfully' });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update invoice status
app.patch('/api/invoices/:id/status', authenticateToken, async (req, res) => {
  try {
    const { status, paid_date, amount_paid } = req.body;
    
    let query = 'UPDATE invoices SET status = ?';
    const params = [status];
    
    if (status === 'paid' && paid_date) {
      query += ', paid_date = ?, amount_paid = ?';
      params.push(paid_date, amount_paid);
    }
    
    query += ' WHERE id = ?';
    params.push(req.params.id);
    
    await pool.query(query, params);
    res.json({ message: 'Invoice updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== CLIENT ENDPOINTS ====================

// Get all clients
app.get('/api/clients', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM clients WHERE is_active = TRUE ORDER BY name'
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create client
app.post('/api/clients', authenticateToken, async (req, res) => {
  try {
    const { name, company, email, phone, billing_rate } = req.body;
    
    const [result] = await pool.query(
      'INSERT INTO clients (name, company, email, phone, billing_rate) VALUES (?, ?, ?, ?, ?)',
      [name, company, email, phone, billing_rate]
    );
    
    res.json({ id: result.insertId, message: 'Client created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get client revenue summary
app.get('/api/clients/:id/revenue', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM client_revenue WHERE client_id = ?',
      [req.params.id]
    );
    res.json(rows[0] || {});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== DASHBOARD/REPORTING ENDPOINTS ====================

// Overall P&L Dashboard
app.get('/api/dashboard/pnl', authenticateToken, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    const [rows] = await pool.query(
      `SELECT 
        SUM(CASE WHEN te.billable = TRUE THEN te.hours * te.hourly_rate ELSE 0 END) as total_revenue,
        SUM(te.hours * u.hourly_rate) as total_labor_cost,
        COALESCE(SUM(e.amount), 0) as total_expenses,
        SUM(te.hours * u.hourly_rate) + COALESCE(SUM(e.amount), 0) as total_cost,
        SUM(te.hours) as total_hours,
        SUM(CASE WHEN te.billable = TRUE THEN te.hours ELSE 0 END) as billable_hours
      FROM time_entries te
      JOIN users u ON te.user_id = u.id
      LEFT JOIN expenses e ON te.project_id = e.project_id
      WHERE te.entry_date BETWEEN ? AND ?`,
      [start_date || '2000-01-01', end_date || '2099-12-31']
    );
    
    const data = rows[0];
    const profit = (data.total_revenue || 0) - (data.total_cost || 0);
    const profit_margin = data.total_revenue > 0 ? (profit / data.total_revenue) * 100 : 0;
    const utilization_rate = data.total_hours > 0 ? (data.billable_hours / data.total_hours) * 100 : 0;
    
    res.json({
      ...data,
      profit,
      profit_margin,
      utilization_rate
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Project summary for dashboard
app.get('/api/dashboard/projects', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM project_pnl ORDER BY profit DESC LIMIT 10'
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Team utilization
app.get('/api/dashboard/team', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM user_performance ORDER BY utilization_rate DESC'
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start Server
app.listen(PORT, () => {
  console.log(`✓ Server running on http://localhost:${PORT}`);
  console.log(`✓ API endpoints available at http://localhost:${PORT}/api`);
  console.log(`✓ Database: ${process.env.DB_NAME || 'project_tracker'}`);
});

module.exports = app;
