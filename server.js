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
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, Postman, curl)
    if (!origin) return callback(null, true);
    
    // Allow coefficient.fun and all its subdomains
    if (origin.includes('coefficient.fun') || 
        origin.includes('localhost') || 
        origin.includes('127.0.0.1')) {
      callback(null, true);
    } else {
      callback(null, true); // Allow all for now - can restrict later
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Content-Length', 'X-Request-Id']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Handle preflight for all routes
app.use(express.json({ limit: '50mb' })); // Increase limit for bulk imports
app.use(express.urlencoded({ limit: '50mb', extended: true }));

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
        role: user.role,
        hourly_rate: parseFloat(user.hourly_rate || 0)
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
  console.log('📥 Import request received');
  console.log('User:', req.user);
  console.log('Entries count:', req.body.entries?.length || 0);
  
  try {
    const { entries } = req.body;
    
    if (!entries || !Array.isArray(entries)) {
      console.log('❌ Invalid entries format');
      return res.status(400).json({ error: 'Invalid entries format' });
    }
    
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
          console.log(`❌ Error importing entry ${i}:`, err.message);
          errors.push({ index: i, error: err.message });
        }
      }
      
      await connection.commit();
      console.log(`✓ Imported ${imported} entries, ${errors.length} errors`);
      if (errors.length > 0) {
        console.log('First error:', errors[0]);
      }
      res.json({ imported, errors });
    } catch (error) {
      await connection.rollback();
      console.log('❌ Transaction error:', error.message);
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.log('❌ Import failed:', error.message);
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

// Public stats endpoint (no auth required)
app.get('/api/stats', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    // Get total entries
    const [entryCount] = await connection.query('SELECT COUNT(*) as count FROM time_entries');
    
    // Get total hours
    const [hoursSum] = await connection.query('SELECT SUM(hours) as total FROM time_entries');
    
    // Get unique projects
    const [projectCount] = await connection.query('SELECT COUNT(DISTINCT project_id) as count FROM time_entries WHERE project_id IS NOT NULL');
    
    // Get unique users
    const [userCount] = await connection.query('SELECT COUNT(DISTINCT user_id) as count FROM time_entries');
    
    // Get recent entries (last 100)
    const [entries] = await connection.query(`
      SELECT 
        id, user_id, project_id, description, hours, entry_date, source, created_at
      FROM time_entries 
      ORDER BY created_at DESC 
      LIMIT 100
    `);
    
    connection.release();
    
    res.json({
      totalEntries: parseInt(entryCount[0].count) || 0,
      totalHours: parseFloat(hoursSum[0].total) || 0,
      totalProjects: parseInt(projectCount[0].count) || 0,
      totalUsers: parseInt(userCount[0].count) || 0,
      recentEntries: entries
    });
  } catch (error) {
    console.error('Error getting stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// Bulk update time entries - assign to project (no auth for now)
app.post('/api/time-entries/bulk-assign', async (req, res) => {
  try {
    const { entryIds, projectId } = req.body;
    
    if (!entryIds || !Array.isArray(entryIds) || entryIds.length === 0) {
      return res.status(400).json({ error: 'entryIds array is required' });
    }
    
    if (!projectId) {
      return res.status(400).json({ error: 'projectId is required' });
    }
    
    const connection = await pool.getConnection();
    
    // Update entries
    const placeholders = entryIds.map(() => '?').join(',');
    const [result] = await connection.query(
      `UPDATE time_entries SET project_id = ? WHERE id IN (${placeholders})`,
      [projectId, ...entryIds]
    );
    
    connection.release();
    
    res.json({ 
      success: true, 
      updated: result.affectedRows,
      message: `${result.affectedRows} entries assigned to project ${projectId}`
    });
  } catch (error) {
    console.error('Error bulk assigning:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update project
app.put('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, color, status } = req.body;
    
    const [result] = await pool.query(
      'UPDATE projects SET name = ?, description = ?, color = ?, status = ? WHERE id = ?',
      [name, description, color, status, id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    res.json({ success: true, message: 'Project updated' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete project
app.delete('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Unassign all time entries from this project
    await pool.query('UPDATE time_entries SET project_id = NULL WHERE project_id = ?', [id]);
    
    // Delete project
    const [result] = await pool.query('DELETE FROM projects WHERE id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    res.json({ success: true, message: 'Project deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create user
app.post('/api/users', authenticateToken, async (req, res) => {
  try {
    const { name, email, password, hourly_rate, role } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password required' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password_hash, hourly_rate, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, hashedPassword, hourly_rate || 75, role || 'agent']
    );
    
    res.json({ success: true, id: result.insertId });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: error.message });
  }
});

// Update user
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, password, hourly_rate, role } = req.body;
    
    let query = 'UPDATE users SET name = ?, email = ?, hourly_rate = ?, role = ?';
    let params = [name, email, hourly_rate, role];
    
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      query += ', password_hash = ?';
      params.push(hashedPassword);
    }
    
    query += ' WHERE id = ?';
    params.push(id);
    
    const [result] = await pool.query(query, params);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ success: true, message: 'User updated' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete user
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Don't allow deleting yourself
    if (req.user.id === parseInt(id)) {
      return res.status(400).json({ error: 'Cannot delete yourself' });
    }
    
    const [result] = await pool.query('DELETE FROM users WHERE id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ success: true, message: 'User deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get project details with all time entries
app.get('/api/projects/:id/details', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get project info
    const [projects] = await pool.query(
      `SELECT p.*, c.name as client_name 
       FROM projects p 
       LEFT JOIN clients c ON p.client_id = c.id 
       WHERE p.id = ?`,
      [id]
    );
    
    if (projects.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }
    
    // Get all time entries for this project with user info
    const [entries] = await pool.query(
      `SELECT 
        te.*,
        u.name as user_name,
        u.hourly_rate as user_hourly_rate,
        (te.hours * u.hourly_rate) as cost
       FROM time_entries te
       JOIN users u ON te.user_id = u.id
       WHERE te.project_id = ?
       ORDER BY te.entry_date DESC, te.created_at DESC`,
      [id]
    );
    
    // Calculate totals
    const totalHours = entries.reduce((sum, e) => sum + parseFloat(e.hours), 0);
    const totalCost = entries.reduce((sum, e) => sum + parseFloat(e.cost), 0);
    const uniqueUsers = [...new Set(entries.map(e => e.user_id))].length;
    
    // Group by user
    const userBreakdown = {};
    entries.forEach(e => {
      if (!userBreakdown[e.user_id]) {
        userBreakdown[e.user_id] = {
          user_id: e.user_id,
          user_name: e.user_name,
          user_rate: parseFloat(e.user_hourly_rate),
          hours: 0,
          cost: 0,
          entries: 0
        };
      }
      userBreakdown[e.user_id].hours += parseFloat(e.hours);
      userBreakdown[e.user_id].cost += parseFloat(e.cost);
      userBreakdown[e.user_id].entries++;
    });
    
    res.json({
      project: projects[0],
      entries: entries.map(e => ({
        ...e,
        hours: parseFloat(e.hours),
        cost: parseFloat(e.cost)
      })),
      summary: {
        totalHours,
        totalCost,
        totalEntries: entries.length,
        uniqueUsers
      },
      userBreakdown: Object.values(userBreakdown)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get real reports data
app.get('/api/reports/overview', authenticateToken, async (req, res) => {
  try {
    // Project report with real calculations
    const [projectReport] = await pool.query(`
      SELECT 
        p.id,
        p.name,
        p.color,
        p.status,
        p.fixed_budget,
        p.estimated_hours,
        COUNT(te.id) as total_entries,
        COALESCE(SUM(te.hours), 0) as total_hours,
        COUNT(DISTINCT te.user_id) as team_members,
        COALESCE(SUM(te.hours * u.hourly_rate), 0) as total_cost
      FROM projects p
      LEFT JOIN time_entries te ON p.id = te.project_id
      LEFT JOIN users u ON te.user_id = u.id
      WHERE p.status = 'active'
      GROUP BY p.id, p.name, p.color, p.status, p.fixed_budget, p.estimated_hours
      ORDER BY total_hours DESC
    `);
    
    // User report with real calculations
    const [userReport] = await pool.query(`
      SELECT 
        u.id,
        u.name,
        u.email,
        u.hourly_rate,
        COUNT(te.id) as total_entries,
        COALESCE(SUM(te.hours), 0) as total_hours,
        COUNT(DISTINCT te.project_id) as projects_count,
        COALESCE(SUM(te.hours * u.hourly_rate), 0) as total_cost
      FROM users u
      LEFT JOIN time_entries te ON u.id = te.user_id
      WHERE u.is_active = TRUE
      GROUP BY u.id, u.name, u.email, u.hourly_rate
      ORDER BY total_hours DESC
    `);
    
    res.json({
      projectReport: projectReport.map(p => ({
        ...p,
        total_hours: parseFloat(p.total_hours),
        total_cost: parseFloat(p.total_cost),
        fixed_budget: p.fixed_budget ? parseFloat(p.fixed_budget) : null,
        estimated_hours: p.estimated_hours ? parseFloat(p.estimated_hours) : null
      })),
      userReport: userReport.map(u => ({
        ...u,
        total_hours: parseFloat(u.total_hours),
        total_cost: parseFloat(u.total_cost),
        hourly_rate: parseFloat(u.hourly_rate)
      }))
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get time entries for a specific user
app.get('/api/time-entries/user/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Users can only see their own entries, unless admin
    if (req.user.role !== 'admin' && req.user.id !== parseInt(userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const [entries] = await pool.query(`
      SELECT 
        te.*,
        p.name as project_name,
        p.color as project_color
      FROM time_entries te
      LEFT JOIN projects p ON te.project_id = p.id
      WHERE te.user_id = ?
      ORDER BY te.entry_date DESC, te.created_at DESC
      LIMIT 200
    `, [userId]);
    
    res.json(entries.map(e => ({
      ...e,
      hours: parseFloat(e.hours)
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create time entry
app.post('/api/time-entries', authenticateToken, async (req, res) => {
  try {
    const { user_id, project_id, entry_date, hours, description, billable, source } = req.body;
    
    // Users can only create entries for themselves, unless admin
    if (req.user.role !== 'admin' && req.user.id !== parseInt(user_id)) {
      return res.status(403).json({ error: 'Can only create entries for yourself' });
    }
    
    // Get user's hourly rate
    const [users] = await pool.query('SELECT hourly_rate FROM users WHERE id = ?', [user_id]);
    const hourlyRate = users[0] ? users[0].hourly_rate : 0;
    
    const [result] = await pool.query(
      `INSERT INTO time_entries 
       (user_id, project_id, entry_date, hours, description, billable, hourly_rate, source, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [user_id, project_id, entry_date, hours, description || '', billable !== false, hourlyRate, source || 'manual']
    );
    
    res.json({ success: true, id: result.insertId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete time entry
app.delete('/api/time-entries/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check ownership
    const [entries] = await pool.query('SELECT user_id FROM time_entries WHERE id = ?', [id]);
    
    if (entries.length === 0) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    
    // Users can only delete their own entries, unless admin
    if (req.user.role !== 'admin' && req.user.id !== entries[0].user_id) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    await pool.query('DELETE FROM time_entries WHERE id = ?', [id]);
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get project assignments (which users can use which projects)
app.get('/api/projects/:projectId/assignments', authenticateToken, async (req, res) => {
  try {
    const { projectId } = req.params;
    
    const [assignments] = await pool.query(
      'SELECT user_id FROM project_assignments WHERE project_id = ?',
      [projectId]
    );
    
    res.json(assignments.map(a => a.user_id));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Set project assignments
app.post('/api/projects/:projectId/assignments', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }
    
    const { projectId } = req.params;
    const { userIds } = req.body; // Array of user IDs
    
    // Delete existing assignments
    await pool.query('DELETE FROM project_assignments WHERE project_id = ?', [projectId]);
    
    // Add new assignments
    if (userIds && userIds.length > 0) {
      const values = userIds.map(userId => [projectId, userId]);
      await pool.query(
        'INSERT INTO project_assignments (project_id, user_id) VALUES ?',
        [values]
      );
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get projects for current user (only projects they're assigned to, or all if admin)
app.get('/api/projects/my/list', authenticateToken, async (req, res) => {
  try {
    let query;
    let params = [];
    
    if (req.user.role === 'admin') {
      // Admins see all projects
      query = 'SELECT * FROM projects ORDER BY name';
    } else {
      // Users see only assigned projects
      query = `
        SELECT DISTINCT p.* 
        FROM projects p
        LEFT JOIN project_assignments pa ON p.id = pa.project_id
        WHERE pa.user_id = ? OR pa.user_id IS NULL
        ORDER BY p.name
      `;
      params = [req.user.id];
    }
    
    const [projects] = await pool.query(query, params);
    res.json(projects);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`✓ Server running on http://localhost:${PORT}`);
  console.log(`✓ API endpoints available at http://localhost:${PORT}/api`);
  console.log(`✓ Database: ${process.env.DB_NAME || 'project_tracker'}`);
});

module.exports = app;
