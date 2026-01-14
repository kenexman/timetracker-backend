const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// CORS Configuration - MUST BE FIRST!
// ============================================
app.use(cors({
  origin: [
    'https://coefficient.fun',
    'https://www.coefficient.fun',
    'http://localhost:3000',
    'http://localhost:5173'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ============================================
// Middleware
// ============================================
app.use(express.json());

// ============================================
// Database Connection Pool
// ============================================
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'srv1670.hstgr.io',
  user: process.env.DB_USER || 'u242064145_project_tracke',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'u242064145_project_tracke',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test database connection
pool.getConnection()
  .then(connection => {
    console.log('✅ Database connected successfully');
    connection.release();
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
  });

// ============================================
// Authentication Middleware
// ============================================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key-change-this', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// ============================================
// Health Check
// ============================================
app.get('/', (req, res) => {
  res.json({ 
    message: 'Time Tracker API',
    version: '1.0.0',
    status: 'running'
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================
// AUTH ROUTES
// ============================================

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const [users] = await pool.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role 
      },
      process.env.JWT_SECRET || 'your-secret-key-change-this',
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        hourly_rate: user.hourly_rate
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Register (optional - only if you want user registration)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, hourly_rate } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    // Check if user exists
    const [existing] = await pool.query(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      'INSERT INTO users (name, email, password, hourly_rate, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, hashedPassword, hourly_rate || 0, 'user']
    );

    const token = jwt.sign(
      { id: result.insertId, email, role: 'user' },
      process.env.JWT_SECRET || 'your-secret-key-change-this',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: {
        id: result.insertId,
        name,
        email,
        role: 'user',
        hourly_rate: hourly_rate || 0
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ============================================
// USER ROUTES
// ============================================

// Get all users (admin only)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, name, email, role, hourly_rate, created_at FROM users ORDER BY name'
    );
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get user by ID
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, name, email, role, hourly_rate, created_at FROM users WHERE id = ?',
      [req.params.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(users[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// Update user
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { name, email, hourly_rate, role } = req.body;
    
    // Only admin or self can update
    if (req.user.role !== 'admin' && req.user.id !== parseInt(req.params.id)) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    const [result] = await pool.query(
      'UPDATE users SET name = ?, email = ?, hourly_rate = ?, role = ? WHERE id = ?',
      [name, email, hourly_rate, role, req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'User updated successfully' });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const [result] = await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ============================================
// PROJECT ROUTES
// ============================================

// Get all projects
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const [projects] = await pool.query(
      'SELECT * FROM projects ORDER BY name'
    );
    res.json(projects);
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

// Get project by ID
app.get('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    const [projects] = await pool.query(
      'SELECT * FROM projects WHERE id = ?',
      [req.params.id]
    );

    if (projects.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    res.json(projects[0]);
  } catch (error) {
    console.error('Error fetching project:', error);
    res.status(500).json({ error: 'Failed to fetch project' });
  }
});

// Create project (admin only)
app.post('/api/projects', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { name, description, color, hourly_budget, status } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Project name is required' });
    }

    const [result] = await pool.query(
      'INSERT INTO projects (name, description, color, hourly_budget, status) VALUES (?, ?, ?, ?, ?)',
      [name, description || null, color || '#667eea', hourly_budget || null, status || 'active']
    );

    res.status(201).json({
      id: result.insertId,
      name,
      description,
      color,
      hourly_budget,
      status: status || 'active'
    });
  } catch (error) {
    console.error('Error creating project:', error);
    res.status(500).json({ error: 'Failed to create project' });
  }
});

// Update project (admin only)
app.put('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { name, description, color, hourly_budget, status } = req.body;

    const [result] = await pool.query(
      'UPDATE projects SET name = ?, description = ?, color = ?, hourly_budget = ?, status = ? WHERE id = ?',
      [name, description, color, hourly_budget, status, req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    res.json({ message: 'Project updated successfully' });
  } catch (error) {
    console.error('Error updating project:', error);
    res.status(500).json({ error: 'Failed to update project' });
  }
});

// Delete project (admin only)
app.delete('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const [result] = await pool.query('DELETE FROM projects WHERE id = ?', [req.params.id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    res.json({ message: 'Project deleted successfully' });
  } catch (error) {
    console.error('Error deleting project:', error);
    res.status(500).json({ error: 'Failed to delete project' });
  }
});

// ============================================
// TIME ENTRY ROUTES
// ============================================

// Get time entries for a user
app.get('/api/time-entries/user/:userId', authenticateToken, async (req, res) => {
  try {
    // Users can only see their own entries unless they're admin
    if (req.user.role !== 'admin' && req.user.id !== parseInt(req.params.userId)) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    const [entries] = await pool.query(`
      SELECT 
        te.*,
        p.name as project_name,
        p.color as project_color,
        u.name as user_name,
        u.hourly_rate as user_hourly_rate,
        ar.id as rule_id,
        ar.match_type as rule_match_type,
        ar.match_value as rule_match_value,
        CONCAT(ar.match_type, ': "', ar.match_value, '"') as rule_info
      FROM time_entries te
      LEFT JOIN projects p ON te.project_id = p.id
      LEFT JOIN users u ON te.user_id = u.id
      LEFT JOIN assignment_rules ar ON te.rule_id = ar.id
      WHERE te.user_id = ?
      ORDER BY te.entry_date DESC, te.created_at DESC
    `, [req.params.userId]);

    res.json(entries);
  } catch (error) {
    console.error('Error fetching time entries:', error);
    res.status(500).json({ error: 'Failed to fetch time entries' });
  }
});

// Get unassigned entries
app.get('/api/time-entries/unassigned', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.role === 'admin' ? null : req.user.id;
    
    let query = `
      SELECT 
        te.*,
        u.name as user_name,
        u.hourly_rate as user_hourly_rate
      FROM time_entries te
      LEFT JOIN users u ON te.user_id = u.id
      WHERE te.project_id IS NULL
    `;
    
    const params = [];
    if (userId) {
      query += ' AND te.user_id = ?';
      params.push(userId);
    }
    
    query += ' ORDER BY te.entry_date DESC';
    
    const [entries] = await pool.query(query, params);
    res.json(entries);
  } catch (error) {
    console.error('Error fetching unassigned entries:', error);
    res.status(500).json({ error: 'Failed to fetch unassigned entries' });
  }
});

// Create time entry
app.post('/api/time-entries', authenticateToken, async (req, res) => {
  try {
    const { user_id, project_id, rule_id, description, hours, entry_date, billable, source } = req.body;

    // Users can only create entries for themselves unless they're admin
    if (req.user.role !== 'admin' && req.user.id !== user_id) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    if (!user_id || !hours || !entry_date) {
      return res.status(400).json({ error: 'user_id, hours, and entry_date are required' });
    }

    const [result] = await pool.query(
      `INSERT INTO time_entries 
       (user_id, project_id, rule_id, description, hours, entry_date, billable, source) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [user_id, project_id || null, rule_id || null, description || '', hours, entry_date, billable !== false, source || 'manual']
    );

    res.status(201).json({
      id: result.insertId,
      user_id,
      project_id,
      rule_id,
      description,
      hours,
      entry_date,
      billable: billable !== false,
      source: source || 'manual'
    });
  } catch (error) {
    console.error('Error creating time entry:', error);
    res.status(500).json({ error: 'Failed to create time entry' });
  }
});

// Update time entry
app.put('/api/time-entries/:id', authenticateToken, async (req, res) => {
  try {
    const { project_id, description, hours, entry_date, billable } = req.body;

    // Check ownership
    const [entries] = await pool.query('SELECT user_id FROM time_entries WHERE id = ?', [req.params.id]);
    
    if (entries.length === 0) {
      return res.status(404).json({ error: 'Time entry not found' });
    }

    if (req.user.role !== 'admin' && req.user.id !== entries[0].user_id) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    const [result] = await pool.query(
      'UPDATE time_entries SET project_id = ?, description = ?, hours = ?, entry_date = ?, billable = ? WHERE id = ?',
      [project_id, description, hours, entry_date, billable !== false, req.params.id]
    );

    res.json({ message: 'Time entry updated successfully' });
  } catch (error) {
    console.error('Error updating time entry:', error);
    res.status(500).json({ error: 'Failed to update time entry' });
  }
});

// Bulk update time entries (assign project)
app.patch('/api/time-entries/bulk-assign', authenticateToken, async (req, res) => {
  try {
    const { entry_ids, project_id } = req.body;

    if (!entry_ids || !Array.isArray(entry_ids) || entry_ids.length === 0) {
      return res.status(400).json({ error: 'entry_ids array is required' });
    }

    if (!project_id) {
      return res.status(400).json({ error: 'project_id is required' });
    }

    // Check ownership for non-admin users
    if (req.user.role !== 'admin') {
      const placeholders = entry_ids.map(() => '?').join(',');
      const [entries] = await pool.query(
        `SELECT id FROM time_entries WHERE id IN (${placeholders}) AND user_id = ?`,
        [...entry_ids, req.user.id]
      );

      if (entries.length !== entry_ids.length) {
        return res.status(403).json({ error: 'Not authorized to update all entries' });
      }
    }

    const placeholders = entry_ids.map(() => '?').join(',');
    const [result] = await pool.query(
      `UPDATE time_entries SET project_id = ? WHERE id IN (${placeholders})`,
      [project_id, ...entry_ids]
    );

    res.json({ 
      message: 'Entries updated successfully',
      updated_count: result.affectedRows
    });
  } catch (error) {
    console.error('Error bulk updating entries:', error);
    res.status(500).json({ error: 'Failed to update entries' });
  }
});

// Delete time entry
app.delete('/api/time-entries/:id', authenticateToken, async (req, res) => {
  try {
    // Check ownership
    const [entries] = await pool.query('SELECT user_id FROM time_entries WHERE id = ?', [req.params.id]);
    
    if (entries.length === 0) {
      return res.status(404).json({ error: 'Time entry not found' });
    }

    if (req.user.role !== 'admin' && req.user.id !== entries[0].user_id) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    const [result] = await pool.query('DELETE FROM time_entries WHERE id = ?', [req.params.id]);
    res.json({ message: 'Time entry deleted successfully' });
  } catch (error) {
    console.error('Error deleting time entry:', error);
    res.status(500).json({ error: 'Failed to delete time entry' });
  }
});

// ============================================
// ASSIGNMENT RULES ROUTES
// ============================================

// Get all assignment rules
app.get('/api/assignment-rules', authenticateToken, async (req, res) => {
  try {
    const [rules] = await pool.query(`
      SELECT 
        ar.*,
        p.name as project_name,
        p.color as project_color
      FROM assignment_rules ar
      LEFT JOIN projects p ON ar.project_id = p.id
      ORDER BY ar.priority DESC, ar.created_at DESC
    `);
    res.json(rules);
  } catch (error) {
    console.error('Error fetching assignment rules:', error);
    res.status(500).json({ error: 'Failed to fetch assignment rules' });
  }
});

// Create assignment rule (admin only)
app.post('/api/assignment-rules', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { project_id, match_type, match_value, priority, is_active } = req.body;

    if (!project_id || !match_type || !match_value) {
      return res.status(400).json({ error: 'project_id, match_type, and match_value are required' });
    }

    const [result] = await pool.query(
      'INSERT INTO assignment_rules (project_id, match_type, match_value, priority, is_active) VALUES (?, ?, ?, ?, ?)',
      [project_id, match_type, match_value, priority || 10, is_active !== false]
    );

    res.status(201).json({
      id: result.insertId,
      project_id,
      match_type,
      match_value,
      priority: priority || 10,
      is_active: is_active !== false
    });
  } catch (error) {
    console.error('Error creating assignment rule:', error);
    res.status(500).json({ error: 'Failed to create assignment rule' });
  }
});

// Update assignment rule (admin only)
app.put('/api/assignment-rules/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { project_id, match_type, match_value, priority, is_active } = req.body;

    const [result] = await pool.query(
      'UPDATE assignment_rules SET project_id = ?, match_type = ?, match_value = ?, priority = ?, is_active = ? WHERE id = ?',
      [project_id, match_type, match_value, priority, is_active !== false, req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Assignment rule not found' });
    }

    res.json({ message: 'Assignment rule updated successfully' });
  } catch (error) {
    console.error('Error updating assignment rule:', error);
    res.status(500).json({ error: 'Failed to update assignment rule' });
  }
});

// Toggle assignment rule active status (admin only)
app.patch('/api/assignment-rules/:id/toggle', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const [result] = await pool.query(
      'UPDATE assignment_rules SET is_active = NOT is_active WHERE id = ?',
      [req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Assignment rule not found' });
    }

    res.json({ message: 'Assignment rule toggled successfully' });
  } catch (error) {
    console.error('Error toggling assignment rule:', error);
    res.status(500).json({ error: 'Failed to toggle assignment rule' });
  }
});

// Delete assignment rule (admin only)
app.delete('/api/assignment-rules/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const [result] = await pool.query('DELETE FROM assignment_rules WHERE id = ?', [req.params.id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Assignment rule not found' });
    }

    res.json({ message: 'Assignment rule deleted successfully' });
  } catch (error) {
    console.error('Error deleting assignment rule:', error);
    res.status(500).json({ error: 'Failed to delete assignment rule' });
  }
});

// ============================================
// STATS / REPORTS ROUTES
// ============================================

app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const userId = isAdmin ? null : req.user.id;
    
    // Get project stats
    let projectStatsQuery = `
      SELECT 
        p.id as project_id,
        p.name as project_name,
        p.color as project_color,
        COALESCE(SUM(te.hours), 0) as total_hours,
        COUNT(DISTINCT te.user_id) as user_count
      FROM projects p
      LEFT JOIN time_entries te ON p.id = te.project_id
      WHERE p.status = 'active'
    `;
    
    if (userId) {
      projectStatsQuery += ` AND (te.user_id = ? OR te.user_id IS NULL)`;
    }
    
    projectStatsQuery += `
      GROUP BY p.id, p.name, p.color
      HAVING total_hours > 0
      ORDER BY total_hours DESC
    `;
    
    const [projectStats] = await pool.query(
      projectStatsQuery,
      userId ? [userId] : []
    );
    
    // Calculate costs for projects
    const projectStatsWithCost = await Promise.all(
      projectStats.map(async (project) => {
        const [entries] = await pool.query(
          `SELECT te.hours, u.hourly_rate 
           FROM time_entries te
           JOIN users u ON te.user_id = u.id
           WHERE te.project_id = ? ${userId ? 'AND te.user_id = ?' : ''}`,
          userId ? [project.project_id, userId] : [project.project_id]
        );
        
        const total_cost = entries.reduce((sum, e) => {
          return sum + (parseFloat(e.hours) * parseFloat(e.hourly_rate || 0));
        }, 0);
        
        return {
          ...project,
          total_cost: total_cost
        };
      })
    );
    
    // Get user stats
    let userStatsQuery = `
      SELECT 
        u.id as user_id,
        u.name as user_name,
        u.email as user_email,
        u.hourly_rate,
        COALESCE(SUM(te.hours), 0) as total_hours
      FROM users u
      LEFT JOIN time_entries te ON u.id = te.user_id
    `;
    
    if (userId) {
      userStatsQuery += ` WHERE u.id = ?`;
    }
    
    userStatsQuery += `
      GROUP BY u.id, u.name, u.email, u.hourly_rate
      HAVING total_hours > 0
      ORDER BY total_hours DESC
    `;
    
    const [userStats] = await pool.query(
      userStatsQuery,
      userId ? [userId] : []
    );
    
    // Calculate costs for users
    const userStatsWithCost = userStats.map(user => ({
      ...user,
      total_cost: parseFloat(user.total_hours) * parseFloat(user.hourly_rate || 0)
    }));
    
    // Get recent entries for detailed breakdown
    let recentEntriesQuery = `
      SELECT 
        te.*,
        u.name as user_name,
        u.hourly_rate as user_hourly_rate,
        p.name as project_name,
        p.color as project_color
      FROM time_entries te
      LEFT JOIN users u ON te.user_id = u.id
      LEFT JOIN projects p ON te.project_id = p.id
    `;
    
    if (userId) {
      recentEntriesQuery += ` WHERE te.user_id = ?`;
    }
    
    recentEntriesQuery += `
      ORDER BY te.entry_date DESC
      LIMIT 1000
    `;
    
    const [recentEntries] = await pool.query(
      recentEntriesQuery,
      userId ? [userId] : []
    );
    
    res.json({
      projectStats: projectStatsWithCost,
      userStats: userStatsWithCost,
      recentEntries: recentEntries
    });
    
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ 
      error: 'Failed to fetch statistics',
      message: error.message 
    });
  }
});

// ============================================
// 404 Handler
// ============================================
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ============================================
// Error Handler
// ============================================
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ============================================
// Start Server
// ============================================
app.listen(PORT, () => {
  console.log(`🚀 Time Tracker API running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 CORS enabled for: coefficient.fun`);
  console.log(`✅ Ready to accept connections`);
});
