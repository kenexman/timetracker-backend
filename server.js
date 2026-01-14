// ============================================
// BACKEND: STATS ENDPOINT FOR REPORTS
// Add this to server.js
// ============================================

// GET /api/stats - Get statistics for reports
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const userId = isAdmin ? null : req.user.id;
    
    // Build WHERE clause for user filter
    const userFilter = userId ? 'WHERE te.user_id = ?' : '';
    const userParams = userId ? [userId] : [];
    
    // Get project stats
    const [projectStats] = await pool.query(`
      SELECT 
        p.id as project_id,
        p.name as project_name,
        p.color as project_color,
        COALESCE(SUM(te.hours), 0) as total_hours,
        COALESCE(SUM(te.hours * u.hourly_rate), 0) as total_cost,
        COUNT(DISTINCT te.user_id) as user_count
      FROM projects p
      LEFT JOIN time_entries te ON p.id = te.project_id ${userFilter ? 'AND te.user_id = ?' : ''}
      LEFT JOIN users u ON te.user_id = u.id
      WHERE p.status = 'active'
      GROUP BY p.id, p.name, p.color
      HAVING total_hours > 0
      ORDER BY total_hours DESC
    `, userId ? [userId] : []);
    
    // Get user stats
    const [userStats] = await pool.query(`
      SELECT 
        u.id as user_id,
        u.name as user_name,
        u.email as user_email,
        u.hourly_rate,
        COALESCE(SUM(te.hours), 0) as total_hours,
        COALESCE(SUM(te.hours * u.hourly_rate), 0) as total_cost
      FROM users u
      LEFT JOIN time_entries te ON u.id = te.user_id ${userFilter}
      ${userId ? 'WHERE u.id = ?' : ''}
      GROUP BY u.id, u.name, u.email, u.hourly_rate
      HAVING total_hours > 0
      ORDER BY total_hours DESC
    `, userParams);
    
    // Get recent entries for detailed breakdown
    const [recentEntries] = await pool.query(`
      SELECT 
        te.*,
        u.name as user_name,
        u.hourly_rate as user_hourly_rate,
        p.name as project_name,
        p.color as project_color
      FROM time_entries te
      LEFT JOIN users u ON te.user_id = u.id
      LEFT JOIN projects p ON te.project_id = p.id
      ${userFilter}
      ORDER BY te.entry_date DESC
      LIMIT 1000
    `, userParams);
    
    res.json({
      projectStats,
      userStats,
      recentEntries
    });
    
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// ============================================
// ALTERNATIVE: SIMPLER STATS ENDPOINT
// Use this if the above is too complex
// ============================================

app.get('/api/stats/simple', authenticateToken, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const userId = isAdmin ? null : req.user.id;
    
    // Project totals
    const projectQuery = `
      SELECT 
        p.id as project_id,
        p.name as project_name,
        COALESCE(SUM(te.hours), 0) as total_hours,
        COALESCE(COUNT(DISTINCT te.user_id), 0) as user_count
      FROM projects p
      LEFT JOIN time_entries te ON p.id = te.project_id
      WHERE p.status = 'active'
      ${userId ? 'AND (te.user_id = ? OR te.user_id IS NULL)' : ''}
      GROUP BY p.id, p.name
      HAVING total_hours > 0
      ORDER BY total_hours DESC
    `;
    
    const [projectStats] = await pool.query(projectQuery, userId ? [userId] : []);
    
    // User totals
    const userQuery = `
      SELECT 
        u.id as user_id,
        u.name as user_name,
        u.hourly_rate,
        COALESCE(SUM(te.hours), 0) as total_hours
      FROM users u
      LEFT JOIN time_entries te ON u.id = te.user_id
      ${userId ? 'WHERE u.id = ?' : ''}
      GROUP BY u.id, u.name, u.hourly_rate
      HAVING total_hours > 0
      ORDER BY total_hours DESC
    `;
    
    const [userStats] = await pool.query(userQuery, userId ? [userId] : []);
    
    // Add calculated cost
    const userStatsWithCost = userStats.map(u => ({
      ...u,
      total_cost: u.total_hours * parseFloat(u.hourly_rate || 0)
    }));
    
    const projectStatsWithCost = projectStats.map(p => ({
      ...p,
      total_cost: 0 // Calculate if needed
    }));
    
    res.json({
      projectStats: projectStatsWithCost,
      userStats: userStatsWithCost,
      recentEntries: []
    });
    
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});
