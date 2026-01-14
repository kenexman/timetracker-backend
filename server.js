// ============================================
// BACKEND FIX: Add Stats Endpoint to server.js
// ============================================

// IMPORTANT: Add this AFTER all the express setup
// Find where other routes are defined (after app = express())
// Add this with the other GET endpoints

// ============================================
// Add this AFTER your other routes (like GET /api/projects, etc.)
// Look for where you have: app.get('/api/time-entries/...
// Add this nearby:
// ============================================

app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    console.log('Stats endpoint called by user:', req.user.id);
    
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
    
    console.log(`Returning stats: ${projectStatsWithCost.length} projects, ${userStatsWithCost.length} users, ${recentEntries.length} entries`);
    
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
// WHERE TO ADD THIS IN YOUR server.js:
// ============================================

/*
Find this pattern in your server.js:
// ← Add CORS configuration HERE (before other middleware)
app.use(cors({
  origin: [
    'https://coefficient.fun',
    'https://www.coefficient.fun'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());  // ← This should come AFTER cors()

// Routes
app.get('/api/projects', authenticateToken, async (req, res) => {
  ...
});

app.get('/api/time-entries/user/:userId', authenticateToken, async (req, res) => {
  ...
});

// ← ADD THE STATS ENDPOINT HERE ←
// (After other routes, before app.listen)

app.get('/api/stats', authenticateToken, async (req, res) => {
  // ... code above ...
});

// Start server
app.listen(PORT, ...);
*/

// ============================================
// DEPLOYMENT STEPS:
// ============================================

/*
1. Open your server.js in Railway or locally
2. Find where your other routes are (app.get('/api/...'))
3. Add the /api/stats endpoint there
4. Make sure it's AFTER:
   - const app = express();
   - app.use(express.json());
   - authenticateToken middleware
5. And BEFORE:
   - app.listen(PORT, ...)
6. Save file
7. Git commit and push
8. Railway will auto-deploy
9. Test: https://your-backend.railway.app/api/stats
*/

// ============================================
// TEST THE ENDPOINT:
// ============================================

/*
# Test with curl:
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://timetracker-backend-production-ba09.up.railway.app/api/stats

# Should return:
{
  "projectStats": [...],
  "userStats": [...],
  "recentEntries": [...]
}
*/
