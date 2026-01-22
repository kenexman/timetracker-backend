// BACKEND FIX - Replace the CREATE PROJECT endpoint in server.js

// Create project (admin only)
app.post('/api/projects', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { 
      name, 
      description, 
      color, 
      hourly_budget, 
      status,
      client_id,
      project_code,
      billing_type,
      hourly_rate,
      fixed_budget,
      estimated_hours,
      start_date,
      end_date
    } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Project name is required' });
    }

    const [result] = await pool.query(
      `INSERT INTO projects 
       (name, description, color, hourly_budget, status, client_id, project_code, 
        billing_type, hourly_rate, fixed_budget, estimated_hours, start_date, end_date) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name, 
        description || null, 
        color || '#667eea', 
        hourly_budget || null, 
        status || 'active',
        client_id || null,
        project_code || null,
        billing_type || 'hourly',
        hourly_rate || null,
        fixed_budget || null,
        estimated_hours || null,
        start_date || null,
        end_date || null
      ]
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
    res.status(500).json({ 
      error: 'Failed to create project',
      details: error.message 
    });
  }
});

// ALSO UPDATE THE PUT ENDPOINT:

// Update project (admin only)
app.put('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { 
      name, 
      description, 
      color, 
      hourly_budget, 
      status,
      client_id,
      project_code,
      billing_type,
      hourly_rate,
      fixed_budget,
      estimated_hours,
      start_date,
      end_date
    } = req.body;

    const [result] = await pool.query(
      `UPDATE projects 
       SET name = ?, description = ?, color = ?, hourly_budget = ?, status = ?,
           client_id = ?, project_code = ?, billing_type = ?, hourly_rate = ?,
           fixed_budget = ?, estimated_hours = ?, start_date = ?, end_date = ?
       WHERE id = ?`,
      [
        name, 
        description, 
        color, 
        hourly_budget, 
        status,
        client_id,
        project_code,
        billing_type,
        hourly_rate,
        fixed_budget,
        estimated_hours,
        start_date,
        end_date,
        req.params.id
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    res.json({ message: 'Project updated successfully' });
  } catch (error) {
    console.error('Error updating project:', error);
    res.status(500).json({ 
      error: 'Failed to update project',
      details: error.message 
    });
  }
});
