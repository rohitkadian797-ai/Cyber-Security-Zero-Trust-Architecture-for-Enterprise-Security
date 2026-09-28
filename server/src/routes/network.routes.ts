import { Router } from 'express';
import db from '../db/database.js';

export const networkRouter = Router();

// GET /api/network/segments
networkRouter.get('/segments', (_req, res) => {
  try {
    const segments = db.prepare('SELECT * FROM network_segments').all();
    return res.json(segments);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/network/rules
networkRouter.get('/rules', (_req, res) => {
  try {
    const rules = db.prepare(`
      SELECT r.*, 
             s1.name as source_segment_name, s1.code as source_segment_code, s1.color as source_segment_color,
             s2.name as target_segment_name, s2.code as target_segment_code, s2.color as target_segment_color
      FROM segment_rules r
      JOIN network_segments s1 ON r.source_segment_id = s1.id
      JOIN network_segments s2 ON r.target_segment_id = s2.id
    `).all();
    return res.json(rules);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/network/rules/:id/toggle - Toggle rule allowed status
networkRouter.post('/rules/:id/toggle', (req, res) => {
  try {
    const { id } = req.params;
    const rule = db.prepare('SELECT allowed FROM segment_rules WHERE id = ?').get(id) as { allowed: number } | undefined;
    if (!rule) return res.status(404).json({ error: 'Rule not found' });

    const newAllowed = rule.allowed === 1 ? 0 : 1;
    db.prepare('UPDATE segment_rules SET allowed = ?, updated_at = ? WHERE id = ?')
      .run(newAllowed, new Date().toISOString(), id);

    return res.json({ id, allowed: newAllowed });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
