// server/routes/chat.js
const express = require('express');
const Chat = require('../models/Chat');
const router = express.Router();

/**
 * GET /api/chat?before=<ISO timestamp>&limit=20
 * - If `before` not provided: returns latest `limit` messages (newest).
 * - Otherwise: returns messages older than `before`, up to `limit`.
 * Returned array is ordered oldest -> newest (so it can be appended normally).
 */
router.get('/', async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 20, 200);
    const before = req.query.before;

    const query = {};
    if (before) {
      // fetch messages strictly older than `before`
      query.createdAt = { $lt: new Date(before) };
    }

    // fetch newest-first then reverse so client receives oldest->newest
    const items = await Chat.find(query)
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    res.json(items.reverse());
  } catch (err) {
    console.error('Failed to load chats:', err);
    res.status(500).json({ message: 'Failed to load chats' });
  }
});

module.exports = router;
