// server/app.js
const express = require('express');
const http = require('http');
const cors = require('cors');
const socketio = require('socket.io');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();
const mongoose = require('mongoose');

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

const authRoutes = require('./routes/auth');
const Chat = require('./models/Chat');

const app = express();
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3001'],
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Auth routes
app.use('/api/auth', authRoutes);
const chatRoutes = require('./routes/chat');
app.use('/api/chat', chatRoutes);

// Socket.IO auth middleware
const verifySocketToken = (socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Authentication error'));

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return next(new Error('Authentication error'));
        socket.user = user;
        next();
    });
};

const server = http.createServer(app);
const io = socketio(server, {
    cors: {
        origin: ['http://localhost:3000', 'http://localhost:3001'],
        methods: ['GET', 'POST'],
        credentials: true
    }
});

io.use(verifySocketToken);

io.on('connection', async (socket) => {
  console.log(`Connected: ${socket.user?.id}`);

  // Send last 50 messages (oldest -> newest)
  try {
    const lastChats = await Chat.find().sort({ createdAt: -1 }).limit(50);
    socket.emit('chat-history', lastChats.reverse());
  } catch (err) {
    console.error('Failed to load chat history:', err);
  }

  socket.on('chat', async (data) => {
    const messageData = {
      sender: socket.user?.username || String(socket.user?.id || 'unknown'),
      message: data.message,
      createdAt: new Date()
    };

    try {
      // save and get saved doc (contains _id)
      const saved = await new Chat(messageData).save();
      io.emit('chat', saved);
    } catch (err) {
      console.error('Failed to save chat:', err);
      // emit a safe fallback (temporary id) so clients still get the message
      io.emit('chat', { ...messageData, _id: `temp-${Date.now()}` });
    }
  });

  socket.on('disconnect', () => {
    console.log('Disconnected', socket.user?.id);
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
