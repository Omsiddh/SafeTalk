import { Server } from 'socket.io';
import jwt from 'jsonwebtoken';

export function initSocket(server) {
  const io = new Server(server, {
    cors: {
      origin: (process.env.CLIENT_ORIGIN || 'http://localhost:5173').split(','),
      credentials: true,
    },
  });

  io.use((socket, next) => {
    const token = socket.handshake.auth?.token || null;
    if (!token) return next(new Error('Unauthorized'));
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      socket.user = { id: payload.userId, role: payload.role };
      return next();
    } catch (e) {
      return next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    // Join personal room for direct messages
    socket.join(socket.user.id);

    socket.on('message:send', ({ to, ciphertext, encryptedKey, iv }) => {
      if (!to || !ciphertext || !encryptedKey || !iv) return;
      io.to(to).emit('message:receive', {
        from: socket.user.id,
        to,
        ciphertext,
        encryptedKey,
        iv,
        timestamp: new Date().toISOString(),
      });
    });
  });

  return io;
}