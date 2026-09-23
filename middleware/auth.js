const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Acceso denegado: Token no provisto' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Consultar usuario directamente en DB para tener el rol actualizado en tiempo real
    const dbUser = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, email: true, tipo_usuario: true },
    });

    if (!dbUser) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    req.user = dbUser;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Token inválido o expirado' });
  }
};

module.exports = authenticateToken;