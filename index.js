const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
require('dotenv').config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// Ruta de verificación
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Servidor conectado' });
});

// 1. REGISTRO DE USUARIO
app.post('/api/auth/register', async (req, res) => {
  try {
    const { nombre, email, password, tipo_usuario } = req.body;

    if (!nombre || !email || !password) {
      return res.status(400).json({ error: 'Nombre, email y contraseña son obligatorios' });
    }

    // Verificar si el usuario ya existe
    const userExists = await prisma.user.findUnique({ where: { email } });
    if (userExists) {
      return res.status(400).json({ error: 'El email ya está registrado' });
    }

    // Encriptar la contraseña
    const password_hash = await bcrypt.hash(password, 10);

    // Guardar en Supabase mediante Prisma
    const newUser = await prisma.user.create({
      data: {
        nombre,
        email,
        password_hash,
        tipo_usuario: tipo_usuario || 'cliente',
      },
    });

    res.status(201).json({
      message: 'Usuario registrado exitosamente',
      user: { id: newUser.id, nombre: newUser.nombre, email: newUser.email },
    });
  } catch (error) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// 2. LOGIN DE USUARIO
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña requeridos' });
    }

    // Buscar usuario por email
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }

    // Comparar contraseña encriptada
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }

    // Generar Token JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, tipo_usuario: user.tipo_usuario },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Inicio de sesión exitoso',
      token,
      user: { id: user.id, nombre: user.nombre, email: user.email, tipo_usuario: user.tipo_usuario },
    });
  } catch (error) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});