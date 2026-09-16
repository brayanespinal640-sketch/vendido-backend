const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { PrismaClient } = require('@prisma/client');
require('dotenv').config();

// Importar Middleware de Autenticación
const authenticateToken = require('./middleware/auth');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 4000;

// Configuración de Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configuración de Multer para recibir archivos en memoria
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors());
app.use(express.json());

// --- RUTA DE SALUD ---
app.get('/api/health', (req, res) => res.json({ status: 'ok', message: 'Servidor conectado' }));

// --- 1. REGISTRO DE USUARIO ---
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

// --- 2. LOGIN DE USUARIO ---
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

// --- 3. UPLOAD DE IMÁGENES ---
app.post('/api/upload', upload.single('imagen'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No se ha adjuntado ninguna imagen' });
    const fileBase64 = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
    const result = await cloudinary.uploader.upload(fileBase64, { folder: 'vendido_products' });
    res.json({ message: 'Imagen subida exitosamente', url: result.secure_url });
  } catch (error) {
    res.status(500).json({ error: 'Error al procesar la imagen' });
  }
});

// --- 4. ENDPOINTS DE PRODUCTOS ---

// Crear Producto (Requiere autenticación)
app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const { titulo, descripcion, precio, imagenes, tipo_entrega } = req.body;

    if (!titulo || !descripcion || !precio) {
      return res.status(400).json({ error: 'Título, descripción y precio son requeridos' });
    }

    const newProduct = await prisma.product.create({
      data: {
        user_id: req.user.id, // ID extraído del token JWT
        titulo,
        descripcion,
        precio: parseFloat(precio),
        imagenes: imagenes || [],
        tipo_entrega: tipo_entrega || 'AMBOS',
      },
    });

    res.status(201).json({
      message: 'Producto publicado exitosamente',
      product: newProduct,
    });
  } catch (error) {
    console.error('Error al crear producto:', error);
    res.status(500).json({ error: 'Error al publicar el producto' });
  }
});

// Listar todos los productos disponibles (Feed público)
app.get('/api/products', async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: { estado: 'DISPONIBLE' },
      orderBy: { created_at: 'desc' },
      include: {
        user: {
          select: { id: true, nombre: true, email: true, foto_perfil: true },
        },
      },
    });

    res.json(products);
  } catch (error) {
    console.error('Error al obtener productos:', error);
    res.status(500).json({ error: 'Error al obtener el catálogo de productos' });
  }
});

// Obtener detalle de un producto específico
app.get('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const product = await prisma.product.findUnique({
      where: { id },
      include: {
        user: {
          select: { id: true, nombre: true, email: true, foto_perfil: true },
        },
      },
    });

    if (!product) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    res.json(product);
  } catch (error) {
    console.error('Error al consultar producto:', error);
    res.status(500).json({ error: 'Error interno al buscar el producto' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});