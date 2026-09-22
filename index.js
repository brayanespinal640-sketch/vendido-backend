const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { PrismaClient } = require('@prisma/client');
require('dotenv').config();

// Importar Middleware de Autenticación
const authenticateToken = require('./middleware/auth');

// Importar Esquemas de Validación con Zod
const { registerSchema } = require('./schemas/auth.schema');

const app = express();
const server = http.createServer(app);

// Configuración de Socket.IO con CORS
const io = new Server(server, {
  cors: {
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST'],
  },
});

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

// --- 1. REGISTRO DE USUARIO CON VALIDACIÓN DE ZOD ---
app.post('/api/auth/register', async (req, res) => {
  try {
    // Validar el cuerpo de la petición con Zod
    const validationResult = registerSchema.safeParse(req.body);

    if (!validationResult.success) {
      // Mapear los errores y devolverlos al frontend
      const errors = validationResult.error.errors.map((err) => err.message);
      return res.status(400).json({ errors });
    }

    const { nombre, email, password, tipo_usuario } = validationResult.data;

    // Verificar si el usuario ya existe
    const userExists = await prisma.user.findUnique({ where: { email } });
    if (userExists) {
      return res.status(400).json({ errors: ['El email ya está registrado'] });
    }

    // Encriptar la contraseña
    const password_hash = await bcrypt.hash(password, 10);

    // Crear usuario
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
    console.error('Error en registro:', error);
    res.status(500).json({ errors: ['Error interno del servidor'] });
  }
});

// --- 2. LOGIN DE USUARIO ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña requeridos' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }

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

// --- 3. UPLOAD DE IMÁGENES A CLOUDINARY ---
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

// Crear Producto
app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const { titulo, descripcion, precio, imagenes, tipo_entrega } = req.body;

    if (!titulo || !descripcion || !precio) {
      return res.status(400).json({ error: 'Título, descripción y precio son requeridos' });
    }

    const newProduct = await prisma.product.create({
      data: {
        user_id: req.user.id,
        titulo,
        descripcion,
        precio: parseFloat(precio),
        imagenes: imagenes || [],
        tipo_entrega: tipo_entrega || 'AMBOS',
      },
    });

    res.status(201).json({ message: 'Producto publicado exitosamente', product: newProduct });
  } catch (error) {
    res.status(500).json({ error: 'Error al publicar el producto' });
  }
});

// Obtener catálogo público de productos
app.get('/api/products', async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: { estado: 'DISPONIBLE' },
      orderBy: { created_at: 'desc' },
      include: { user: { select: { id: true, nombre: true, email: true, foto_perfil: true } } },
    });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener productos' });
  }
});

// Obtener detalle de un producto
app.get('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const product = await prisma.product.findUnique({
      where: { id },
      include: { user: { select: { id: true, nombre: true, email: true, foto_perfil: true } } },
    });
    if (!product) return res.status(404).json({ error: 'Producto no encontrado' });
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: 'Error al buscar el producto' });
  }
});

// --- 5. ENDPOINTS DE PERFIL Y MIS PRODUCTOS ---

// Obtener datos actualizados del usuario autenticado
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        nombre: true,
        email: true,
        foto_perfil: true,
        telefono: true,
        descripcion: true,
        tipo_usuario: true,
      },
    });

    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Error al consultar perfil' });
  }
});

// Actualizar perfil del usuario (nombre, foto, teléfono, descripción)
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { nombre, foto_perfil, telefono, descripcion } = req.body;

    const updatedUser = await prisma.user.update({
      where: { id: req.user.id },
      data: {
        nombre,
        foto_perfil,
        telefono,
        descripcion,
      },
      select: {
        id: true,
        nombre: true,
        email: true,
        foto_perfil: true,
        telefono: true,
        descripcion: true,
        tipo_usuario: true,
      },
    });

    res.json({ message: 'Perfil actualizado exitosamente', user: updatedUser });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar perfil' });
  }
});

// Obtener todos los productos publicados por el usuario en sesión
app.get('/api/user/products', authenticateToken, async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: { user_id: req.user.id },
      orderBy: { created_at: 'desc' },
    });

    res.json(products);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener tus productos' });
  }
});

// --- 6. ENDPOINTS DE PERFIL PÚBLICO Y RESEÑAS ---

// Obtener perfil público, productos disponibles y reseñas de un usuario
app.get('/api/users/:id/public', async (req, res) => {
  try {
    const { id } = req.params;

    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        nombre: true,
        foto_perfil: true,
        descripcion: true,
        created_at: true,
        products: {
          where: { estado: 'DISPONIBLE' },
          orderBy: { created_at: 'desc' },
        },
        reviewsReceived: {
          orderBy: { created_at: 'desc' },
          include: {
            autor: {
              select: { id: true, nombre: true, foto_perfil: true },
            },
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json(user);
  } catch (error) {
    console.error('Error al obtener perfil público:', error);
    res.status(500).json({ error: 'Error al consultar perfil del vendedor' });
  }
});

// Dejar una reseña/calificación a un vendedor
app.post('/api/users/:id/reviews', authenticateToken, async (req, res) => {
  try {
    const vendedor_id = req.params.id;
    const autor_id = req.user.id;
    const { calificacion, comentario } = req.body;

    if (vendedor_id === autor_id) {
      return res.status(400).json({ error: 'No puedes dejarte una reseña a ti mismo' });
    }

    if (!calificacion || calificacion < 1 || calificacion > 5) {
      return res.status(400).json({ error: 'La calificación debe ser entre 1 y 5 estrellas' });
    }

    if (!comentario) {
      return res.status(400).json({ error: 'El comentario es requerido' });
    }

    const newReview = await prisma.review.create({
      data: {
        vendedor_id,
        autor_id,
        calificacion: parseInt(calificacion),
        comentario,
      },
      include: {
        autor: { select: { id: true, nombre: true, foto_perfil: true } },
      },
    });

    res.status(201).json({ message: 'Reseña publicada exitosamente', review: newReview });
  } catch (error) {
    console.error('Error al crear reseña:', error);
    res.status(500).json({ error: 'Error al publicar la reseña' });
  }
});

// --- 7. ENDPOINTS DE CONVERSACIONES Y MENSAJES ---

// Obtener o crear conversación
app.post('/api/conversations', authenticateToken, async (req, res) => {
  try {
    const { producto_id, vendedor_id } = req.body;
    const comprador_id = req.user.id;

    if (comprador_id === vendedor_id) {
      return res.status(400).json({ error: 'No puedes iniciar un chat con tu propio producto' });
    }

    let conversation = await prisma.conversation.findUnique({
      where: {
        comprador_id_vendedor_id_producto_id: {
          comprador_id,
          vendedor_id,
          producto_id,
        },
      },
    });

    if (!conversation) {
      conversation = await prisma.conversation.create({
        data: { comprador_id, vendedor_id, producto_id },
      });
    }

    res.json(conversation);
  } catch (error) {
    console.error('Error al gestionar conversación:', error);
    res.status(500).json({ error: 'Error al obtener la conversación' });
  }
});

// Obtener historial de mensajes
app.get('/api/conversations/:id/messages', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const messages = await prisma.message.findMany({
      where: { conversation_id: id },
      orderBy: { created_at: 'asc' },
      include: { emisor: { select: { id: true, nombre: true } } },
    });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener los mensajes' });
  }
});

// --- 8. ENDPOINT DE CREACIÓN DE PEDIDOS Y GESTIÓN DE ENVÍO ---
app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { producto_id, metodo_envio, direccion } = req.body;
    const comprador_id = req.user.id;

    if (!producto_id || !metodo_envio) {
      return res.status(400).json({ error: 'Producto y método de envío son requeridos' });
    }

    const product = await prisma.product.findUnique({
      where: { id: producto_id },
    });

    if (!product) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    if (product.estado === 'VENDIDO') {
      return res.status(400).json({ error: 'El producto ya ha sido vendido' });
    }

    if (product.user_id === comprador_id) {
      return res.status(400).json({ error: 'No puedes comprar tu propio producto' });
    }

    const estado_envio =
      metodo_envio === 'DELIVERY'
        ? 'PENDIENTE_DE_ENVIO'
        : 'ACORDADO_PRESENCIAL';

    const [newOrder, updatedProduct] = await prisma.$transaction([
      prisma.order.create({
        data: {
          producto_id,
          comprador_id,
          vendedor_id: product.user_id,
          metodo_envio,
          estado_envio,
          monto_total: product.precio,
          direccion: metodo_envio === 'DELIVERY' ? direccion || 'Sin dirección provista' : null,
        },
      }),
      prisma.product.update({
        where: { id: producto_id },
        data: { estado: 'VENDIDO' },
      }),
    ]);

    res.status(201).json({
      message: 'Compra procesada exitosamente',
      order: newOrder,
      product: updatedProduct,
    });
  } catch (error) {
    console.error('Error al procesar la orden:', error);
    res.status(500).json({ error: 'Error al procesar la compra' });
  }
});

// --- 9. EVENTOS DE SOCKET.IO EN TIEMPO REAL ---
io.on('connection', (socket) => {
  console.log('Cliente conectado a Socket.IO:', socket.id);

  socket.on('join_room', (conversation_id) => {
    socket.join(conversation_id);
    console.log(`Socket ${socket.id} se unió a la sala: ${conversation_id}`);
  });

  socket.on('send_message', async (data) => {
    const { conversation_id, emisor_id, contenido } = data;

    try {
      const savedMessage = await prisma.message.create({
        data: {
          conversation_id,
          emisor_id,
          contenido,
        },
        include: { emisor: { select: { id: true, nombre: true } } },
      });

      io.to(conversation_id).emit('receive_message', savedMessage);
    } catch (error) {
      console.error('Error guardando o emitiendo mensaje:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('Cliente desconectado de Socket.IO:', socket.id);
  });
});

// Servidor escuchando peticiones HTTP y WebSockets
server.listen(PORT, () => {
  console.log(`Servidor HTTP y WebSockets corriendo en http://localhost:${PORT}`);
});