const requireAdminOrLogistics = (req, res, next) => {
  const rol = req.user?.tipo_usuario ? String(req.user.tipo_usuario).toUpperCase() : '';

  if (rol !== 'ADMIN' && rol !== 'LOGISTICA') {
    return res.status(403).json({
      error: 'Acceso denegado: Se requieren permisos de administración o logística',
    });
  }
  next();
};

module.exports = requireAdminOrLogistics;