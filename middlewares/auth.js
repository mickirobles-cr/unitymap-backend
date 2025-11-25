const jwt = require('jsonwebtoken');
const { User } = require('../models'); // Ajusta según tu modelo

const SECRET = process.env.JWT_SECRET;

function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });

    jwt.verify(token, SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = decoded; // decoded debe contener información del usuario
        next();
    });
}

function requireAdmin(req, res, next) {
    // req.user debe tener role
    if (!req.user) return res.status(403).json({ error: 'No autorizado' });
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Acceso solo para admin' });
    }
    next();
}

module.exports = { verifyToken, requireAdmin };
