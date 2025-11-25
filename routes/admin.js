const express = require('express');
const router = express.Router();
const { verifyToken, requireAdmin } = require('../middlewares/auth');
const { User, Point } = require('../models'); // Ajusta según tus modelos

// Obtener todos los usuarios
router.get('/users', verifyToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({}, 'id email role'); // solo algunos campos
        res.json(users);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Error al obtener usuarios' });
    }
});

// Borrar todos los puntos
router.post('/delete-points', verifyToken, requireAdmin, async (req, res) => {
    try {
        await Point.deleteMany({});
        res.json({ ok: true, message: 'Todos los puntos eliminados' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Error al borrar puntos' });
    }
});

// (Opcional) Bloquear usuario por su ID
router.post('/block-user', verifyToken, requireAdmin, async (req, res) => {
    const { userId } = req.body;
    try {
        await User.updateOne({ _id: userId }, { blocked: true });
        res.json({ ok: true, message: 'Usuario bloqueado' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Error al bloquear usuario' });
    }
});

module.exports = router;
