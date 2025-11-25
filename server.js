import express from "express";
import fs from "fs";
import bcrypt from "bcrypt";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

const app = express();
const PORT = process.env.PORT || 3000;

// ================================
// CONFIGURACIÓN Y MIDDLEWARE
// ================================
app.use(cors());
app.use(express.json());

const USERS_FILE = "./users.json";
const POINTS_FILE = "./points.json";
const ADMIN_KEY = "unitymap-admin-access";

// Crear archivos si no existen
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));
if (!fs.existsSync(POINTS_FILE)) fs.writeFileSync(POINTS_FILE, JSON.stringify([]));

// ================================
// FUNCIONES AUXILIARES
// ================================
const loadUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));
const saveUsers = (users) => fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
const findUser = (username) => loadUsers().find(u => u.username === username);

const loadPoints = () => JSON.parse(fs.readFileSync(POINTS_FILE));
const savePoints = (points) => fs.writeFileSync(POINTS_FILE, JSON.stringify(points, null, 2));

const requireAdminKey = (req, res) => {
  if (req.query.adminKey !== ADMIN_KEY) {
    res.status(403).json({ ok: false, msg: "No autorizado" });
    return false;
  }
  return true;
};

// ================================
// CREAR ADMIN POR DEFECTO
// ================================
(async () => {
  const users = loadUsers();
  if (!users.find(u => u.username === "admin")) {
    const hashed = await bcrypt.hash("12345", 10);
    users.push({ username: "admin", password: hashed, role: "admin" });
    saveUsers(users);
    console.log("Usuario admin creado (user: admin / pass: 12345)");
  }
})();

// ================================
// RUTAS DE USUARIOS
// ================================

// Registro
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ ok: false, msg: "Faltan datos" });

  const users = loadUsers();
  if (users.find(u => u.username === username))
    return res.status(400).json({ ok: false, msg: "El usuario ya existe" });

  const hashed = await bcrypt.hash(password, 10);
  users.push({ username, password: hashed, role: "user" });
  saveUsers(users);
  res.json({ ok: true, msg: "Usuario registrado correctamente" });
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) return res.status(400).json({ ok: false, msg: "Usuario no encontrado" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ ok: false, msg: "Contraseña incorrecta" });

  res.json({ ok: true, msg: "Login exitoso", role: user.role });
});

// Obtener rol
app.get("/getUserRole/:username", (req, res) => {
  const user = findUser(req.params.username);
  if (!user) return res.status(404).json({ ok: false, msg: "Usuario no existe" });
  res.json({ ok: true, role: user.role });
});

// Listar usuarios (solo admin)
app.get("/users", (req, res) => {
  if (!requireAdminKey(req, res)) return;
  const users = loadUsers().map(u => ({ username: u.username, role: u.role }));
  res.json({ ok: true, users });
});

// Eliminar usuario (solo admin)
app.delete("/user/:username", (req, res) => {
  if (!requireAdminKey(req, res)) return;

  const username = req.params.username;
  if (username === "admin") return res.status(400).json({ ok: false, msg: "No se puede eliminar el admin por defecto" });

  let users = loadUsers();
  if (!users.find(u => u.username === username))
    return res.status(404).json({ ok: false, msg: "Usuario no encontrado" });

  users = users.filter(u => u.username !== username);
  saveUsers(users);
  res.json({ ok: true, msg: `Usuario ${username} eliminado` });
});

// Cambiar rol (solo admin)
app.patch("/user/:username/role", (req, res) => {
  if (!requireAdminKey(req, res)) return;

  const { username } = req.params;
  const { role } = req.body;

  if (!["user", "admin"].includes(role)) return res.status(400).json({ ok: false, msg: "Rol inválido" });
  if (username === "admin") return res.status(400).json({ ok: false, msg: "No se puede cambiar el rol del admin por defecto" });

  const users = loadUsers();
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ ok: false, msg: "Usuario no encontrado" });

  user.role = role;
  saveUsers(users);
  res.json({ ok: true, msg: `Rol de ${username} cambiado a ${role}` });
});

// ================================
// RUTAS DE PUNTOS
// ================================

// Listar puntos (cualquiera)
app.get("/points", (req, res) => {
  const points = loadPoints();
  res.json({ ok: true, points });
});

// Crear punto
app.post("/points", (req, res) => {
  const { user, type, desc } = req.body;
  if (!user || !type || !desc) return res.status(400).json({ ok: false, msg: "Faltan datos" });

  const points = loadPoints();
  const newPoint = { id: uuidv4(), user, type, desc, createdAt: new Date().toISOString() };
  points.push(newPoint);
  savePoints(points);
  res.json({ ok: true, msg: "Punto agregado", point: newPoint });
});

// Eliminar punto individual (solo admin)
app.delete("/point/:id", (req, res) => {
  if (!requireAdminKey(req, res)) return;

  const { id } = req.params;
  let points = loadPoints();
  if (!points.find(p => p.id === id)) return res.status(404).json({ ok: false, msg: "Punto no encontrado" });

  points = points.filter(p => p.id !== id);
  savePoints(points);
  res.json({ ok: true, msg: "Punto eliminado" });
});

// Eliminar todos los puntos (solo admin)
app.delete("/points", (req, res) => {
  if (!requireAdminKey(req, res)) return;

  savePoints([]);
  res.json({ ok: true, msg: "Todos los puntos eliminados" });
});

// ================================
// RUTA RAÍZ
// ================================
app.get("/", (req, res) => res.send("Backend UnityMap funcionando"));

// ================================
// INICIAR SERVIDOR
// ================================
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
