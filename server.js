import express from "express";
import fs from "fs";
import bcrypt from "bcrypt";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Archivo donde se guardarán los usuarios
const DB_FILE = "./users.json";

// Crear archivo si no existe
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify([]));
}

// Leer usuarios
function loadUsers() {
  return JSON.parse(fs.readFileSync(DB_FILE));
}

// Guardar usuarios
function saveUsers(users) {
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

/* =====================================================
    CREAR ADMIN POR DEFECTO SI NO EXISTE
======================================================*/
(async () => {
  let users = loadUsers();
  const admin = users.find(u => u.username === "admin");

  if (!admin) {
    const hashed = await bcrypt.hash("12345", 10);
    users.push({
      username: "admin",
      password: hashed,
      role: "admin"
    });
    saveUsers(users);
    console.log("Usuario admin creado (user: admin / pass: 12345)");
  }
})();

/* =====================================================
      REGISTRO
======================================================*/
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ ok: false, msg: "Faltan datos" });

  const users = loadUsers();

  if (users.find(u => u.username === username)) {
    return res.status(400).json({ ok: false, msg: "El usuario ya existe" });
  }

  const hashed = await bcrypt.hash(password, 10);

  users.push({
    username,
    password: hashed,
    role: "user" // por defecto
  });

  saveUsers(users);

  res.json({ ok: true, msg: "Usuario registrado correctamente" });
});

/* =====================================================
        LOGIN
======================================================*/
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const users = loadUsers();
  const user = users.find(u => u.username === username);

  if (!user)
    return res.status(400).json({ ok: false, msg: "Usuario no encontrado" });

  const valid = await bcrypt.compare(password, user.password);

  if (!valid)
    return res.status(400).json({ ok: false, msg: "Contraseña incorrecta" });

  res.json({
    ok: true,
    msg: "Login exitoso",
    role: user.role
  });
});

/* =====================================================
      OBTENER ROL DE USUARIO
======================================================*/
app.get("/getUserRole/:username", (req, res) => {
  const { username } = req.params;

  const users = loadUsers();
  const user = users.find(u => u.username === username);

  if (!user)
    return res.status(404).json({ ok: false, msg: "Usuario no existe" });

  res.json({ ok: true, role: user.role });
});

/* =====================================================
      LISTA DE USUARIOS (solo admin)
======================================================*/
app.get("/users", (req, res) => {
  const { adminKey } = req.query;

  if (adminKey !== "unitymap-admin-access")
    return res.status(403).json({ ok: false, msg: "No autorizado" });

  const users = loadUsers().map(u => ({
    username: u.username,
    role: u.role
  }));

  res.json({ ok: true, users });
});

/* =====================================================
  ELIMINAR USUARIO (solo admin)
======================================================*/
app.delete("/user/:username", (req, res) => {
  const { adminKey } = req.query;
  const { username } = req.params;

  if (adminKey !== "unitymap-admin-access") {
    return res.status(403).json({ ok: false, msg: "No autorizado" });
  }

  if (username === "admin") {
    return res.status(400).json({ ok: false, msg: "No se puede eliminar el admin por defecto" });
  }

  let users = loadUsers();
  users = users.filter(u => u.username !== username);
  saveUsers(users);

  res.json({ ok: true, msg: `Usuario ${username} eliminado` });
});

/* =====================================================
  CAMBIAR ROL (solo admin)
======================================================*/
app.patch("/user/:username/role", (req, res) => {
  const { adminKey } = req.query;
  const { username } = req.params;
  const { role } = req.body;

  if (adminKey !== "unitymap-admin-access") {
    return res.status(403).json({ ok: false, msg: "No autorizado" });
  }

  if (!["user", "admin"].includes(role)) {
    return res.status(400).json({ ok: false, msg: "Rol inválido" });
  }

  if (username === "admin") {
    return res.status(400).json({ ok: false, msg: "No se puede cambiar el rol del admin por defecto" });
  }

  const users = loadUsers();
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ ok: false, msg: "Usuario no encontrado" });

  user.role = role;
  saveUsers(users);

  res.json({ ok: true, msg: `Rol de ${username} cambiado a ${role}` });
});

/* =====================================================
      INICIAR SERVIDOR
======================================================*/
app.get("/", (req, res) => {
  res.send("Backend UnityMap funcionando");
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});


