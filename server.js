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

/* ==============================
      REGISTRO
===============================*/
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ ok: false, msg: "Faltan datos" });

  const users = loadUsers();

  if (users.find(u => u.username === username)) {
    return res.status(400).json({ ok: false, msg: "El usuario ya existe" });
  }

  const hashed = await bcrypt.hash(password, 10);
  users.push({ username, password: hashed });
  saveUsers(users);

  res.json({ ok: true, msg: "Usuario registrado correctamente" });
});

/* ==============================
        LOGIN
===============================*/
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const users = loadUsers();
  const user = users.find(u => u.username === username);

  if (!user)
    return res.status(400).json({ ok: false, msg: "Usuario no encontrado" });

  const valid = await bcrypt.compare(password, user.password);

  if (!valid)
    return res.status(400).json({ ok: false, msg: "Contraseña incorrecta" });

  res.json({ ok: true, msg: "Login exitoso" });
});

/* ==============================
      INICIAR SERVIDOR
===============================*/
app.get("/", (req, res) => {
  res.send("Backend UnityMap funcionando");
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
