import express from "express";
import bcrypt from "bcrypt";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import mongoose from "mongoose";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";

const app = express();
const PORT = process.env.PORT || 3000;

// ================================
// MIDDLEWARE
// ================================
app.use(cors());
app.use(express.json());

// ================================
// MONGODB
// ================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB conectado"))
  .catch(err => console.error("Error MongoDB:", err));

// ================================
// CLOUDINARY
// ================================
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_KEY,
  api_secret: process.env.CLOUD_SECRET
});

const upload = multer({ dest: "/tmp" });

// ================================
// MODELOS
// ================================
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: String,
  foto: String
});

const PointSchema = new mongoose.Schema({
  pointId: String,
  user: String,
  type: String,
  desc: String,
  createdAt: String
});

const User = mongoose.model("User", UserSchema);
const Point = mongoose.model("Point", PointSchema);

// ================================
// CREAR ADMIN SI NO EXISTE
// ================================
(async () => {
  const adminExists = await User.findOne({ username: "admin" });
  if (!adminExists) {
    const hashed = await bcrypt.hash("12345", 10);
    await User.create({
      username: "admin",
      password: hashed,
      role: "admin",
      foto: ""
    });
    console.log("Admin creado (admin / 12345)");
  }
})();

// ================================
// AUTH
// ================================
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ ok: false, msg: "Faltan datos" });

    const exists = await User.findOne({ username });
    if (exists)
      return res.status(400).json({ ok: false, msg: "Usuario ya existe" });

    const hashed = await bcrypt.hash(password, 10);

    await User.create({
      username,
      password: hashed,
      role: "user",
      foto: ""
    });

    res.json({ ok: true, msg: "Usuario registrado" });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user)
      return res.status(400).json({ ok: false, msg: "Usuario no encontrado" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(400).json({ ok: false, msg: "Contraseña incorrecta" });

    res.json({
      ok: true,
      usuario: {
        id: user._id,
        username: user.username,
        role: user.role,
        foto: user.foto || ""
      }
    });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ================================
// SUBIR FOTO DE PERFIL
// ================================
app.post("/upload-foto/:username", upload.single("foto"), async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) return res.status(404).json({ ok: false });

    const result = await cloudinary.uploader.upload(req.file.path);
    user.foto = result.secure_url;
    await user.save();

    res.json({ ok: true, foto: result.secure_url });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ================================
// USERS (ADMIN)
// ================================
app.get("/users", async (req, res) => {
  const users = await User.find({}, { password: 0 });
  res.json({ ok: true, users });
});

// ================================
// ADMIN - ELIMINAR USUARIO
// ================================
app.delete("/user/:username", async (req, res) => {
  try {
    const { username } = req.params;
    if (username === "admin") {
      return res.status(403).json({ ok: false, msg: "No puedes borrar al admin" });
    }

    await User.deleteOne({ username });
    await Point.deleteMany({ user: username });

    res.json({ ok: true, msg: "Usuario eliminado" });
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

// ================================
// ADMIN - CAMBIAR ROL
// ================================
app.patch("/user/:username/role", async (req, res) => {
  try {
    const { role } = req.body;
    await User.updateOne({ username: req.params.username }, { role });
    res.json({ ok: true, msg: "Rol actualizado" });
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

// ================================
// ADMIN - BORRAR TODOS LOS PUNTOS
// ================================
app.delete("/points", async (req, res) => {
  try {
    await Point.deleteMany({});
    res.json({ ok: true, msg: "Todos los puntos eliminados" });
  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});


// ================================
// POINTS
// ================================
app.get("/points", async (req, res) => {
  const points = await Point.find();
  res.json({ ok: true, points });
});

app.post("/points", async (req, res) => {
  try {
    const { user, type, desc } = req.body;

    const newPoint = await Point.create({
      pointId: uuidv4(),
      user,
      type,
      desc,
      createdAt: new Date().toISOString()
    });

    res.json({ ok: true, point: newPoint });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete("/point/:id", async (req, res) => {
  await Point.deleteOne({ pointId: req.params.id });
  res.json({ ok: true });
});

// ================================
// ROOT
// ================================
app.get("/", (req, res) => {
  res.send("UnityMap Backend funcionando");
});

// ================================
// SERVIDOR
// ================================
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});



