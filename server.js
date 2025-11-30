import express from "express";
import bcrypt from "bcrypt";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import mongoose from "mongoose";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { OAuth2Client } from "google-auth-library";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

/* ============================
   GOOGLE CLIENT
============================ */
if (!process.env.GOOGLE_CLIENT_ID) {
  throw new Error("GOOGLE_CLIENT_ID no está definido en Render");
}

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

/* ============================
   MONGODB
============================ */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB conectado"))
  .catch(err => console.error("Error MongoDB:", err));

/* ============================
   CLOUDINARY
============================ */
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_KEY,
  api_secret: process.env.CLOUD_SECRET
});

/* ============================
   MULTER
============================ */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 3 * 1024 * 1024 }
});

/* ============================
   MODELOS
============================ */
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: String,
  foto: String,
  googleId: String
});

const PointSchema = new mongoose.Schema({
  pointId: String,
  user: String,
  type: String,
  desc: String,
  svgX: Number,
  svgY: Number,
  createdAt: String
});

const User = mongoose.model("User", UserSchema);
const Point = mongoose.model("Point", PointSchema);

/* ============================
   ADMIN DEFAULT
============================ */
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
    console.log("Admin creado");
  }
})();

/* ============================
   LOGIN GOOGLE (REAL)
============================ */
app.post("/login-google", async (req, res) => {
  try {
    const { token } = req.body;

    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const googleId = payload.sub;
    const email = payload.email;
    const googleFoto = payload.picture || "";

    let user = await User.findOne({ googleId });

    if (!user) {
      return res.json({
        ok: true,
        newUser: true,
        email,
        googleFoto,
        googleId
      });
    }

    res.json({
      ok: true,
      newUser: false,
      usuario: {
        id: user._id,
        username: user.username,
        role: user.role,
        foto: user.foto || googleFoto,
        googleId: user.googleId
      }
    });

  } catch (err) {
    console.error("LOGIN GOOGLE ERROR:", err);
    res.status(401).json({ ok: false, msg: "Token inválido" });
  }
});

/* ============================
   REGISTRO GOOGLE
============================ */
app.post("/auth/google-register", upload.single("pfp"), async (req, res) => {
  try {
    const { username, googleId } = req.body;
    if (!username || !googleId) {
      return res.status(400).json({ ok: false, msg: "Datos incompletos" });
    }

    const exists = await User.findOne({ username });
    if (exists) {
      return res.status(400).json({ ok: false, msg: "Usuario ya existe" });
    }

    let fotoURL = "";

    if (req.file) {
      const stream = cloudinary.uploader.upload_stream(
        { folder: "unitymap/pfps" },
        async (error, result) => {
          if (error) return res.status(500).json({ ok: false, msg: error.message });

          fotoURL = result.secure_url;

          const user = await User.create({
            username,
            googleId,
            role: "user",
            password: "",
            foto: fotoURL
          });

          return res.json({
            ok: true,
            usuario: {
              id: user._id,
              username: user.username,
              role: user.role,
              foto: user.foto,
              googleId: user.googleId
            }
          });
        }
      );

      stream.end(req.file.buffer);
      return;
    }

    const user = await User.create({
      username,
      googleId,
      role: "user",
      password: "",
      foto: ""
    });

    res.json({
      ok: true,
      usuario: {
        id: user._id,
        username: user.username,
        role: user.role,
        foto: user.foto,
        googleId: user.googleId
      }
    });

  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

/* ============================
   REGISTER NORMAL
============================ */
app.post("/register", upload.single("pfp"), async (req, res) => {
  try {
    const { username, password } = req.body;

    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ ok: false, msg: "Usuario ya existe" });

    const hashed = await bcrypt.hash(password, 10);
    let fotoURL = "";

    if (req.file) {
      const stream = cloudinary.uploader.upload_stream(
        { folder: "unitymap/pfps" },
        async (error, result) => {
          if (error) return res.status(500).json({ ok: false, msg: error.message });

          fotoURL = result.secure_url;

          const user = await User.create({
            username,
            password: hashed,
            role: "user",
            foto: fotoURL
          });

          return res.json({ ok: true, usuario: user });
        }
      );

      stream.end(req.file.buffer);
      return;
    }

    const user = await User.create({
      username,
      password: hashed,
      role: "user",
      foto: ""
    });

    res.json({ ok: true, usuario: user });

  } catch (err) {
    res.status(500).json({ ok: false, msg: err.message });
  }
});

/* ============================
   LOGIN NORMAL
============================ */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.json({ ok: false });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.json({ ok: false });

  res.json({ ok: true, usuario: user });
});

/* ============================
   POINTS
============================ */
app.post("/points", async (req, res) => {
  const { user, type, desc, svgX, svgY } = req.body;

  const newPoint = await Point.create({
    pointId: uuidv4(),
    user,
    type,
    desc,
    svgX,
    svgY,
    createdAt: new Date().toISOString()
  });

  res.json({ ok: true, point: newPoint });
});

app.get("/points", async (req, res) => {
  const points = await Point.find();
  res.json({ ok: true, points });
});

/* ============================
   ROOT
============================ */
app.get("/", (req, res) => {
  res.send("UnityMap Backend funcionando");
});

/* ============================
   START
============================ */
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
