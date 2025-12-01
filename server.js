import express from "express";
import bcrypt from "bcrypt";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import mongoose from "mongoose";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { OAuth2Client } from "google-auth-library";
import jwt from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

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
  user: String,
  type: String,
  desc: String,
  svgX: Number,
  svgY: Number,
  foto: String,
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
    await User.create({ username: "admin", password: hashed, role: "admin", foto: "" });
    console.log("Admin creado");
  }
})();

/* ============================
   MIDDLEWARE JWT
============================ */
const authenticateJWT = async (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Bearer <token>
  if (!token) return res.status(401).json({ ok:false, msg:"Token faltante" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.id);
    if (!user) return res.status(401).json({ ok:false, msg:"Usuario no encontrado" });
    req.user = user;
    next();
  } catch(err) {
    res.status(401).json({ ok:false, msg:"Token inválido" });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== "admin") return res.status(403).json({ ok:false, msg:"No eres admin" });
  next();
};

/* ============================
   UTIL
============================ */
const validateId = (id) => mongoose.Types.ObjectId.isValid(id);

/* ============================
   LOGIN NORMAL (JWT)
============================ */
app.post("/login", async (req,res)=>{
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if(!user) return res.json({ ok:false, msg:"Usuario no encontrado" });

  const valid = await bcrypt.compare(password, user.password);
  if(!valid) return res.json({ ok:false, msg:"Contraseña incorrecta" });

  const token = jwt.sign({ id:user._id, role:user.role }, JWT_SECRET, { expiresIn:"12h" });
  res.json({ ok:true, usuario:user, token });
});

/* ============================
   LOGIN GOOGLE
============================ */
app.post("/login-google", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ ok:false, msg:"Token de Google faltante" });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    let user = await User.findOne({ googleId: payload.sub });

    if (!user) {
      return res.json({ ok:true, newUser:true, googleId: payload.sub, foto: payload.picture });
    }

    const jwtToken = jwt.sign({ id:user._id, role:user.role }, JWT_SECRET, { expiresIn:"12h" });
    res.json({ ok:true, usuario:user, token: jwtToken });
  } catch (err) {
    res.status(500).json({ ok:false, msg: err.message });
  }
});

/* ============================
   REGISTER GOOGLE
============================ */
app.post("/auth/google-register", upload.single("pfp"), async (req,res)=>{
  try{
    const { username, googleId } = req.body;
    if(!username || !googleId) return res.status(400).json({ ok:false, msg:"Datos incompletos" });
    if(await User.findOne({ username })) return res.status(400).json({ ok:false, msg:"Usuario ya existe" });

    let fotoURL = "";
    if(req.file){
      const result = await new Promise((resolve,reject)=>{
        const stream = cloudinary.uploader.upload_stream({ folder:"unitymap/pfps" }, (err,r)=>err?reject(err):resolve(r));
        stream.end(req.file.buffer);
      });
      fotoURL = result.secure_url;
    }

    const user = await User.create({ username, role:"user", googleId, foto: fotoURL });
    const token = jwt.sign({ id:user._id, role:user.role }, JWT_SECRET, { expiresIn:"12h" });

    res.json({ ok:true, usuario:user, token });
  }catch(err){
    res.status(500).json({ ok:false, msg: err.message });
  }
});

/* ============================
   REGISTER NORMAL
============================ */
app.post("/auth/register", upload.single("pfp"), async (req,res)=>{
  try{
    const { username, password } = req.body;
    if(!username || !password) return res.status(400).json({ ok:false, msg:"Datos incompletos" });
    if(await User.findOne({ username })) return res.status(400).json({ ok:false, msg:"Usuario ya existe" });

    const hashed = await bcrypt.hash(password, 10);
    let fotoURL = "";
    if(req.file){
      const result = await new Promise((resolve,reject)=>{
        const stream = cloudinary.uploader.upload_stream({ folder:"unitymap/pfps" }, (err,r)=>err?reject(err):resolve(r));
        stream.end(req.file.buffer);
      });
      fotoURL = result.secure_url;
    }

    const user = await User.create({ username, password:hashed, role:"user", foto:fotoURL });
    const token = jwt.sign({ id:user._id, role:user.role }, JWT_SECRET, { expiresIn:"12h" });

    res.json({ ok:true, usuario:user, token });
  }catch(err){
    res.status(500).json({ ok:false, msg:err.message });
  }
});

/* ============================
   USERS (ADMIN ONLY)
============================ */
app.get("/users", authenticateJWT, isAdmin, async (req,res)=>{
  try{
    const users = await User.find({}, "-password");
    res.json({ ok:true, users });
  }catch(err){
    res.status(500).json({ ok:false, msg: err.message });
  }
});

app.delete("/users/:id", authenticateJWT, isAdmin, async (req,res)=>{
  const { id } = req.params;
  if(!validateId(id)) return res.status(400).json({ ok:false, msg:"ID inválido" });

  try{
    const user = await User.findById(id);
    if(!user) return res.status(404).json({ ok:false, msg:"Usuario no encontrado" });
    if(user.username === "admin") return res.status(403).json({ ok:false, msg:"No puedes eliminar al admin" });

    await User.findByIdAndDelete(id);
    res.json({ ok:true, msg:"Usuario eliminado" });
  }catch(err){
    res.status(500).json({ ok:false, msg: err.message });
  }
});

app.patch("/users/:id/role", authenticateJWT, isAdmin, async (req,res)=>{
  const { id } = req.params;
  const { role } = req.body;
  if(!validateId(id)) return res.status(400).json({ ok:false, msg:"ID inválido" });
  if(!["admin","user"].includes(role)) return res.status(400).json({ ok:false, msg:"Rol inválido" });

  try{
    const user = await User.findById(id);
    if(!user) return res.status(404).json({ ok:false, msg:"Usuario no encontrado" });
    if(user.username === "admin") return res.status(403).json({ ok:false, msg:"No puedes cambiar rol del admin" });

    user.role = role;
    await user.save();
    res.json({ ok:true, usuario:{ id:user._id, username:user.username, role:user.role } });
  }catch(err){
    res.status(500).json({ ok:false, msg: err.message });
  }
});

/* ============================
   POINTS
============================ */
app.post("/points", authenticateJWT, async (req,res)=>{
  const { type, desc, svgX, svgY } = req.body;
  if(!type || !desc || svgX==null || svgY==null) return res.status(400).json({ ok:false, msg:"Datos incompletos" });

  try{
    const newPoint = await Point.create({
      user:req.user.username,
      type,
      desc,
      svgX,
      svgY,
      foto,
      createdAt: new Date().toISOString()
    });
    res.json({ ok:true, point:newPoint });
  }catch(err){
    res.status(500).json({ ok:false, msg: err.message });
  }
});

app.get("/points", authenticateJWT, async (req,res)=>{
  try{
    const points = await Point.find();
    res.json({ ok:true, points });
  }catch(err){
    res.status(500).json({ ok:false, msg: err.message });
  }
});

app.patch("/point/:id", authenticateJWT, async (req,res)=>{
  const { id } = req.params;
  const { type, desc, svgX, svgY } = req.body;
  if(!validateId(id)) return res.status(400).json({ ok:false, msg:"ID inválido" });

  try{
    const point = await Point.findById(id);
    if(!point) return res.status(404).json({ ok:false, msg:"Punto no encontrado" });
    if(point.user !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ ok:false, msg:"No tienes permiso" });

    point.type = type;
    point.desc = desc;
    point.svgX = svgX;
    point.svgY = svgY;
    point.foto = foto;
    await point.save();

    res.json({ ok:true, point });
  }catch(err){
    res.status(500).json({ ok:false, msg: err.message });
  }
});

app.delete("/point/:id", authenticateJWT, async (req,res)=>{
  const { id } = req.params;
  if(!validateId(id)) return res.status(400).json({ ok:false, msg:"ID inválido" });

  try{
    const point = await Point.findById(id);
    if(!point) return res.status(404).json({ ok:false, msg:"Punto no encontrado" });
    if(point.user !== req.user.username && req.user.role !== "admin")
      return res.status(403).json({ ok:false, msg:"No tienes permiso" });

    await Point.findByIdAndDelete(id);
    res.json({ ok:true, msg:"Punto eliminado" });
  }catch(err){
    res.status(500).json({ ok:false, msg: err.message });
  }
});

app.delete("/points", authenticateJWT, isAdmin, async (req,res)=>{
  try{
    await Point.deleteMany({});
    res.json({ ok:true, msg:"Todos los puntos eliminados" });
  }catch(err){
    res.status(500).json({ ok:false, msg: err.message });
  }
});

/* ============================
   UPLOAD FOTO
============================ */
app.post("/upload-foto/:username", authenticateJWT, upload.single("pfp"), async (req,res)=>{
  if(req.user.username !== req.params.username && req.user.role!=="admin")
    return res.status(403).json({ ok:false, msg:"No tienes permiso" });

  if(!req.file) return res.status(400).json({ ok:false, msg:"Archivo faltante" });

  try{
    const result = await new Promise((resolve,reject)=>{
      const stream = cloudinary.uploader.upload_stream({ folder:"unitymap/pfps" }, (err,r)=>err?reject(err):resolve(r));
      stream.end(req.file.buffer);
    });

    req.user.foto = result.secure_url;
    await req.user.save();

    res.json({ ok:true, url: result.secure_url });
  }catch(err){
    res.status(500).json({ ok:false, msg: err.message });
  }
});

/* ============================
   ROOT
============================ */
app.get("/", (req,res)=>res.send("UnityMap Backend funcionando"));

/* ============================
   START
============================ */
app.listen(PORT,()=>console.log(`Servidor corriendo en puerto ${PORT}`));

