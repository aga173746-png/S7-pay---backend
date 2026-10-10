const express=require("express");
const cors=require("cors");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const Database=require("better-sqlite3");

const app=express();
app.use(cors({origin:true}));
app.use(express.json());

const PORT=process.env.PORT||3000;
const JWT_SECRET=process.env.JWT_SECRET;
if(!JWT_SECRET){console.error("ERROR: Set JWT_SECRET environment variable.");process.exit(1);}

const db=new Database(process.env.DB_FILE||"s7pay.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS admins(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT,
 email TEXT UNIQUE,
 password_hash TEXT NOT NULL,
 balance REAL DEFAULT 0,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tasks(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 description TEXT DEFAULT '',
 reward REAL DEFAULT 0,
 active INTEGER DEFAULT 1,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS withdrawals(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 amount REAL NOT NULL,
 status TEXT DEFAULT 'pending',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

function auth(req,res,next){
 const h=req.headers.authorization||"";
 if(!h.startsWith("Bearer "))return res.status(401).json({error:"Unauthorized"});
 try{req.admin=jwt.verify(h.slice(7),JWT_SECRET);next()}
 catch(e){return res.status(401).json({error:"Invalid or expired token"})}
}

app.get("/api/health",(req,res)=>res.json({ok:true}));
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Name, email and password are required"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const exists = db.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).get(normalizedEmail);

    if (exists) {
      return res.status(409).json({
        error: "Email already registered"
      });
    }

    const passwordHash = bcrypt.hashSync(password, 12);

    const result = db.prepare(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)"
    ).run(name.trim(), normalizedEmail, passwordHash);

    return res.status(201).json({
      ok: true,
      message: "Registration successful",
      userId: result.lastInsertRowid
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      error: "Registration failed"
    });
  }
});

// First-admin setup. Protect this with SETUP_KEY and disable it after first admin exists.
app.post("/api/admin/setup",(req,res)=>{
 const setupKey=process.env.SETUP_KEY;
 if(!setupKey || req.headers["x-setup-key"]!==setupKey)
   return res.status(403).json({error:"Admin setup is disabled or setup key is incorrect"});
 const {email,password}=req.body||{};
 if(!email||!password||password.length<10)return res.status(400).json({error:"Email and a password of at least 10 characters are required"});
 const exists=db.prepare("SELECT id FROM admins LIMIT 1").get();
 if(exists)return res.status(409).json({error:"An admin already exists"});
 try{
  const hash=bcrypt.hashSync(password,12);
  db.prepare("INSERT INTO admins(email,password_hash) VALUES(?,?)").run(email.trim().toLowerCase(),hash);
  res.json({ok:true,message:"Admin created. You can now login."});
 }catch(e){res.status(400).json({error:"Could not create admin"})}
});

app.post("/api/admin/login",(req,res)=>{
 const {email,password}=req.body||{};
 const a=db.prepare("SELECT * FROM admins WHERE email=?").get((email||"").trim().toLowerCase());
 if(!a||!bcrypt.compareSync(password||"",a.password_hash))return res.status(401).json({error:"Invalid email or password"});
 const token=jwt.sign({id:a.id,email:a.email},JWT_SECRET,{expiresIn:"12h"});
 res.json({token});
});

app.get("/api/admin/dashboard",auth,(req,res)=>{
 const users=db.prepare("SELECT COUNT(*) c FROM users").get().c;
 const tasks=db.prepare("SELECT COUNT(*) c FROM tasks WHERE active=1").get().c;
 const pendingWithdrawals=db.prepare("SELECT COUNT(*) c FROM withdrawals WHERE status='pending'").get().c;
 res.json({users,tasks,pendingWithdrawals});
});

app.get("/api/admin/tasks",auth,(req,res)=>{
 res.json({tasks:db.prepare("SELECT * FROM tasks ORDER BY id DESC").all()});
});

app.post("/api/admin/tasks",auth,(req,res)=>{
 const {title,description="",reward=0}=req.body||{};
 if(!title)return res.status(400).json({error:"Title required"});
 const r=db.prepare("INSERT INTO tasks(title,description,reward) VALUES(?,?,?)").run(title,description,Number(reward)||0);
 res.json({id:r.lastInsertRowid});
});

app.patch("/api/admin/tasks/:id",auth,(req,res)=>{
 const {active}=req.body||{};
 db.prepare("UPDATE tasks SET active=? WHERE id=?").run(active?1:0,Number(req.params.id));
 res.json({ok:true});
});

app.get("/api/admin/withdrawals",auth,(req,res)=>{
 res.json({withdrawals:db.prepare("SELECT * FROM withdrawals ORDER BY id DESC").all()});
});

app.patch("/api/admin/withdrawals/:id",auth,(req,res)=>{
 const {status}=req.body||{};
 if(!["approved","rejected","pending"].includes(status))return res.status(400).json({error:"Invalid status"});
 const r=db.prepare("UPDATE withdrawals SET status=? WHERE id=?").run(status,Number(req.params.id));
 if(!r.changes)return res.status(404).json({error:"Withdrawal not found"});
 res.json({ok:true});
});

app.listen(PORT,()=>console.log(`S7 Pay backend running on port ${PORT}`));
