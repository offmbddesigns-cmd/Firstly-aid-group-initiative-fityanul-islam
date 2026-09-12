const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET || 'change-this-session-secret', resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' } }));
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false });

async function init(){
  await pool.query(`CREATE TABLE IF NOT EXISTS members (
    id SERIAL PRIMARY KEY, member_id VARCHAR(30) UNIQUE NOT NULL, full_name TEXT NOT NULL,
    phone VARCHAR(40), email TEXT, state TEXT, lga TEXT, gender VARCHAR(30), date_of_birth DATE,
    address TEXT, emergency_contact TEXT, emergency_phone VARCHAR(40), blood_group VARCHAR(10),
    qualification TEXT, first_aid_level TEXT, unit TEXT, photo_url TEXT, status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW(), approved_at TIMESTAMPTZ
  );
  CREATE TABLE IF NOT EXISTS admins (
    id SERIAL PRIMARY KEY, username VARCHAR(80) UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    role VARCHAR(30) DEFAULT 'approver', created_at TIMESTAMPTZ DEFAULT NOW()
  );`);
  const {rows} = await pool.query('SELECT COUNT(*)::int AS n FROM admins');
  if(rows[0].n === 0){
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'FityanulAdmin2026!', 12);
    await pool.query('INSERT INTO admins(username,password_hash,role) VALUES($1,$2,$3)', [process.env.ADMIN_USERNAME || 'admin', hash, 'super_admin']);
  }
}
const adminOnly=(req,res,next)=> req.session.admin ? next() : res.status(401).json({error:'Admin login required'});
function newId(){ return 'FNI-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2,6).toUpperCase(); }

app.get('/api/health',(req,res)=>res.json({ok:true}));
app.post('/api/register', async(req,res)=>{
  try{
    const {full_name,phone,email,state,lga,gender,date_of_birth,address,emergency_contact,emergency_phone,blood_group,qualification,first_aid_level,unit,photo_url}=req.body;
    if(!full_name) return res.status(400).json({error:'Full name is required'});
    const member_id=newId();
    await pool.query(`INSERT INTO members(member_id,full_name,phone,email,state,lga,gender,date_of_birth,address,emergency_contact,emergency_phone,blood_group,qualification,first_aid_level,unit,photo_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,[member_id,full_name,phone,email,state,lga,gender,date_of_birth||null,address,emergency_contact,emergency_phone,blood_group,qualification,first_aid_level,unit,photo_url]);
    res.json({ok:true,member_id,message:'Registration submitted successfully. Your application is awaiting approval.'});
  }catch(e){console.error(e);res.status(500).json({error:'Unable to submit registration'});}
});
app.get('/api/member/:id',async(req,res)=>{try{const {rows}=await pool.query('SELECT member_id,full_name,phone,email,state,lga,gender,date_of_birth,address,emergency_contact,emergency_phone,blood_group,qualification,first_aid_level,unit,photo_url,status,created_at,approved_at FROM members WHERE member_id=$1 AND status=$2',[req.params.id,'approved']); if(!rows[0]) return res.status(404).json({error:'Approved member not found'});res.json(rows[0]);}catch(e){res.status(500).json({error:'Search failed'});}});
app.post('/api/admin/login',async(req,res)=>{try{const {username,password}=req.body;const {rows}=await pool.query('SELECT * FROM admins WHERE username=$1',[username]);if(!rows[0]||!(await bcrypt.compare(password,rows[0].password_hash)))return res.status(401).json({error:'Invalid username or password'});req.session.admin={id:rows[0].id,username:rows[0].username,role:rows[0].role};res.json({ok:true,admin:req.session.admin});}catch(e){res.status(500).json({error:'Login failed'});}});
app.post('/api/admin/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/admin/me',adminOnly,(req,res)=>res.json(req.session.admin));
app.get('/api/admin/members',adminOnly,async(req,res)=>{try{const status=req.query.status||'pending';const q=status==='all'?'SELECT * FROM members ORDER BY created_at DESC':'SELECT * FROM members WHERE status=$1 ORDER BY created_at DESC';const {rows}=status==='all'?await pool.query(q):await pool.query(q,[status]);res.json(rows);}catch(e){res.status(500).json({error:'Unable to load members'});}});
app.patch('/api/admin/members/:id',adminOnly,async(req,res)=>{try{const {status}=req.body;if(!['approved','rejected','pending'].includes(status))return res.status(400).json({error:'Invalid status'});const {rows}=await pool.query('UPDATE members SET status=$1, approved_at=CASE WHEN $1=\'approved\' THEN NOW() ELSE approved_at END WHERE id=$2 RETURNING *',[status,req.params.id]);if(!rows[0])return res.status(404).json({error:'Member not found'});res.json(rows[0]);}catch(e){res.status(500).json({error:'Update failed'});}});
app.post('/api/admin/admins',adminOnly,async(req,res)=>{try{if(req.session.admin.role!=='super_admin')return res.status(403).json({error:'Super admin only'});const {username,password,role='approver'}=req.body;if(!username||!password)return res.status(400).json({error:'Username and password are required'});const hash=await bcrypt.hash(password,12);await pool.query('INSERT INTO admins(username,password_hash,role) VALUES($1,$2,$3)',[username,hash,role]);res.json({ok:true});}catch(e){res.status(400).json({error:'Could not create admin; username may already exist'});}});

const PORT=process.env.PORT||10000;
init().then(()=>app.listen(PORT,()=>console.log('Fityanul Islam portal running on '+PORT))).catch(e=>{console.error(e);process.exit(1)});
