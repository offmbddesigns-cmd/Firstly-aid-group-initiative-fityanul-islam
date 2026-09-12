const express=require('express');
const session=require('express-session');
const {Pool}=require('pg');
const bcrypt=require('bcryptjs');
const crypto=require('crypto');
const path=require('path');
const app=express();

app.use(express.json({limit:'4mb'}));
app.use(express.urlencoded({extended:true,limit:'4mb'}));
app.use(session({secret:process.env.SESSION_SECRET||'change-this-session-secret',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:1000*60*60*8}}));
app.use(express.static(path.join(__dirname,'public')));

const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?{rejectUnauthorized:false}:false});
let dbReady=false;

async function init(){
  if(!process.env.DATABASE_URL)throw Error('DATABASE_URL is not configured');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS members(
      id SERIAL PRIMARY KEY,member_id VARCHAR(30) UNIQUE NOT NULL,full_name TEXT NOT NULL,phone VARCHAR(40),email TEXT,
      state TEXT,lga TEXT,gender VARCHAR(30),date_of_birth DATE,address TEXT,emergency_contact TEXT,emergency_phone VARCHAR(40),
      blood_group VARCHAR(10),qualification TEXT,first_aid_level TEXT,unit TEXT,year_of_entry VARCHAR(10),rank TEXT,
      office_description TEXT,photo_url TEXT,status VARCHAR(20) DEFAULT 'pending',created_at TIMESTAMPTZ DEFAULT NOW(),approved_at TIMESTAMPTZ,
      last_login_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS admins(id SERIAL PRIMARY KEY,username VARCHAR(80) UNIQUE NOT NULL,password_hash TEXT NOT NULL,role VARCHAR(30) DEFAULT 'approver',created_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS member_login_codes(id SERIAL PRIMARY KEY,member_id INTEGER REFERENCES members(id) ON DELETE CASCADE,code_hash TEXT NOT NULL,expires_at TIMESTAMPTZ NOT NULL,attempts INTEGER DEFAULT 0,used_at TIMESTAMPTZ,created_at TIMESTAMPTZ DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS audit_logs(id SERIAL PRIMARY KEY,admin_id INTEGER REFERENCES admins(id) ON DELETE SET NULL,action VARCHAR(80) NOT NULL,member_id INTEGER REFERENCES members(id) ON DELETE SET NULL,details TEXT,created_at TIMESTAMPTZ DEFAULT NOW());
  `);
  await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ`);
  const {rows}=await pool.query('SELECT COUNT(*)::int n FROM admins');
  if(rows[0].n===0){
    const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD||'FityanulAdmin2026!',12);
    await pool.query('INSERT INTO admins(username,password_hash,role) VALUES($1,$2,$3)',[process.env.ADMIN_USERNAME||'admin',hash,'super_admin']);
  }
  dbReady=true;console.log('Database ready');
}
init().catch(e=>console.error('Database initialization pending:',e.message));

const db=(req,res,next)=>dbReady?next():res.status(503).json({error:'Database is still connecting. Please try again shortly.'});
const admin=(req,res,next)=>req.session.admin?next():res.status(401).json({error:'Admin login required'});
const memberAuth=(req,res,next)=>req.session.member?next():res.status(401).json({error:'Member login required'});
function newId(){return'FNI-'+Date.now().toString(36).toUpperCase()+'-'+Math.random().toString(36).slice(2,6).toUpperCase()}
function normalizeEmail(v){return String(v||'').trim().toLowerCase()}
function codeHash(code){return crypto.createHash('sha256').update(String(code)).digest('hex')}
function newCode(){return String(crypto.randomInt(100000,1000000))}
async function audit(req,action,memberId,details=''){try{await pool.query('INSERT INTO audit_logs(admin_id,action,member_id,details) VALUES($1,$2,$3,$4)',[req.session.admin?.id||null,action,memberId||null,details])}catch(e){console.error('Audit error:',e.message)}}
async function sendMemberCode(email,name,code){
  if(!process.env.RESEND_API_KEY||!process.env.RESEND_FROM_EMAIL)throw Error('Member email service is not configured');
  const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+process.env.RESEND_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({from:process.env.RESEND_FROM_EMAIL,to:[email],subject:'Your Fityanul Islam member login code',html:`<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto"><h2>First Aid Group Initiative</h2><p>Assalamu alaikum ${name},</p><p>Your member login verification code is:</p><div style="font-size:34px;font-weight:700;letter-spacing:8px;padding:18px;background:#f1f7f3;text-align:center">${code}</div><p>This code expires in 10 minutes and can only be used once.</p><p>If you did not request this code, you can ignore this email.</p></div>`})});
  if(!r.ok)throw Error('Unable to send verification email');
}

app.get('/api/health',(req,res)=>res.json({ok:true,database:dbReady,email_service:!!(process.env.RESEND_API_KEY&&process.env.RESEND_FROM_EMAIL)}));

app.post('/api/register',db,async(req,res)=>{try{
  const d=req.body;const email=normalizeEmail(d.email);
  if(!d.full_name)return res.status(400).json({error:'Full name is required'});
  if(!email)return res.status(400).json({error:'Email is required for member login'});
  if(!d.photo_url)return res.status(400).json({error:'Passport photograph is required'});
  const duplicate=await pool.query('SELECT id FROM members WHERE lower(email)=lower($1) AND status<>$2 LIMIT 1',[email,'rejected']);
  if(duplicate.rows[0])return res.status(409).json({error:'This email is already registered. Please contact an administrator.'});
  const id=newId();
  await pool.query(`INSERT INTO members(member_id,full_name,phone,email,state,lga,gender,date_of_birth,address,emergency_contact,emergency_phone,blood_group,qualification,first_aid_level,unit,year_of_entry,photo_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,[id,d.full_name,d.phone,email,d.state,d.lga,d.gender,d.date_of_birth||null,d.address,d.emergency_contact,d.emergency_phone,d.blood_group,d.qualification,d.first_aid_level,d.unit,d.year_of_entry,d.photo_url]);
  res.json({ok:true,member_id:id,message:'Registration submitted. Wait for admin approval.'});
}catch(e){console.error(e);res.status(500).json({error:'Unable to submit registration'})}});

// Public verification intentionally exposes only non-sensitive identity/organization fields.
app.get('/api/member/:id',db,async(req,res)=>{try{
  const {rows}=await pool.query(`SELECT member_id,full_name,photo_url,status,rank,unit,year_of_entry,office_description FROM members WHERE member_id=$1 AND status='approved'`,[req.params.id]);
  if(!rows[0])return res.status(404).json({error:'Approved member not found'});res.json(rows[0]);
}catch(e){res.status(500).json({error:'Search failed'})}});

// Member login: full name + email -> one-time email code.
app.post('/api/member/request-code',db,async(req,res)=>{try{
  const fullName=String(req.body.full_name||'').trim();const email=normalizeEmail(req.body.email);
  if(!fullName||!email)return res.status(400).json({error:'Full name and email are required'});
  const {rows}=await pool.query(`SELECT * FROM members WHERE lower(email)=lower($1) AND lower(full_name)=lower($2) AND status='approved' LIMIT 1`,[email,fullName]);
  if(!rows[0])return res.status(401).json({error:'Approved member account not found. Check your full name and email.'});
  await pool.query('UPDATE member_login_codes SET used_at=NOW() WHERE member_id=$1 AND used_at IS NULL',[rows[0].id]);
  const code=newCode();await pool.query('INSERT INTO member_login_codes(member_id,code_hash,expires_at) VALUES($1,$2,NOW()+INTERVAL \'10 minutes\')',[rows[0].id,code]);
  await sendMemberCode(email,rows[0].full_name,code);
  res.json({ok:true,message:'A verification code has been sent to your email.'});
}catch(e){console.error(e);res.status(503).json({error:e.message.includes('email service')?e.message:'Unable to send login code. Please try again.'})}});

app.post('/api/member/verify-code',db,async(req,res)=>{try{
  const email=normalizeEmail(req.body.email);const fullName=String(req.body.full_name||'').trim();const code=String(req.body.code||'').trim();
  if(!email||!fullName||!/^\d{6}$/.test(code))return res.status(400).json({error:'Enter the 6-digit code sent to your email.'});
  const member=await pool.query(`SELECT * FROM members WHERE lower(email)=lower($1) AND lower(full_name)=lower($2) AND status='approved' LIMIT 1`,[email,fullName]);
  if(!member.rows[0])return res.status(401).json({error:'Member account not found'});
  const m=member.rows[0];const q=await pool.query(`SELECT * FROM member_login_codes WHERE member_id=$1 AND used_at IS NULL AND expires_at>NOW() ORDER BY created_at DESC LIMIT 1`,[m.id]);
  if(!q.rows[0])return res.status(401).json({error:'Code expired. Request a new code.'});
  const record=q.rows[0];if(record.attempts>=5)return res.status(429).json({error:'Too many attempts. Request a new code.'});
  if(codeHash(code)!==record.code_hash){await pool.query('UPDATE member_login_codes SET attempts=attempts+1 WHERE id=$1',[record.id]);return res.status(401).json({error:'Incorrect verification code.'})}
  await pool.query('UPDATE member_login_codes SET used_at=NOW() WHERE id=$1',[record.id]);await pool.query('UPDATE members SET last_login_at=NOW() WHERE id=$1',[m.id]);
  req.session.member={id:m.id,member_id:m.member_id,full_name:m.full_name};res.json({ok:true});
}catch(e){res.status(500).json({error:'Login verification failed'})}});

app.get('/api/member/me',memberAuth,db,async(req,res)=>{try{
  const {rows}=await pool.query(`SELECT id,member_id,full_name,phone,email,state,lga,gender,date_of_birth,address,emergency_contact,emergency_phone,blood_group,qualification,first_aid_level,unit,year_of_entry,rank,office_description,photo_url,status,created_at,approved_at,last_login_at FROM members WHERE id=$1 AND status='approved'`,[req.session.member.id]);
  if(!rows[0])return res.status(401).json({error:'Member account is no longer active'});res.json(rows[0]);
}catch(e){res.status(500).json({error:'Unable to load member profile'})}});
app.post('/api/member/logout',(req,res)=>{req.session.member=null;res.json({ok:true})});

// Admin authentication and command APIs.
app.post('/api/admin/login',db,async(req,res)=>{try{const {username,password}=req.body;const {rows}=await pool.query('SELECT * FROM admins WHERE username=$1',[username]);if(!rows[0]||!(await bcrypt.compare(password,rows[0].password_hash)))return res.status(401).json({error:'Invalid username or password'});req.session.admin={id:rows[0].id,username:rows[0].username,role:rows[0].role};res.json({ok:true,admin:req.session.admin})}catch(e){res.status(500).json({error:'Login failed'})}});
app.post('/api/admin/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));app.get('/api/admin/me',admin,(req,res)=>res.json(req.session.admin));
app.get('/api/admin/stats',admin,db,async(req,res)=>{try{const {rows}=await pool.query(`SELECT COUNT(*)::int AS total,COUNT(*) FILTER(WHERE status='pending')::int AS pending,COUNT(*) FILTER(WHERE status='approved')::int AS approved,COUNT(*) FILTER(WHERE status='rejected')::int AS rejected,COUNT(*) FILTER(WHERE photo_url IS NOT NULL AND photo_url<>'')::int AS with_photo FROM members`);const units=await pool.query(`SELECT COALESCE(NULLIF(unit,''),'Unassigned') unit,COUNT(*)::int count FROM members GROUP BY 1 ORDER BY count DESC,unit`);res.json({summary:rows[0],units:units.rows})}catch(e){res.status(500).json({error:'Unable to load statistics'})}});
app.get('/api/admin/members',admin,db,async(req,res)=>{try{const s=req.query.status||'all',q=(req.query.q||'').trim();const params=[];const where=[];if(s!=='all'){params.push(s);where.push(`status=$${params.length}`)}if(q){params.push('%'+q+'%');where.push(`(full_name ILIKE $${params.length} OR member_id ILIKE $${params.length} OR phone ILIKE $${params.length} OR email ILIKE $${params.length} OR unit ILIKE $${params.length} OR state ILIKE $${params.length} OR lga ILIKE $${params.length})`)}const sql=`SELECT * FROM members ${where.length?'WHERE '+where.join(' AND '):''} ORDER BY created_at DESC`;const {rows}=await pool.query(sql,params);res.json(rows)}catch(e){res.status(500).json({error:'Unable to load members'})}});
app.get('/api/admin/members/:id',admin,db,async(req,res)=>{try{const {rows}=await pool.query('SELECT * FROM members WHERE id=$1',[req.params.id]);if(!rows[0])return res.status(404).json({error:'Member not found'});res.json(rows[0])}catch(e){res.status(500).json({error:'Unable to load member'})}});
app.patch('/api/admin/members/:id',admin,db,async(req,res)=>{try{const d=req.body;const allowed=['approved','rejected','pending'];if(d.status&&!allowed.includes(d.status))return res.status(400).json({error:'Invalid status'});const {rows}=await pool.query(`UPDATE members SET full_name=COALESCE($1,full_name),phone=COALESCE($2,phone),email=COALESCE($3,email),state=COALESCE($4,state),lga=COALESCE($5,lga),gender=COALESCE($6,gender),date_of_birth=COALESCE($7,date_of_birth),address=COALESCE($8,address),emergency_contact=COALESCE($9,emergency_contact),emergency_phone=COALESCE($10,emergency_phone),blood_group=COALESCE($11,blood_group),qualification=COALESCE($12,qualification),first_aid_level=COALESCE($13,first_aid_level),unit=COALESCE($14,unit),year_of_entry=COALESCE($15,year_of_entry),rank=COALESCE($16,rank),office_description=COALESCE($17,office_description),photo_url=COALESCE($18,photo_url),status=COALESCE($19,status),approved_at=CASE WHEN COALESCE($19,status)='approved' THEN COALESCE(approved_at,NOW()) ELSE approved_at END WHERE id=$20 RETURNING *`,[d.full_name,d.phone,normalizeEmail(d.email)||d.email,d.state,d.lga,d.gender,d.date_of_birth||null,d.address,d.emergency_contact,d.emergency_phone,d.blood_group,d.qualification,d.first_aid_level,d.unit,d.year_of_entry,d.rank,d.office_description,d.photo_url,d.status,req.params.id]);if(!rows[0])return res.status(404).json({error:'Member not found'});await audit(req,d.status==='approved'?'approve_member':'update_member',rows[0].id,JSON.stringify({fields:Object.keys(d)}));res.json(rows[0])}catch(e){console.error(e);res.status(500).json({error:'Update failed'})}});
app.post('/api/admin/members/:id/photo',admin,db,async(req,res)=>{try{if(!req.body.photo_url)return res.status(400).json({error:'Photo is required'});const {rows}=await pool.query('UPDATE members SET photo_url=$1 WHERE id=$2 RETURNING *',[req.body.photo_url,req.params.id]);if(!rows[0])return res.status(404).json({error:'Member not found'});await audit(req,'update_photo',rows[0].id);res.json(rows[0])}catch(e){res.status(500).json({error:'Photo update failed'})}});
app.delete('/api/admin/members/:id',admin,db,async(req,res)=>{try{if(req.session.admin.role!=='super_admin')return res.status(403).json({error:'Super admin only'});const r=await pool.query('DELETE FROM members WHERE id=$1',[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Member not found'});await audit(req,'delete_member',req.params.id);res.json({ok:true})}catch(e){res.status(500).json({error:'Delete failed'})}});
app.get('/api/admin/admins',admin,db,async(req,res)=>{try{if(req.session.admin.role!=='super_admin')return res.status(403).json({error:'Super admin only'});const {rows}=await pool.query('SELECT id,username,role,created_at FROM admins ORDER BY created_at');res.json(rows)}catch(e){res.status(500).json({error:'Unable to load admins'})}});
app.post('/api/admin/admins',admin,db,async(req,res)=>{try{if(req.session.admin.role!=='super_admin')return res.status(403).json({error:'Super admin only'});const {username,password,role='approver'}=req.body;if(!username||!password)return res.status(400).json({error:'Username and password are required'});const hash=await bcrypt.hash(password,12);await pool.query('INSERT INTO admins(username,password_hash,role) VALUES($1,$2,$3)',[username,hash,role]);res.json({ok:true})}catch(e){res.status(400).json({error:'Could not create admin'})}});
app.get('/api/admin/audit-logs',admin,db,async(req,res)=>{try{const {rows}=await pool.query(`SELECT a.*,m.full_name,ad.username FROM audit_logs a LEFT JOIN members m ON m.id=a.member_id LEFT JOIN admins ad ON ad.id=a.admin_id ORDER BY a.created_at DESC LIMIT 250`);res.json(rows)}catch(e){res.status(500).json({error:'Unable to load audit logs'})}});

const PORT=process.env.PORT||10000;app.listen(PORT,()=>console.log('Fityanul Islam portal running on '+PORT));
