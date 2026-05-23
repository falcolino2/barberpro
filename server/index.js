require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const path    = require('path');
const ws      = require('ws');
const { createClient } = require('@supabase/supabase-js');

const sb     = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY, {
  realtime: { transport: ws }
});
const SECRET = process.env.JWT_SECRET || 'barberpro_secret';
const PORT   = process.env.PORT || 3001;

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const tod = () => new Date().toISOString().slice(0,10);
const now = () => new Date().toISOString();

function getHours(s) {
  const slots = [];
  const [oh,om] = s.open_time.split(':').map(Number);
  const [ch,cm] = s.close_time.split(':').map(Number);
  const [lsh,lsm] = s.lunch_start.split(':').map(Number);
  const [leh,lem] = s.lunch_end.split(':').map(Number);
  let h=oh,m=om;
  while(h*60+m<ch*60+cm){
    const ts=`${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
    const mins=h*60+m;
    if(!s.lunch_enabled||mins<lsh*60+lsm||mins>=leh*60+lem)slots.push(ts);
    m+=30;if(m>=60){h++;m-=60;}
  }
  return slots;
}

const DEFAULT_SETTINGS = { open_days:[1,2,3,4,5,6], open_time:'08:00', close_time:'19:00', lunch_enabled:true, lunch_start:'12:00', lunch_end:'13:00', whatsapp_enabled:false, whatsapp_number:'', reminder_enabled:false, reminder_hours:24, monthly_goal:0 };

async function getSettings(shopId) {
  const { data } = await sb.from('shop_settings').select('*').eq('shop_id',shopId).single();
  return data || DEFAULT_SETTINGS;
}

// Auto-expiry
async function checkExpiry() {
  const today=tod();
  const { data:shops } = await sb.from('barbershops').select('id,name,expires').eq('active',true);
  for(const s of shops||[]){
    if(s.expires && s.expires<=today){
      await sb.from('barbershops').update({active:false}).eq('id',s.id);
      console.log(`⚠️  Expirada: ${s.name}`);
    }
  }
}
checkExpiry();
setInterval(checkExpiry,60000);

// Auth middleware
function auth(req,res,next){
  const token=req.headers.authorization?.split(' ')[1];
  if(!token)return res.status(401).json({error:'Token necessário'});
  try{req.user=jwt.verify(token,SECRET);next();}
  catch{res.status(401).json({error:'Token inválido'});}
}
function superOnly(req,res,next){
  if(req.user?.role!=='superadmin')return res.status(403).json({error:'Acesso negado'});
  next();
}
async function shopAuth(req,res,next){
  const shopId=req.params.shopId||req.user?.shopId;
  if(!shopId)return res.status(400).json({error:'Barbearia não identificada'});
  const {data:shop}=await sb.from('barbershops').select('*').eq('id',shopId).single();
  if(!shop)return res.status(404).json({error:'Barbearia não encontrada'});
  if(!shop.expires)return res.status(403).json({error:'Barbearia indisponível',unavailable:true});
  if(shop.expires<=tod())return res.status(403).json({error:'Acesso expirado',expired:true});
  if(!shop.active)return res.status(403).json({error:'Barbearia inativa',unavailable:true});
  req.shop=shop;next();
}
function shopAdmin(req,res,next){
  if(req.user.role==='superadmin')return next();
  if(req.user.role==='admin'&&req.user.shopId===req.shop?.id)return next();
  return res.status(403).json({error:'Acesso negado'});
}

app.get('/api/health',(_, res)=>res.json({ok:true}));

// ── Serve frontend ────────────────────────────────────────────────────────────
const distPath = path.join(__dirname, '../dist');
if (require('fs').existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get('*', (req, res) => {
    if (!req.path.startsWith('/api')) {
      res.sendFile(path.join(distPath, 'index.html'));
    }
  });
}

// Super admin auth
app.post('/api/super/login',async(req,res)=>{
  const {email,password}=req.body;
  const {data:sa}=await sb.from('superadmins').select('*').eq('email',email).single();
  if(!sa||!bcrypt.compareSync(password,sa.password))return res.status(400).json({error:'Email ou senha incorretos'});
  const token=jwt.sign({id:sa.id,name:sa.name,email:sa.email,role:'superadmin'},SECRET,{expiresIn:'30d'});
  res.json({token,user:{id:sa.id,name:sa.name,email:sa.email,role:'superadmin'}});
});

// Super admin shops
app.get('/api/super/shops',auth,superOnly,async(_,res)=>{
  try {
    const {data:shops, error}=await sb.from('barbershops').select('*').order('created_at',{ascending:false});
    if (error) return res.status(500).json({error:error.message});
    res.json((shops||[]).map(s=>({...s, ownerPasswordHint:s.owner_password_hint||null, stats:{totalApts:0,monthRevenue:0,activeBarbers:0}})));
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/super/shops',auth,superOnly,async(req,res)=>{
  try{
    const {name,ownerName,ownerPhone,ownerPassword,address,phone,expires}=req.body;
    if(!name||!ownerPhone||!ownerPassword)return res.status(400).json({error:'Dados incompletos'});
    const raw=ownerPhone.replace(/\D/g,'');
    const {data:exists}=await sb.from('users').select('id').eq('phone',raw).single();
    if(exists)return res.status(400).json({error:'Telefone já cadastrado'});
    const {data:shop,error:se}=await sb.from('barbershops').insert({name,address:address||'',phone:phone||'',active:true,expires:expires||null,owner_password_hint:ownerPassword}).select().single();
    if(se)throw se;
    const {data:owner,error:oe}=await sb.from('users').insert({phone:raw,name:ownerName||name,password:bcrypt.hashSync(ownerPassword,10),role:'admin',shop_id:shop.id}).select().single();
    if(oe)throw oe;
    await sb.from('services').insert([
      {shop_id:shop.id,name:'Corte Simples',price:35,duration:30,icon:'✂',active:true},
      {shop_id:shop.id,name:'Corte + Barba',price:60,duration:60,icon:'🪒',active:true},
      {shop_id:shop.id,name:'Barba',price:30,duration:30,icon:'🧔',active:true},
    ]);
    await sb.from('shop_settings').insert({shop_id:shop.id,...DEFAULT_SETTINGS});
    await sb.from('loyalty_settings').insert({shop_id:shop.id,enabled:false,points_per_visit:10,points_to_discount:100,discount_value:10});
    res.json({shop:{...shop,ownerPhone:owner.phone,ownerName:owner.name,ownerPasswordHint:ownerPassword},owner:{...owner,password:undefined}});
  }catch(e){res.status(500).json({error:e.message});}
});

app.put('/api/super/shops/:id',auth,superOnly,async(req,res)=>{
  const {name,active,address,phone,expires,ownerPhone,ownerName,newPassword}=req.body;
  const update={};
  if(name!==undefined)update.name=name;
  if(address!==undefined)update.address=address;
  if(phone!==undefined)update.phone=phone;
  if(expires!==undefined)update.expires=expires||null;
  if(active!==undefined)update.active=active;
  if(expires&&expires<=tod())update.active=false;
  const {data:shop}=await sb.from('barbershops').update(update).eq('id',req.params.id).select().single();
  if(ownerPhone||ownerName||newPassword){
    const ownerUpdate={};
    if(ownerPhone)ownerUpdate.phone=ownerPhone.replace(/\D/g,'');
    if(ownerName)ownerUpdate.name=ownerName.trim();
    if(newPassword&&newPassword.length>=6){
      ownerUpdate.password=bcrypt.hashSync(newPassword,10);
      await sb.from('barbershops').update({owner_password_hint:newPassword}).eq('id',req.params.id);
    }
    await sb.from('users').update(ownerUpdate).eq('shop_id',req.params.id).eq('role','admin');
  }
  const {data:owner}=await sb.from('users').select('phone,name').eq('shop_id',req.params.id).eq('role','admin').single();
  const {data:hint}=await sb.from('barbershops').select('owner_password_hint').eq('id',req.params.id).single();
  res.json({...shop,ownerPhone:owner?.phone,ownerName:owner?.name,ownerPasswordHint:hint?.owner_password_hint});
});

app.delete('/api/super/shops/:id',auth,superOnly,async(req,res)=>{
  if(req.query.hard==='true'){
    const tables=['appointments','services','barbers','blocked_slots','waiting_list','reviews','clients','coupons','gallery','shop_settings','loyalty_settings'];
    for(const t of tables)await sb.from(t).delete().eq('shop_id',req.params.id);
    await sb.from('users').delete().eq('shop_id',req.params.id);
    await sb.from('barbershops').delete().eq('id',req.params.id);
  }else{
    await sb.from('barbershops').update({active:false}).eq('id',req.params.id);
  }
  res.json({ok:true});
});

app.get('/api/super/stats',auth,superOnly,async(_,res)=>{
  const {data:shops}=await sb.from('barbershops').select('active');
  res.json({totalShops:shops?.length||0,activeShops:shops?.filter(s=>s.active).length||0});
});

// Public shop info
app.get('/api/shop/:shopId',async(req,res)=>{
  const {data:shop}=await sb.from('barbershops').select('*').eq('id',req.params.shopId).single();
  if(!shop)return res.status(404).json({error:'Não encontrada'});
  const available=shop.active&&shop.expires&&shop.expires>tod();
  res.json({id:shop.id,name:shop.name,phone:shop.phone,address:shop.address,available,
    reason:!shop.active?'inactive':!shop.expires?'no_expiry':shop.expires<=tod()?'expired':null});
});

// Auth
app.post('/api/auth/register',async(req,res)=>{
  try{
    const {phone,name,password,shopId}=req.body;
    const raw=phone?.replace(/\D/g,'');
    if(!raw||!name||!password)return res.status(400).json({error:'Dados incompletos'});
    if(password.length<6)return res.status(400).json({error:'Senha mínima 6 caracteres'});
    let sid=shopId;
    if(!sid){
      const {data:shops}=await sb.from('barbershops').select('id').eq('active',true);
      if(shops?.length===1)sid=shops[0].id;
      else return res.status(400).json({error:'Informe o ID da barbearia'});
    }
    const {data:shop}=await sb.from('barbershops').select('*').eq('id',sid).single();
    if(!shop||!shop.active)return res.status(404).json({error:'Barbearia não encontrada'});
    const {data:exists}=await sb.from('users').select('id').eq('phone',raw).single();
    if(exists)return res.status(400).json({error:'Número já cadastrado'});
    const {data:user}=await sb.from('users').insert({phone:raw,name:name.trim(),password:bcrypt.hashSync(password,10),role:'client',shop_id:sid}).select().single();
    const token=jwt.sign({id:user.id,phone:user.phone,name:user.name,role:user.role,shopId:sid},SECRET,{expiresIn:'30d'});
    res.json({token,user:{id:user.id,phone:user.phone,name:user.name,role:user.role,shopId:sid}});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/auth/login',async(req,res)=>{
  try{
    const {phone,password,shopId}=req.body;
    const raw=phone?.replace(/\D/g,'');
    let q=sb.from('users').select('*').eq('phone',raw);
    if(shopId)q=q.eq('shop_id',shopId);
    const {data:users}=await q;
    const user=(users||[]).find(u=>bcrypt.compareSync(password,u.password));
    if(!user)return res.status(400).json({error:'Celular ou senha incorretos'});
    if(user.role!=='superadmin'&&user.shop_id){
      const {data:shop}=await sb.from('barbershops').select('active').eq('id',user.shop_id).single();
      if(shop&&!shop.active)return res.status(403).json({error:'Barbearia inativa'});
    }
    const token=jwt.sign({id:user.id,phone:user.phone,name:user.name,role:user.role,shopId:user.shop_id},SECRET,{expiresIn:'30d'});
    res.json({token,user:{id:user.id,phone:user.phone,name:user.name,role:user.role,shopId:user.shop_id,avatar:user.avatar}});
  }catch(e){res.status(500).json({error:e.message});}
});

// Profile
app.get('/api/:shopId/profile',auth,shopAuth,async(req,res)=>{
  const {data}=await sb.from('users').select('id,name,phone,role,avatar').eq('id',req.user.id).single();
  res.json(data);
});
app.put('/api/:shopId/profile',auth,shopAuth,async(req,res)=>{
  const {name,phone,password,currentPassword,avatar}=req.body;
  const {data:user}=await sb.from('users').select('*').eq('id',req.user.id).single();
  const update={};
  if(name)update.name=name.trim();
  if(phone)update.phone=phone.replace(/\D/g,'');
  if(avatar!==undefined)update.avatar=avatar;
  if(password){
    if(!bcrypt.compareSync(currentPassword,user.password))return res.status(400).json({error:'Senha atual incorreta'});
    if(password.length<6)return res.status(400).json({error:'Mínimo 6 caracteres'});
    update.password=bcrypt.hashSync(password,10);
  }
  await sb.from('users').update(update).eq('id',req.user.id);
  const {data:updated}=await sb.from('users').select('id,name,phone,role,avatar').eq('id',req.user.id).single();
  const token=jwt.sign({id:updated.id,phone:updated.phone,name:updated.name,role:updated.role,shopId:user.shop_id},SECRET,{expiresIn:'30d'});
  res.json({token,user:{...updated,shopId:user.shop_id}});
});

// Settings
app.get('/api/:shopId/settings',async(req,res)=>{
  const s=await getSettings(req.params.shopId);
  if(!req.headers.authorization)return res.json({open_days:s.open_days,open_time:s.open_time,close_time:s.close_time});
  try{const u=jwt.verify(req.headers.authorization.split(' ')[1],SECRET);if(u.role==='admin'||u.role==='superadmin')return res.json(s);}catch{}
  res.json({open_days:s.open_days,open_time:s.open_time,close_time:s.close_time});
});
app.put('/api/:shopId/settings',auth,shopAuth,shopAdmin,async(req,res)=>{
  const existing=await getSettings(req.params.shopId);
  if(existing.shop_id){await sb.from('shop_settings').update(req.body).eq('shop_id',req.params.shopId);}
  else{await sb.from('shop_settings').insert({shop_id:req.params.shopId,...req.body});}
  res.json(await getSettings(req.params.shopId));
});

// Available
app.get('/api/:shopId/available',async(req,res)=>{
  const {date,barberId}=req.query;
  if(!date)return res.status(400).json({error:'Data obrigatória'});
  const s=await getSettings(req.params.shopId);
  const dow=new Date(date+'T12:00').getDay();
  if(!s.open_days.includes(dow))return res.json([]);
  let bQ=sb.from('appointments').select('time').eq('shop_id',req.params.shopId).eq('date',date).neq('status','cancelled');
  if(barberId)bQ=bQ.eq('barber_id',barberId);
  const {data:booked}=await bQ;
  let blQ=sb.from('blocked_slots').select('time').eq('shop_id',req.params.shopId).eq('date',date);
  if(barberId)blQ=blQ.or(`barber_id.eq.${barberId},barber_id.is.null`);
  const {data:blocked}=await blQ;
  const taken=new Set([...(booked||[]).map(a=>a.time),...(blocked||[]).map(b=>b.time)]);
  res.json(getHours(s).filter(h=>!taken.has(h)));
});

// Services
app.get('/api/:shopId/services',async(req,res)=>{const {data}=await sb.from('services').select('*').eq('shop_id',req.params.shopId).eq('active',true).order('name');res.json(data||[]);});
app.post('/api/:shopId/services',auth,shopAuth,shopAdmin,async(req,res)=>{const {name,price,duration,icon}=req.body;const {data}=await sb.from('services').insert({shop_id:req.params.shopId,name,price:+price,duration:+duration,icon:icon||'✂',active:true}).select().single();res.json(data);});
app.put('/api/:shopId/services/:id',auth,shopAuth,shopAdmin,async(req,res)=>{const {data}=await sb.from('services').update(req.body).eq('id',req.params.id).select().single();res.json(data);});
app.delete('/api/:shopId/services/:id',auth,shopAuth,shopAdmin,async(req,res)=>{await sb.from('services').update({active:false}).eq('id',req.params.id);res.json({ok:true});});

// Barbers
app.get('/api/:shopId/barbers',async(req,res)=>{const {data}=await sb.from('barbers').select('*').eq('shop_id',req.params.shopId).eq('active',true).order('name');res.json(data||[]);});
app.post('/api/:shopId/barbers',auth,shopAuth,shopAdmin,async(req,res)=>{const {name,specialty,color}=req.body;const {data}=await sb.from('barbers').insert({shop_id:req.params.shopId,name,specialty:specialty||'',color:color||'#c9a84c',active:true}).select().single();res.json(data);});
app.put('/api/:shopId/barbers/:id',auth,shopAuth,shopAdmin,async(req,res)=>{const {data}=await sb.from('barbers').update(req.body).eq('id',req.params.id).select().single();res.json(data);});
app.delete('/api/:shopId/barbers/:id',auth,shopAuth,shopAdmin,async(req,res)=>{await sb.from('barbers').update({active:false}).eq('id',req.params.id);res.json({ok:true});});

// Blocked slots
app.get('/api/:shopId/blocked',auth,shopAuth,shopAdmin,async(req,res)=>{const {data}=await sb.from('blocked_slots').select('*').eq('shop_id',req.params.shopId).order('date').order('time');res.json(data||[]);});
app.post('/api/:shopId/blocked',auth,shopAuth,shopAdmin,async(req,res)=>{
  const {date,time,barberId,reason}=req.body;
  if(!date)return res.status(400).json({error:'Data obrigatória'});
  if(!time){const s=await getSettings(req.params.shopId);const rows=getHours(s).map(h=>({shop_id:req.params.shopId,date,time:h,barber_id:barberId||null,reason:reason||'Folga'}));await sb.from('blocked_slots').upsert(rows,{onConflict:'shop_id,date,time,barber_id'});return res.json({ok:true});}
  const {data}=await sb.from('blocked_slots').insert({shop_id:req.params.shopId,date,time,barber_id:barberId||null,reason:reason||''}).select().single();res.json(data);
});
app.delete('/api/:shopId/blocked/:id',auth,shopAuth,shopAdmin,async(req,res)=>{await sb.from('blocked_slots').delete().eq('id',req.params.id);res.json({ok:true});});

// Appointments
app.get('/api/:shopId/appointments',auth,shopAuth,async(req,res)=>{
  let q=sb.from('appointments').select('*, service:services(*), barber:barbers(*), client:users(id,name,phone)').eq('shop_id',req.params.shopId).order('date').order('time');
  if(req.user.role==='client')q=q.eq('client_id',req.user.id);
  if(req.query.date)q=q.eq('date',req.query.date);
  if(req.query.status)q=q.eq('status',req.query.status);
  const {data}=await q;res.json(data||[]);
});
app.post('/api/:shopId/appointments/admin',auth,shopAuth,shopAdmin,async(req,res)=>{
  const {clientName,serviceId,barberId,date,time}=req.body;
  if(!clientName||!serviceId||!barberId||!date||!time)return res.status(400).json({error:'Dados incompletos'});
  const {data:conflict}=await sb.from('appointments').select('id').eq('shop_id',req.params.shopId).eq('date',date).eq('time',time).eq('barber_id',barberId).neq('status','cancelled').single();
  if(conflict)return res.status(400).json({error:'Horário já ocupado'});
  const {data}=await sb.from('appointments').insert({shop_id:req.params.shopId,client_id:null,client_name:clientName.trim(),service_id:serviceId,barber_id:barberId,date,time,status:'confirmed'}).select('*, service:services(*), barber:barbers(*)').single();
  res.json(data);
});
app.post('/api/:shopId/appointments',auth,shopAuth,async(req,res)=>{
  const {serviceId,barberId,date,time}=req.body;
  if(!serviceId||!barberId||!date||!time)return res.status(400).json({error:'Dados incompletos'});
  const {data:conflict}=await sb.from('appointments').select('id').eq('shop_id',req.params.shopId).eq('date',date).eq('time',time).eq('barber_id',barberId).neq('status','cancelled').single();
  if(conflict)return res.status(400).json({error:'Horário já ocupado'});
  const {data:blocked}=await sb.from('blocked_slots').select('id').eq('shop_id',req.params.shopId).eq('date',date).eq('time',time).single();
  if(blocked)return res.status(400).json({error:'Horário bloqueado'});
  const {data}=await sb.from('appointments').insert({shop_id:req.params.shopId,client_id:req.user.id,client_name:req.user.name,service_id:serviceId,barber_id:barberId,date,time,status:'confirmed'}).select('*, service:services(*), barber:barbers(*)').single();
  res.json(data);
});
app.put('/api/:shopId/appointments/:id',auth,shopAuth,async(req,res)=>{
  const {data:apt}=await sb.from('appointments').select('client_id').eq('id',req.params.id).single();
  if(!apt)return res.status(404).json({error:'Não encontrado'});
  if(req.user.role==='client'&&apt.client_id!==req.user.id)return res.status(403).json({error:'Acesso negado'});
  const fields=(req.user.role==='admin'||req.user.role==='superadmin')?{status:req.body.status,date:req.body.date,time:req.body.time,barber_id:req.body.barberId,service_id:req.body.serviceId}:{status:req.body.status};
  const update=Object.fromEntries(Object.entries(fields).filter(([,v])=>v!==undefined));
  if(update.status==='cancelled'){update.cancelled_by=req.user.role==='client'?'client':'admin';update.cancelled_by_name=req.user.name;update.cancelled_at=now();}
  const {data}=await sb.from('appointments').update(update).eq('id',req.params.id).select('*, service:services(*), barber:barbers(*)').single();
  res.json(data);
});
app.delete('/api/:shopId/appointments/:id',auth,shopAuth,shopAdmin,async(req,res)=>{await sb.from('appointments').delete().eq('id',req.params.id);res.json({ok:true});});
app.get('/api/:shopId/appointments/last',auth,shopAuth,async(req,res)=>{
  const {data}=await sb.from('appointments').select('*, service:services(*), barber:barbers(*)').eq('shop_id',req.params.shopId).eq('client_id',req.user.id).eq('status','confirmed').order('created_at',{ascending:false}).limit(1).single();
  res.json(data||null);
});

// Reviews
app.get('/api/:shopId/reviews',auth,shopAuth,async(req,res)=>{let q=sb.from('reviews').select('*, barber:barbers(name)').eq('shop_id',req.params.shopId).order('created_at',{ascending:false});if(req.user.role==='client')q=q.eq('client_id',req.user.id);const {data}=await q;res.json(data||[]);});
app.post('/api/:shopId/reviews',auth,shopAuth,async(req,res)=>{const {appointmentId,barberId,rating,comment}=req.body;if(!rating||rating<1||rating>5)return res.status(400).json({error:'Nota inválida'});const {data:exists}=await sb.from('reviews').select('id').eq('appointment_id',appointmentId).eq('client_id',req.user.id).single();if(exists)return res.status(400).json({error:'Já avaliado'});const {data}=await sb.from('reviews').insert({shop_id:req.params.shopId,appointment_id:appointmentId,client_id:req.user.id,client_name:req.user.name,barber_id:barberId,rating:+rating,comment:comment||''}).select().single();res.json(data);});

// Waiting
app.get('/api/:shopId/waiting',auth,shopAuth,async(req,res)=>{let q=sb.from('waiting_list').select('*, service:services(name,icon), barber:barbers(name)').eq('shop_id',req.params.shopId).order('created_at');if(req.user.role==='client')q=q.eq('client_id',req.user.id);const {data}=await q;res.json(data||[]);});
app.post('/api/:shopId/waiting',auth,shopAuth,async(req,res)=>{const {serviceId,barberId,date}=req.body;const {data}=await sb.from('waiting_list').insert({shop_id:req.params.shopId,client_id:req.user.id,client_name:req.user.name,service_id:serviceId,barber_id:barberId,date}).select().single();res.json(data);});
app.delete('/api/:shopId/waiting/:id',auth,shopAuth,async(req,res)=>{await sb.from('waiting_list').delete().eq('id',req.params.id);res.json({ok:true});});

// Clients
app.get('/api/:shopId/clients',auth,shopAuth,shopAdmin,async(req,res)=>{const {data:clients}=await sb.from('clients').select('*').eq('shop_id',req.params.shopId).order('name');const {data:apts}=await sb.from('appointments').select('client_name,status,date').eq('shop_id',req.params.shopId);res.json((clients||[]).map(c=>({...c,totalApts:(apts||[]).filter(a=>a.client_name===c.name&&a.status!=='cancelled').length,lastVisit:(apts||[]).filter(a=>a.client_name===c.name&&a.status==='confirmed').sort((a,b)=>b.date.localeCompare(a.date))[0]?.date||null})));});
app.post('/api/:shopId/clients',auth,shopAuth,shopAdmin,async(req,res)=>{const {name,phone,notes}=req.body;if(!name)return res.status(400).json({error:'Nome obrigatório'});const {data}=await sb.from('clients').insert({shop_id:req.params.shopId,name:name.trim(),phone:phone?phone.replace(/\D/g,''):'',notes:notes||'',blocked:false}).select().single();res.json(data);});
app.put('/api/:shopId/clients/:id',auth,shopAuth,shopAdmin,async(req,res)=>{const {data}=await sb.from('clients').update(req.body).eq('id',req.params.id).select().single();res.json(data);});
app.delete('/api/:shopId/clients/:id',auth,shopAuth,shopAdmin,async(req,res)=>{await sb.from('clients').delete().eq('id',req.params.id);res.json({ok:true});});

// Coupons
app.get('/api/:shopId/coupons',auth,shopAuth,async(req,res)=>{const {data}=await sb.from('coupons').select('*').eq('shop_id',req.params.shopId);if(req.user.role==='client')return res.json((data||[]).filter(c=>c.active).map(c=>({id:c.id,code:c.code,description:c.description,type:c.type,value:c.value})));res.json(data||[]);});
app.post('/api/:shopId/coupons/validate',auth,shopAuth,async(req,res)=>{const {data:coupons}=await sb.from('coupons').select('*').eq('shop_id',req.params.shopId).eq('active',true);const c=(coupons||[]).find(x=>x.code.toUpperCase()===req.body.code?.toUpperCase());if(!c)return res.status(400).json({error:'Cupom inválido'});if(c.expires_at&&c.expires_at<tod())return res.status(400).json({error:'Cupom expirado'});if(c.usage_limit&&c.used_count>=c.usage_limit)return res.status(400).json({error:'Cupom esgotado'});res.json(c);});
app.post('/api/:shopId/coupons',auth,shopAuth,shopAdmin,async(req,res)=>{const {code,description,type,value,usageLimit,expiresAt,minVisits}=req.body;const {data}=await sb.from('coupons').insert({shop_id:req.params.shopId,code:code.toUpperCase().trim(),description:description||'',type,value:+value,usage_limit:usageLimit?+usageLimit:null,used_count:0,min_visits:minVisits?+minVisits:0,expires_at:expiresAt||null,active:true}).select().single();res.json(data);});
app.put('/api/:shopId/coupons/:id',auth,shopAuth,shopAdmin,async(req,res)=>{const {data}=await sb.from('coupons').update(req.body).eq('id',req.params.id).select().single();res.json(data);});
app.delete('/api/:shopId/coupons/:id',auth,shopAuth,shopAdmin,async(req,res)=>{await sb.from('coupons').update({active:false}).eq('id',req.params.id);res.json({ok:true});});

// Loyalty
app.get('/api/:shopId/loyalty',auth,shopAuth,async(req,res)=>{const {data:cfg}=await sb.from('loyalty_settings').select('*').eq('shop_id',req.params.shopId).single();const settings=cfg||{enabled:false,points_per_visit:10,points_to_discount:100,discount_value:10};if(req.user.role==='client'){const {data:user}=await sb.from('users').select('points').eq('id',req.user.id).single();return res.json({...settings,myPoints:user?.points||0});}res.json(settings);});
app.put('/api/:shopId/loyalty',auth,shopAuth,shopAdmin,async(req,res)=>{const {data:exists}=await sb.from('loyalty_settings').select('shop_id').eq('shop_id',req.params.shopId).single();if(exists)await sb.from('loyalty_settings').update(req.body).eq('shop_id',req.params.shopId);else await sb.from('loyalty_settings').insert({shop_id:req.params.shopId,...req.body});const {data}=await sb.from('loyalty_settings').select('*').eq('shop_id',req.params.shopId).single();res.json(data);});
app.post('/api/:shopId/loyalty/redeem',auth,shopAuth,async(req,res)=>{const {data:cfg}=await sb.from('loyalty_settings').select('*').eq('shop_id',req.params.shopId).single();if(!cfg?.enabled)return res.status(400).json({error:'Fidelidade desativada'});const {data:user}=await sb.from('users').select('points').eq('id',req.user.id).single();const pts=user?.points||0;if(pts<cfg.points_to_discount)return res.status(400).json({error:`Precisa de ${cfg.points_to_discount} pontos`});await sb.from('users').update({points:pts-cfg.points_to_discount}).eq('id',req.user.id);res.json({discount:cfg.discount_value,remaining:pts-cfg.points_to_discount});});

// Gallery
app.get('/api/:shopId/gallery',async(req,res)=>{const {data}=await sb.from('gallery').select('*').eq('shop_id',req.params.shopId).eq('active',true);res.json(data||[]);});
app.post('/api/:shopId/gallery',auth,shopAuth,shopAdmin,async(req,res)=>{const {title,description,image,serviceId}=req.body;if(!image)return res.status(400).json({error:'Imagem obrigatória'});const {data}=await sb.from('gallery').insert({shop_id:req.params.shopId,title:title||'',description:description||'',image,service_id:serviceId||null,active:true}).select().single();res.json(data);});
app.delete('/api/:shopId/gallery/:id',auth,shopAuth,shopAdmin,async(req,res)=>{await sb.from('gallery').update({active:false}).eq('id',req.params.id);res.json({ok:true});});

// Stats
app.get('/api/:shopId/stats',auth,shopAuth,shopAdmin,async(req,res)=>{
  const td=tod(),wk=(()=>{const d=new Date();d.setDate(d.getDate()-d.getDay());return d.toISOString().slice(0,10);})(),mo=td.slice(0,7)+'-01';
  const [{data:apts},{data:svcs},{data:revs},{count:clients}]=await Promise.all([
    sb.from('appointments').select('date,status,service_id').eq('shop_id',req.params.shopId),
    sb.from('services').select('id,price').eq('shop_id',req.params.shopId),
    sb.from('reviews').select('rating').eq('shop_id',req.params.shopId),
    sb.from('users').select('*',{count:'exact',head:true}).eq('shop_id',req.params.shopId).eq('role','client'),
  ]);
  const rev=list=>list.filter(a=>a.status==='confirmed').reduce((s,a)=>s+((svcs||[]).find(sv=>sv.id===a.service_id)?.price||0),0);
  const last7=[];for(let i=6;i>=0;i--){const d=new Date();d.setDate(d.getDate()-i);const ds=d.toISOString().slice(0,10);const day=(apts||[]).filter(a=>a.date===ds&&a.status==='confirmed');last7.push({date:ds,revenue:rev(day),count:day.length});}
  res.json({today:{count:(apts||[]).filter(a=>a.date===td&&a.status!=='cancelled').length,revenue:rev((apts||[]).filter(a=>a.date===td))},week:{count:(apts||[]).filter(a=>a.date>=wk&&a.status!=='cancelled').length,revenue:rev((apts||[]).filter(a=>a.date>=wk))},month:{count:(apts||[]).filter(a=>a.date>=mo&&a.status!=='cancelled').length,revenue:rev((apts||[]).filter(a=>a.date>=mo))},totalClients:clients||0,avgRating:(revs||[]).length?((revs||[]).reduce((s,r)=>s+r.rating,0)/(revs||[]).length).toFixed(1):null,last7});
});

// Reports
app.get('/api/:shopId/reports/barbers',auth,shopAuth,shopAdmin,async(req,res)=>{
  const {month}=req.query;
  const [{data:barbers},{data:svcs}]=await Promise.all([sb.from('barbers').select('*').eq('shop_id',req.params.shopId).eq('active',true),sb.from('services').select('*').eq('shop_id',req.params.shopId)]);
  let q=sb.from('appointments').select('*').eq('shop_id',req.params.shopId);
  if(month)q=q.gte('date',month+'-01').lte('date',month+'-31');
  const {data:apts}=await q;
  res.json((barbers||[]).map(b=>{const confirmed=(apts||[]).filter(a=>a.barber_id===b.id&&a.status==='confirmed');const cancelled=(apts||[]).filter(a=>a.barber_id===b.id&&a.status==='cancelled');const revenue=confirmed.reduce((s,a)=>s+((svcs||[]).find(sv=>sv.id===a.service_id)?.price||0),0);const byService=(svcs||[]).map(sv=>({name:sv.name,icon:sv.icon,count:confirmed.filter(a=>a.service_id===sv.id).length,revenue:confirmed.filter(a=>a.service_id===sv.id).length*sv.price})).filter(x=>x.count>0);return{barber:b,confirmed:confirmed.length,cancelled:cancelled.length,total:confirmed.length+cancelled.length,revenue,byService};}));
});

app.get('/api/:shopId/reports/export',auth,shopAuth,shopAdmin,async(req,res)=>{
  const {month}=req.query;
  const [{data:svcs},{data:bars}]=await Promise.all([sb.from('services').select('id,name,price').eq('shop_id',req.params.shopId),sb.from('barbers').select('id,name').eq('shop_id',req.params.shopId)]);
  let q=sb.from('appointments').select('*').eq('shop_id',req.params.shopId).order('date').order('time');
  if(month)q=q.gte('date',month+'-01').lte('date',month+'-31');
  const {data:apts}=await q;
  res.json((apts||[]).map(a=>({data:a.date,horario:a.time,cliente:a.client_name||'',servico:(svcs||[]).find(s=>s.id===a.service_id)?.name||'',barbeiro:(bars||[]).find(b=>b.id===a.barber_id)?.name||'',valor:(svcs||[]).find(s=>s.id===a.service_id)?.price||0,status:a.status})));
});

app.get('/api/:shopId/users',auth,shopAuth,shopAdmin,async(req,res)=>{
  const [{data:users},{data:apts}]=await Promise.all([sb.from('users').select('id,phone,name,created_at').eq('shop_id',req.params.shopId).eq('role','client').order('name'),sb.from('appointments').select('client_id,status,date').eq('shop_id',req.params.shopId)]);
  res.json((users||[]).map(u=>({...u,totalApts:(apts||[]).filter(a=>a.client_id===u.id&&a.status!=='cancelled').length,lastVisit:(apts||[]).filter(a=>a.client_id===u.id&&a.status==='confirmed').sort((a,b)=>b.date.localeCompare(a.date))[0]?.date||null})));
});

app.listen(PORT,()=>{console.log(`\n  ✅  BarberPro SaaS\n  🌐  http://localhost:${PORT}\n  🗄️   Supabase\n`);});
