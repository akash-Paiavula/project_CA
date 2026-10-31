require('dotenv').config();
const express = require('express'), { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const helmet = require('helmet'), rateLimit = require('express-rate-limit'), { z } = require('zod'), multer = require('multer');
const crypto = require('crypto'), fs = require('fs'), path = require('path'), Razorpay = require('razorpay');
const E = process.env, FEE = 20000, AY = '2026-27', DIR = E.FILE_DIR || '/data/files';
const pool = new Pool({ connectionString: E.DATABASE_URL });
const rzp = E.RAZORPAY_KEY_ID ? new Razorpay({ key_id: E.RAZORPAY_KEY_ID, key_secret: E.RAZORPAY_KEY_SECRET }) : null;
fs.mkdirSync(DIR, { recursive: true });
const up = multer({ dest: DIR, limits: { fileSize: 15 * 1024 * 1024 } });
const q = (s, p) => pool.query(s, p).then(r => r.rows);
const audit = (a, act, t, ip) => q('insert into audit_log(actor,action,target,ip) values($1,$2,$3,$4)', [a, act, t, ip]);
const wrap = f => (req, res, next) => Promise.resolve(f(req, res, next)).catch(next);
const lim = (m, max) => rateLimit({ windowMs: m * 60000, max });
const markPaid = async (orderId, payId) => {
  const [r] = await q("update payments set status='paid',rzp_payment_id=$1 where rzp_order_id=$2 and status<>'paid' returning filing_id", [payId, orderId]);
  if (r) await q("update filings set status='In Review' where id=$1 and status='Uploaded'", [r.filing_id]);
};

const app = express(); app.set('trust proxy', 1); app.use(helmet());
app.post('/api/razorpay/webhook', express.raw({ type: 'application/json' }), wrap(async (req, res) => {
  const exp = crypto.createHmac('sha256', E.RAZORPAY_WEBHOOK_SECRET || 'x').update(req.body).digest('hex');
  const got = String(req.headers['x-razorpay-signature'] || '');
  if (got.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(exp))) return res.status(400).end();
  const ev = JSON.parse(req.body);
  if (ev.event === 'payment.captured') await markPaid(ev.payload.payment.entity.order_id, ev.payload.payment.entity.id);
  res.json({ ok: 1 });
}));
app.use(express.json({ limit: '100kb' })); app.use('/api', lim(1, 200));

const tok = u => jwt.sign({ id: u.id, role: u.role }, E.JWT_SECRET, { expiresIn: '4h' });
const session = u => ({ token: tok(u), role: u.role, name: u.name, privWrappedPw: u.priv_wrapped_pw });
const auth = (req, res, next) => { try { req.user = jwt.verify((req.headers.authorization || '').slice(7), E.JWT_SECRET); next(); } catch { res.status(401).json({ error: 'Please log in again' }); } };
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only' });
const verified = wrap(async (req, res, next) => {
  const [u] = await q('select email_verified e, mobile_verified m from users where id=$1', [req.user.id]);
  u.e && u.m ? next() : res.status(403).json({ error: 'Verify your email and mobile first' });
});

app.post('/api/signup', lim(15, 20), wrap(async (req, res) => {
  const b = z.object({ name: z.string().min(2).max(80), email: z.string().email(), mobile: z.string().regex(/^[6-9]\d{9}$/),
    authSecret: z.string().min(20), pubkey: z.string(), privWrappedPw: z.string(), privWrappedRec: z.string() }).parse(req.body);
  const email = b.email.toLowerCase(), role = email === (E.ADMIN_EMAIL || '').toLowerCase() ? 'admin' : 'employee';
  try {
    const [u] = await q('insert into users(name,email,mobile,auth_hash,role,pubkey,priv_wrapped_pw,priv_wrapped_rec) values($1,$2,$3,$4,$5,$6,$7,$8) returning *',
      [b.name, email, b.mobile, await bcrypt.hash(b.authSecret, 12), role, b.pubkey, b.privWrappedPw, b.privWrappedRec]);
    if (role === 'employee') await q('insert into filings(user_id,assessment_year) values($1,$2)', [u.id, AY]);
    res.json(session(u));
  } catch (e) { if (e.code === '23505') return res.status(400).json({ error: 'Email or mobile is already registered' }); throw e; }
}));
app.post('/api/login', lim(15, 10), wrap(async (req, res) => {
  const [u] = await q('select * from users where email=$1', [String(req.body.email || '').toLowerCase()]);
  if (!u || !(await bcrypt.compare(String(req.body.authSecret || ''), u.auth_hash))) return res.status(401).json({ error: 'Wrong email or password' });
  res.json(session(u));
}));

const sendOtp = async (channel, to, code) => console.log(`[OTP ${channel}] ${to}: ${code}`); // replace with MSG91 / SES
const chan = req => req.body.channel === 'email' ? 'email' : 'mobile';
app.post('/api/otp/send', auth, lim(15, 6), wrap(async (req, res) => {
  const ch = chan(req), [u] = await q('select email,mobile from users where id=$1', [req.user.id]);
  const code = String(crypto.randomInt(100000, 1000000));
  await q("insert into otps(target,hash,expires_at) values($1,$2,now()+interval '5 minutes')", [u[ch], await bcrypt.hash(code, 8)]);
  await sendOtp(ch, u[ch], code); res.json(E.DEV_MOCK_PAY === '1' ? { ok: 1, devCode: code } : { ok: 1 });
}));
app.post('/api/otp/verify', auth, lim(15, 20), wrap(async (req, res) => {
  const ch = chan(req), [u] = await q('select email,mobile from users where id=$1', [req.user.id]);
  const [o] = await q('select * from otps where target=$1 and used=false and expires_at>now() order by id desc limit 1', [u[ch]]);
  if (!o || o.attempts >= 5) return res.status(400).json({ error: 'OTP expired. Request a new one' });
  if (!(await bcrypt.compare(String(req.body.code || ''), o.hash))) { await q('update otps set attempts=attempts+1 where id=$1', [o.id]); return res.status(400).json({ error: 'Wrong OTP' }); }
  await q('update otps set used=true where id=$1', [o.id]);
  await q(`update users set ${ch}_verified=true where id=$1`, [req.user.id]); res.json({ ok: 1 });
}));

app.get('/api/config', (req, res) => res.json({ rzpKey: E.RAZORPAY_KEY_ID || null, mock: E.DEV_MOCK_PAY === '1' }));
app.get('/api/admin-key', auth, wrap(async (req, res) => res.json((await q("select pubkey from users where role='admin' limit 1"))[0] || {})));
app.get('/api/me', auth, wrap(async (req, res) => {
  const [f] = await q("select f.id,f.status,exists(select 1 from payments where filing_id=f.id and status='paid') paid from filings f where f.user_id=$1 and f.assessment_year=$2", [req.user.id, AY]);
  const [u] = await q('select email_verified e, mobile_verified m from users where id=$1', [req.user.id]);
  const results = f ? await q("select id,name from files where filing_id=$1 and kind='result'", [f.id]) : [];
  res.json({ ...f, ay: AY, emailOk: u.e, mobileOk: u.m, results });
}));

app.post('/api/files', auth, verified, up.single('file'), wrap(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file received' });
  const [f] = await q('select id from filings where user_id=$1 and assessment_year=$2', [req.user.id, AY]);
  await q("insert into files(filing_id,kind,name,path,iv,wkey,size) values($1,'upload',$2,$3,$4,$5,$6)", [f.id, req.body.name, req.file.path, req.body.iv, req.body.wkey, req.file.size]);
  await q("update filings set status='Uploaded' where id=$1 and status='Registered'", [f.id]);
  await audit(req.user.id, 'upload', f.id, req.ip); res.json({ ok: 1 });
}));
app.get('/api/file/:id', auth, wrap(async (req, res) => {
  const [f] = await q('select f.*, fl.user_id from files f join filings fl on fl.id=f.filing_id where f.id=$1', [req.params.id]);
  if (!f || (req.user.role !== 'admin' && (f.user_id !== req.user.id || f.kind !== 'result'))) return res.status(404).json({ error: 'File not found' });
  await audit(req.user.id, 'download', f.id, req.ip);
  res.set({ 'x-iv': f.iv, 'x-wkey': f.wkey, 'x-name': encodeURIComponent(f.name) }); res.sendFile(path.resolve(f.path));
}));

app.post('/api/pay/order', auth, verified, wrap(async (req, res) => {
  const [f] = await q('select * from filings where user_id=$1 and assessment_year=$2', [req.user.id, AY]);
  if (f.status !== 'Uploaded') return res.status(400).json({ error: 'Upload your Form 16 first, or payment is already done' });
  const o = rzp ? await rzp.orders.create({ amount: FEE, currency: 'INR', receipt: f.id.slice(0, 30) }) : { id: 'mock_' + crypto.randomUUID() };
  await q('insert into payments(filing_id,rzp_order_id,amount_paise) values($1,$2,$3)', [f.id, o.id, FEE]);
  res.json({ orderId: o.id, amount: FEE });
}));
app.post('/api/pay/mock', auth, wrap(async (req, res) => {
  if (E.DEV_MOCK_PAY !== '1') return res.status(404).end();
  const [p] = await q("select p.rzp_order_id from payments p join filings f on f.id=p.filing_id where f.user_id=$1 and p.status='created' order by p.created_at desc limit 1", [req.user.id]);
  if (p) await markPaid(p.rzp_order_id, 'mock'); res.json({ ok: 1 });
}));

app.get('/api/admin/cases', auth, admin, wrap(async (req, res) => res.json(await q(
  `select u.id,u.name,u.email,u.mobile,f.status,
   exists(select 1 from payments where filing_id=f.id and status='paid') paid,
   coalesce((select json_agg(json_build_object('id',x.id,'name',x.name)) from files x where x.filing_id=f.id and x.kind='upload'),'[]') files
   from users u join filings f on f.user_id=u.id where u.role='employee' order by f.created_at desc`))));
app.get('/api/admin/user-key/:id', auth, admin, wrap(async (req, res) => res.json((await q('select pubkey from users where id=$1', [req.params.id]))[0])));
app.post('/api/admin/result/:uid', auth, admin, up.single('file'), wrap(async (req, res) => {
  const [f] = await q('select id from filings where user_id=$1 and assessment_year=$2', [req.params.uid, AY]);
  await q("insert into files(filing_id,kind,name,path,iv,wkey,size) values($1,'result',$2,$3,$4,$5,$6)", [f.id, req.body.name, req.file.path, req.body.iv, req.body.wkey, req.file.size]);
  await q("update filings set status='Completed' where id=$1", [f.id]);
  await audit(req.user.id, 'result_upload', f.id, req.ip); res.json({ ok: 1 });
}));

app.use((e, req, res, next) => {
  if (e.name === 'ZodError') return res.status(400).json({ error: 'Please check the details you entered' });
  console.error(e); res.status(500).json({ error: 'Something went wrong. Try again' });
});
app.listen(3000, () => console.log('API on :3000'));
