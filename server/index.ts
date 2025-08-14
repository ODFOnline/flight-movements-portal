import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import xlsx from 'xlsx';
import { execSync } from 'node:child_process';
import { PrismaClient } from '@prisma/client';
import { extract, parse } from './pdf.js';

const app = express();
const prisma = new PrismaClient();

const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(cors({ origin: '*', credentials: true }));

type Role = 'USER' | 'ADMIN';
type JwtBody = { uid: number; role: Role };

function sign(uid: number, role: Role) {
  return jwt.sign({ uid, role } as JwtBody, process.env.JWT_SECRET || 'dev', { expiresIn: '7d' });
}
function requireAuth(req: any, res: any, next: any) {
  const token = req.cookies.sid || (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(token, process.env.JWT_SECRET || 'dev'); next(); }
  catch { return res.status(401).json({ error: 'Unauthorized' }); }
}
function requireRole(role: 'ADMIN') {
  return (req: any, res: any, next: any) => {
    if (!req.user || req.user.role !== role) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => cb(null, Date.now() + '_' + file.originalname.replace(/\s+/g, '_')),
});
const upload = multer({ storage });

// Health
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// -------- TEMP: Force login (and create admin if missing) ----------
app.get('/api/_force_login', async (req: any, res: any) => {
  try {
    const expected = (process.env.FORCE_LOGIN_TOKEN || '').trim();
    const got = String((req.query.token || '')).trim();
    if (!expected || got !== expected) return res.status(403).json({ error: 'forbidden' });

    const username = process.env.ADMIN_USERNAME || 'odf-admin';
    const pw = process.env.ADMIN_PASSWORD || 'SuperSecurePass!24';

    let user = await prisma.user.findUnique({ where: { username } }).catch(() => null);
    if (!user) {
      const hash = await bcrypt.hash(pw, 11);
      user = await prisma.user.create({ data: { username, passwordHash: hash, role: 'ADMIN' } });
    } else if (user.role !== 'ADMIN') {
      user = await prisma.user.update({ where: { id: user.id }, data: { role: 'ADMIN' } });
    }

    const token = sign(user.id, 'ADMIN');
    res.cookie('sid', token, {
      httpOnly: true, sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 3600 * 1000,
    });
    return res.json({ ok: true, role: 'ADMIN', username });
  } catch (e) {
    console.error('force_login error', e);
    return res.status(500).json({ error: 'force_login_failed' });
  }
});

// Logout
app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('sid', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
  res.json({ ok: true });
});

// Login (form-based clients)
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const user = await prisma.user.findUnique({ where: { username }, include: { member: true } });
  if (!user) return res.status(401).json({ error: 'Invalid login' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid login' });

  const role: Role = user.role === 'ADMIN' ? 'ADMIN' : 'USER';
  const token = sign(user.id, role);
  res.cookie('sid', token, {
    httpOnly: true, sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 3600 * 1000,
  });
  res.json({ ok: true, role, memberId: user.memberId ?? null, name: user.member?.fullName ?? null });
});

// Register (optional)
app.post('/api/auth/register', async (req, res) => {
  const { code, username, password } = req.body || {};
  if (!code || !password) return res.status(400).json({ error: 'Missing fields' });

  const tok = await prisma.enrollmentToken.findUnique({ where: { code }, include: { member: true } });
  if (!tok) return res.status(400).json({ error: 'Invalid code' });
  if (tok.usedAt) return res.status(400).json({ error: 'Code already used' });
  if (tok.expiresAt && tok.expiresAt < new Date()) return res.status(400).json({ error: 'Code expired' });

  const uname = (username || tok.username || tok.member.fullName.replace(/[^A-Za-z0-9]/g, '').toLowerCase()).slice(0, 32);
  const exists = await prisma.user.findUnique({ where: { username: uname } });
  if (exists) return res.status(400).json({ error: 'Username taken. Choose another.' });
  if (String(password).length < 12) return res.status(400).json({ error: 'Use at least 12 characters' });

  const hash = await bcrypt.hash(password, 11);
  const user = await prisma.user.create({ data: { username: uname, passwordHash: hash, role: 'USER', memberId: tok.memberId } });
  await prisma.enrollmentToken.update({ where: { id: tok.id }, data: { usedAt: new Date() } });

  const token = sign(user.id, 'USER');
  res.cookie('sid', token, {
    httpOnly: true, sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 3600 * 1000,
  });
  res.json({ ok: true });
});

// Admin: add user
app.post('/api/admin/users', requireAuth, requireRole('ADMIN'), async (req: any, res: any) => {
  const { username, password, role = 'USER', memberFullName } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  const hash = await bcrypt.hash(password, 10);
  let memberId: number | undefined;
  if (memberFullName) {
    const m = await prisma.member.findUnique({ where: { fullName: memberFullName } });
    if (!m) return res.status(400).json({ error: 'member not found' });
    memberId = m.id;
  }
  const safeRole: Role = role === 'ADMIN' ? 'ADMIN' : 'USER';
  const user = await prisma.user.create({ data: { username, passwordHash: hash, role: safeRole, memberId } });
  res.json({ id: user.id, username: user.username, role: user.role, memberId: user.memberId ?? null });
});

// Admin: upload PDFs
app.post('/api/upload', requireAuth, requireRole('ADMIN'), upload.array('pdfs', 50), async (req, res) => {
  const results: any[] = [];
  for (const f of (req.files as Express.Multer.File[])) {
    const buf = fs.readFileSync(f.path);
    const lines = await extract(buf);
    const parsed = parse(lines);

    const member = await prisma.member.upsert({
      where: { fullName: parsed.traveler },
      update: {},
      create: { fullName: parsed.traveler },
    });

    const itin = await prisma.itinerary.create({
      data: { pnr: parsed.pnr, vendorRef: undefined, pdfPath: f.path, memberId: member.id },
    });

    await prisma.flight.deleteMany({ where: { memberId: member.id, pnr: parsed.pnr || undefined } });

    let idx = 0;
    for (const s of parsed.segments) {
      await prisma.flight.create({
        data: {
          carrier: s.carrier,
          flightNum: s.flightNum,
          departIATA: s.departIATA,
          departName: s.departName,
          departDT: s.departDT ? new Date(s.departDT) : new Date(),
          arriveIATA: s.arriveIATA,
          arriveName: s.arriveName,
          arriveDT: s.arriveDT ? new Date(s.arriveDT) : new Date(),
          equipment: s.equipment,
          pnr: parsed.pnr,
          segmentIdx: idx++,
          memberId: member.id,
          itineraryId: itin.id,
        },
      });
    }
    results.push({ file: f.originalname, member: member.fullName, segments: parsed.segments.length });
  }
  res.json({ imported: results });
});

// Admin: upload roster (.xlsx)
app.post('/api/admin/upload-roster', requireAuth, requireRole('ADMIN'), upload.single('roster'), async (req: any, res: any) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });

    const buf = fs.readFileSync(req.file.path);
    const wb = xlsx.read(buf, { type: 'buffer' });
    const sheetName = wb.SheetNames[0];
    const rows: any[] = xlsx.utils.sheet_to_json(wb.Sheets[sheetName], { defval: '' });

    const normalize = (s: string) => String(s || '').trim();
    let imported = 0;

    for (const r of rows) {
      const fullName =
        normalize(r['Full Name']) ||
        normalize(r['Name']) ||
        normalize(r['Member']) ||
        normalize(r['Traveler']) ||
        normalize(r['Passenger']) ||
        '';
      if (!fullName) continue;

      const member = await prisma.member.upsert({
        where: { fullName },
        update: {},
        create: { fullName },
      });

      const code = Math.random().toString(36).slice(2, 8).toUpperCase();
      await prisma.enrollmentToken.create({
        data: { code, memberId: member.id, expiresAt: null },
      });

      imported++;
    }
    res.json({ ok: true, imported });
  } catch (e) {
    console.error('upload-roster error', e);
    res.status(500).json({ error: 'upload_roster_failed' });
  }
});

// Movements
app.get('/api/movements', requireAuth, async (req: any, res: any) => {
  const isAdmin = req.user.role === 'ADMIN';
  const q = (req.query.q as string)?.trim();
  let members;

  if (isAdmin && q) {
    members = await prisma.member.findMany({
      where: { fullName: { contains: q } },
      include: {
        flights: { orderBy: [{ departDT: 'asc' }, { segmentIdx: 'asc' }] },
        itineraries: { orderBy: { uploadedAt: 'desc' } },
      },
    });
  } else if (isAdmin && !q) {
    members = await prisma.member.findMany({
      take: 100,
      orderBy: { fullName: 'asc' },
      include: {
        flights: { orderBy: [{ departDT: 'asc' }, { segmentIdx: 'asc' }] },
        itineraries: { orderBy: { uploadedAt: 'desc' } },
      },
    });
  } else {
    const me = await prisma.user.findUnique({ where: { id: req.user.uid } });
    if (!me?.memberId) return res.json({ data: [] });
    const m = await prisma.member.findUnique({
      where: { id: me.memberId },
      include: {
        flights: { orderBy: [{ departDT: 'asc' }, { segmentIdx: 'asc' }] },
        itineraries: { orderBy: { uploadedAt: 'desc' } },
      },
    });
    members = m ? [m] : [];
  }

  const now = Date.now();
  const data = members.map((m: any) => {
    const next = m.flights.find((f: any) => new Date(f.departDT).getTime() >= now) || m.flights.at(-1);
    return {
      id: m.id,
      fullName: m.fullName,
      nextFlight: next
        ? {
            carrier: next.carrier,
            flightNum: next.flightNum,
            depart: { iata: next.departIATA, name: next.departName, at: next.departDT },
            arrive: { iata: next.arriveIATA, name: next.arriveName, at: next.arriveDT },
          }
        : null,
      latestItineraryId: m.itineraries[0]?.id ?? null,
    };
  });

  res.set('Cache-Control', 'no-store');
  res.json({ data });
});

// -------- Minimal Admin HTML (no React needed) ----------
app.get('/admin-debug', async (req: any, res: any) => {
  const who = (() => {
    try { return jwt.verify(req.cookies.sid || '', process.env.JWT_SECRET || 'dev') as JwtBody; }
    catch { return null; }
  })();

  const forceToken = process.env.FORCE_LOGIN_TOKEN ? 'set' : 'unset';
  const html = `<!doctype html><html><head>
  <meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin Debug</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto;max-width:860px;margin:24px auto;padding:0 12px}
    .box{border:1px solid #ddd;border-radius:8px;padding:16px;margin:12px 0}
    code{background:#f6f6f6;padding:2px 6px;border-radius:4px}
    .row{display:flex;gap:10px;align-items:center}
    .muted{color:#666}
  </style>
  </head><body>
    <h2>Flight Movements — Admin Debug</h2>
    <div class="box">
      <div><strong>Status:</strong> ${who ? `Logged in as <code>${who.role}</code>` : 'Not logged in'}</div>
      <div class="muted">FORCE_LOGIN_TOKEN is ${forceToken}</div>
      <div class="row" style="margin-top:10px">
        <a href="/api/health" target="_blank">Health</a>
        <button onclick="forceLogin()">Force Login (Admin)</button>
        <button onclick="logout()">Logout</button>
      </div>
    </div>

    <div class="box">
      <h3>Upload Roster (.xlsx)</h3>
      <form id="rosterForm" method="post" action="/api/admin/upload-roster" enctype="multipart/form-data">
        <input type="file" name="roster" accept=".xlsx" required />
        <button type="submit">Upload Roster</button>
      </form>
      <pre id="rosterOut" class="muted"></pre>
    </div>

    <div class="box">
      <h3>Upload Itinerary PDFs</h3>
      <form id="pdfForm" method="post" action="/api/upload" enctype="multipart/form-data">
        <input type="file" name="pdfs" accept=".pdf" multiple required />
        <button type="submit">Upload PDFs</button>
      </form>
      <pre id="pdfOut" class="muted"></pre>
    </div>

    <div class="box">
      <h3>Preview Movements (first 10)</h3>
      <button onclick="fetchMovements()">Load</button>
      <pre id="movementsOut" class="muted"></pre>
    </div>

<script>
async function forceLogin(){
  const u = new URL('/api/_force_login', location.origin);
  u.searchParams.set('token','${(process.env.FORCE_LOGIN_TOKEN||'').replace(/"/g,'&quot;')}');
  const r = await fetch(u, { credentials:'include' });
  document.querySelector('#movementsOut').textContent = await r.text();
  alert('Force login attempted. If ok:true, you are now admin.');
}
async function logout(){
  await fetch('/api/auth/logout', { method:'POST', credentials:'include' });
  alert('Logged out');
  location.reload();
}
document.querySelector('#rosterForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await fetch('/api/admin/upload-roster', { method:'POST', body:fd, credentials:'include' });
  document.querySelector('#rosterOut').textContent = await r.text();
});
document.querySelector('#pdfForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await fetch('/api/upload', { method:'POST', body:fd, credentials:'include' });
  document.querySelector('#pdfOut').textContent = await r.text();
});
async function fetchMovements(){
  const r = await fetch('/api/movements', { credentials:'include' });
  document.querySelector('#movementsOut').textContent = await r.text();
}
</script>
  </body></html>`;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// -------- Serve built frontend (kept for later) ----------
app.use(express.static('client/dist'));
app.get('*', (_req, res) => res.sendFile('client/dist/index.html', { root: '.' }));

// -------- Ensure DB & Prisma client ready ----------
function ensureDb() {
  try {
    execSync('npx prisma db push --schema=server/schema.prisma', { stdio: 'inherit' });
    execSync('npx prisma generate --schema=server/schema.prisma', { stdio: 'inherit' });
    console.log('✅ Database ready');
  } catch (e) {
    console.error('DB prepare failed', e);
  }
}

app.listen(process.env.PORT || 8080, async () => {
  console.log('API on', process.env.PORT || 8080);
  ensureDb();
});
