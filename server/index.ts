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

// ---------- auth helpers ----------
type JwtBody = { uid: number; role: Role };
function sign(uid: number, role: Role) {
  return jwt.sign({ uid, role } as JwtBody, process.env.JWT_SECRET || 'dev', { expiresIn: '7d' });
}
function requireAuth(req: any, res: any, next: any) {
  const token = req.cookies.sid || (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'dev');
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}
function requireRole(role: 'ADMIN') {
  return (req: any, res: any, next: any) => {
    if (!req.user || req.user.role !== role) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

// ---------- uploads ----------
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => cb(null, Date.now() + '_' + file.originalname.replace(/\s+/g, '_')),
});
const upload = multer({ storage });

// ---------- health ----------
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// ------------------ FORCE LOGIN ROUTE ------------------
app.get('/api/_force_login', async (req: any, res: any) => {
  try {
    const expected = process.env.FORCE_LOGIN_TOKEN || '';
    const got = String(req.query.token || '');
    if (!expected || got !== expected) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const username = process.env.ADMIN_USERNAME || 'odf-admin';
    const pw = process.env.ADMIN_PASSWORD || 'SuperSecurePass!24';

    // Ensure admin exists
    let user = await prisma.user.findUnique({ where: { username } }).catch(() => null);
    if (!user) {
      const hash = await bcrypt.hash(pw, 11);
      user = await prisma.user.create({ data: { username, passwordHash: hash, role: 'ADMIN' as Role } });
    } else if (user.role !== 'ADMIN') {
      user = await prisma.user.update({ where: { id: user.id }, data: { role: 'ADMIN' as Role } });
    }

    const token = sign(user.id, 'ADMIN');
    res.cookie('sid', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 3600 * 1000,
    });
    return res.json({ ok: true, role: 'ADMIN', username });
  } catch (e) {
    console.error('force_login error', e);
    return res.status(500).json({ error: 'force_login_failed' });
  }
});
// --------------------------------------------------------

// ---------- auth routes ----------
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const user = await prisma.user.findUnique({ where: { username }, include: { member: true } });
  if (!user) return res.status(401).json({ error: 'Invalid login' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid login' });

  // Coerce Prisma string role into our union type
  const role: Role = user.role === 'ADMIN' ? 'ADMIN' : 'USER';

  const token = sign(user.id, role);
  res.cookie('sid', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 3600 * 1000,
  });
  res.json({ ok: true, role, memberId: user.memberId ?? null, name: user.member?.fullName ?? null });
});

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
  const user = await prisma.user.create({ data: { username: uname, passwordHash: hash, role: 'USER' as Role, memberId: tok.memberId } });
  await prisma.enrollmentToken.update({ where: { id: tok.id }, data: { usedAt: new Date() } });

  const token = sign(user.id, 'USER');
  res.cookie('sid', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 3600 * 1000,
  });
  res.json({ ok: true });
});

// ---------- admin: create user manually ----------
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

// ---------- admin: upload itinerary PDFs ----------
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

// ---------- admin: upload roster (.xlsx) ----------
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

// ---------- movements & itineraries ----------
app.get('/api/movements', requireAuth, async (req: any, res: any) => {
  const isAdmin = req.user.role === 'ADMIN';
  const q = (req.query.q as string)?.trim();
  let members;

  if (isAdmin && q) {
    members = await prisma.member.findMany({
      where: { fullName: { contains: q } }, // removed mode:'insensitive' for SQLite compatibility
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

app.get('/api/itineraries/:id/pdf', requireAuth, async (req: any, res: any) => {
  const id = Number(req.params.id);
  const itin = await prisma.itinerary.findUnique({ where: { id }, include: { member: true } });
  if (!itin) return res.status(404).end();

  if (req.user.role !== 'ADMIN') {
    const me = await prisma.user.findUnique({ where: { id: req.user.uid } });
    if (me?.memberId !== itin.memberId) return res.status(403).json({ error: 'Forbidden' });
  }
  res.sendFile(path.resolve(itin.pdfPath));
});

// ---------- serve the built frontend ----------
app.use(express.static('client/dist'));
app.get('*', (_req, res) => res.sendFile('client/dist/index.html', { root: '.' }));

// ---------- DB init ----------
function ensureDb() {
  try {
    execSync('npx prisma db push --schema=server/schema.prisma', { stdio: 'inherit' });
    execSync('npx prisma generate --schema=server/schema.prisma', { stdio: 'inherit' });
    console.log('✅ Database ready');
  } catch (e) {
    console.error('DB prepare failed', e);
  }
}

// ---------- boot ----------
app.listen(process.env.PORT || 8080, async () => {
  console.log('API on', process.env.PORT || 8080);
  ensureDb();
});
