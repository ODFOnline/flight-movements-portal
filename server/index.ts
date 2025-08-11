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
import { PrismaClient } from '@prisma/client';
import { extract, parse } from './pdf.js';

const app = express();
const prisma = new PrismaClient();

const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.use(helmet());
app.use(express.json({ limit:'10mb' }));
app.use(cookieParser());
app.use(cors({ origin: '*', credentials: true }));

type JwtBody = { uid:number, role:'USER'|'ADMIN' };
function sign(uid:number, role:'USER'|'ADMIN'){
  return jwt.sign({ uid, role } as JwtBody, process.env.JWT_SECRET || 'dev', { expiresIn:'7d' });
}
function requireAuth(req:any, res:any, next:any){
  const token = req.cookies.sid || (req.headers.authorization||'').replace('Bearer ', '');
  try { req.user = jwt.verify(token, process.env.JWT_SECRET || 'dev'); next(); }
  catch { return res.status(401).json({ error:'Unauthorized' }); }
}
function requireRole(role:'ADMIN'){
  return (req:any,res:any,next:any)=>{
    if (!req.user || req.user.role !== role) return res.status(403).json({ error:'Forbidden' });
    next();
  }
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => cb(null, Date.now() + '_' + file.originalname.replace(/\s+/g, '_'))
});
const upload = multer({ storage });

app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error:'Missing credentials' });
  const user = await prisma.user.findUnique({ where:{ username }, include:{ member:true } });
  if (!user) return res.status(401).json({ error:'Invalid login' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error:'Invalid login' });
  const token = sign(user.id, user.role);
  res.cookie('sid', token, { httpOnly:true, sameSite:'lax', secure: process.env.NODE_ENV==='production', maxAge: 7*24*3600*1000 });
  res.json({ ok:true, role:user.role, memberId:user.memberId ?? null, name:user.member?.fullName ?? null });
});

app.post('/api/auth/register', async (req, res) => {
  const { code, username, password } = req.body || {};
  if (!code || !password) return res.status(400).json({ error:'Missing fields' });
  const tok = await prisma.enrollmentToken.findUnique({ where:{ code }, include:{ member:true } });
  if (!tok) return res.status(400).json({ error:'Invalid code' });
  if (tok.usedAt) return res.status(400).json({ error:'Code already used' });
  if (tok.expiresAt && tok.expiresAt < new Date()) return res.status(400).json({ error:'Code expired' });

  const uname = (username || tok.username || tok.member.fullName.replace(/[^A-Za-z0-9]/g,'').toLowerCase()).slice(0,32);
  const exists = await prisma.user.findUnique({ where:{ username: uname } });
  if (exists) return res.status(400).json({ error:'Username taken. Choose another.' });
  if (String(password).length < 12) return res.status(400).json({ error:'Use at least 12 characters' });

  const hash = await bcrypt.hash(password, 11);
  const user = await prisma.user.create({ data:{ username: uname, passwordHash: hash, role:'USER', memberId: tok.memberId } });
  await prisma.enrollmentToken.update({ where:{ id: tok.id }, data:{ usedAt: new Date() } });
  const token = sign(user.id, 'USER');
  res.cookie('sid', token, { httpOnly:true, sameSite:'lax', secure: process.env.NODE_ENV==='production', maxAge: 7*24*3600*1000 });
  res.json({ ok:true });
});

app.post('/api/admin/users', requireAuth, requireRole('ADMIN'), async (req:any, res:any)=>{
  const { username, password, role='USER', memberFullName } = req.body || {};
  if (!username || !password) return res.status(400).json({ error:'username and password required' });
  const hash = await bcrypt.hash(password, 10);
  let memberId: number | undefined;
  if (memberFullName){
    const m = await prisma.member.findUnique({ where:{ fullName: memberFullName }});
    if (!m) return res.status(400).json({ error:'member not found' });
    memberId = m.id;
  }
  const user = await prisma.user.create({ data:{ username, passwordHash:hash, role, memberId } });
  res.json({ id:user.id, username:user.username, role:user.role, memberId:user.memberId ?? null });
});

app.post('/api/upload', requireAuth, requireRole('ADMIN'), upload.array('pdfs', 50), async (req, res) => {
  const results:any[] = [];
  for (const f of (req.files as Express.Multer.File[])) {
    const buf = fs.readFileSync(f.path);
    const lines = await extract(buf);
    const parsed = parse(lines);

    const member = await prisma.member.upsert({
      where: { fullName: parsed.traveler },
      update: {},
      create: { fullName: parsed.traveler }
    });

    const itin = await prisma.itinerary.create({
      data: { pnr: parsed.pnr, vendorRef: undefined, pdfPath: f.path, memberId: member.id }
    });

    await prisma.flight.deleteMany({ where: { memberId: member.id, pnr: parsed.pnr || undefined } });

    let idx = 0;
    for (const s of parsed.segments) {
      await prisma.flight.create({
        data: {
          carrier: s.carrier, flightNum: s.flightNum,
          departIATA: s.departIATA, departName: s.departName,
          departDT: s.departDT ? new Date(s.departDT) : new Date(),
          arriveIATA: s.arriveIATA, arriveName: s.arriveName,
          arriveDT: s.arriveDT ? new Date(s.arriveDT) : new Date(),
          equipment: s.equipment, pnr: parsed.pnr,
          segmentIdx: idx++, memberId: member.id, itineraryId: itin.id
        }
      });
    }
    results.push({ file: f.originalname, member: member.fullName, segments: parsed.segments.length });
  }
  res.json({ imported: results });
});

app.get('/api/movements', requireAuth, async (req:any, res:any) => {
  const isAdmin = req.user.role === 'ADMIN';
  const q = (req.query.q as string)?.trim();
  let members;
  if (isAdmin && q){
    members = await prisma.member.findMany({ where:{ fullName:{ contains:q, mode:'insensitive' }}, include:{ flights:{ orderBy:[{ departDT:'asc' },{ segmentIdx:'asc' }]}, itineraries:{ orderBy:{ uploadedAt:'desc' }}}});
  } else if (isAdmin && !q){
    members = await prisma.member.findMany({ take:100, orderBy:{ fullName:'asc' }, include:{ flights:{ orderBy:[{ departDT:'asc' },{ segmentIdx:'asc' }]}, itineraries:{ orderBy:{ uploadedAt:'desc' }}}});
  } else {
    const me = await prisma.user.findUnique({ where:{ id:req.user.uid }});
    if (!me?.memberId) return res.json({ data: [] });
    const m = await prisma.member.findUnique({ where:{ id:me.memberId }, include:{ flights:{ orderBy:[{ departDT:'asc' },{ segmentIdx:'asc' }]}, itineraries:{ orderBy:{ uploadedAt:'desc' }}}});
    members = m ? [m] : [];
  }
  const now = Date.now();
  const data = members.map((m:any)=>{
    const next = m.flights.find((f:any) => new Date(f.departDT).getTime() >= now) || m.flights.at(-1);
    return {
      id: m.id, fullName: m.fullName,
      nextFlight: next ? {
        carrier: next.carrier, flightNum: next.flightNum,
        depart: { iata: next.departIATA, name: next.departName, at: next.departDT },
        arrive: { iata: next.arriveIATA, name: next.arriveName, at: next.arriveDT }
      } : null,
      latestItineraryId: m.itineraries[0]?.id ?? null
    };
  });
  res.set('Cache-Control', 'no-store');
  res.json({ data });
});

app.get('/api/itineraries/:id/pdf', requireAuth, async (req:any, res:any)=>{
  const id = Number(req.params.id);
  const itin = await prisma.itinerary.findUnique({ where:{ id }, include:{ member:true } });
  if (!itin) return res.status(404).end();
  if (req.user.role !== 'ADMIN'){
    const me = await prisma.user.findUnique({ where:{ id:req.user.uid }});
    if (me?.memberId !== itin.memberId) return res.status(403).json({ error:'Forbidden' });
  }
  res.sendFile(path.resolve(itin.pdfPath));
});

# Serve built frontend (for single-service hosting)
app.use(express.static('client/dist'));
app.get('*', (_req,res)=>res.sendFile('client/dist/index.html',{root:'.'}));

app.listen(process.env.PORT || 8080, () => {
async function bootstrapAdmin() {
  try {
    if (process.env.ADMIN_BOOTSTRAP !== '1') return;
    const count = await prisma.user.count();
    if (count > 0) return;

    const username = process.env.ADMIN_USERNAME || 'odf-admin';
    const pw = process.env.ADMIN_PASSWORD || 'SuperSecurePass!24';
    const hash = await bcrypt.hash(pw, 11);

    await prisma.user.create({
      data: { username, passwordHash: hash, role: 'ADMIN' }
    });

    console.log(`✅ Admin created: ${username}`);
  } catch (e) {
    console.error('bootstrapAdmin error', e);
  }
}

  console.log('API on', process.env.PORT || 8080);
});
