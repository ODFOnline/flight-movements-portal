import React, { useState, useEffect } from 'react';

type LoginResp = { ok: boolean; role: 'ADMIN' | 'USER'; memberId?: number | null; name?: string | null };
type MovementsResp = {
  data: Array<{
    id: number;
    fullName: string;
    nextFlight: null | {
      carrier: string; flightNum: string;
      depart: { iata: string; name: string; at: string };
      arrive: { iata: string; name: string; at: string };
    };
    latestItineraryId: number | null;
  }>;
};

async function api<T = any>(path: string, opts: RequestInit & { body?: any } = {}) {
  const res = await fetch(`/api${path}`, {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    credentials: 'include',
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  try {
    const json = text ? JSON.parse(text) : {};
    if (!res.ok) throw json;
    return json as T;
  } catch {
    if (!res.ok) throw new Error(text || `HTTP ${res.status}`);
    return {} as T;
  }
}

export default function App() {
  const [stage, setStage] = useState<'checking'|'login'|'dashboard'>('checking');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loginErr, setLoginErr] = useState<string | null>(null);
  const [who, setWho] = useState<{ role: 'ADMIN'|'USER'; name?: string|null } | null>(null);
  const [movements, setMovements] = useState<MovementsResp['data']>([]);
  const [q, setQ] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const ping = await fetch('/api/health', { credentials: 'include' });
        if (ping.ok) setStage('login'); else setStage('login');
      } catch { setStage('login'); }
    })();
  }, []);

  async function doLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoginErr(null);
    try {
      const resp = await api<LoginResp>('/auth/login', { method: 'POST', body: { username, password } });
      setWho({ role: resp.role, name: resp.name ?? null });
      setStage('dashboard');
      loadMovements('');
    } catch (e: any) {
      setLoginErr(e?.error || e?.message || 'Login failed');
    }
  }

  async function loadMovements(query: string) {
    const qs = query ? `?q=${encodeURIComponent(query)}` : '';
    const data = await api<MovementsResp>(`/movements${qs}`);
    setMovements(data.data || []);
  }

  // --- Admin uploads ---
  const [rosterMsg, setRosterMsg] = useState<string>('');
  const [pdfMsg, setPdfMsg] = useState<string>('');

  async function uploadRoster(file: File) {
    setRosterMsg('Uploading roster…');
    const fd = new FormData();
    fd.append('roster', file);
    const res = await fetch('/api/admin/upload-roster', { method: 'POST', body: fd, credentials: 'include' });
    const txt = await res.text();
    try {
      const json = JSON.parse(txt);
      if (!res.ok) throw json;
      setRosterMsg(`Imported ${json.imported} members`);
    } catch {
      setRosterMsg(`Error: ${txt || res.status}`);
    }
  }

  async function uploadPdfs(files: FileList) {
    setPdfMsg('Uploading PDFs…');
    const fd = new FormData();
    Array.from(files).forEach(f => fd.append('pdfs', f));
    const res = await fetch('/api/upload', { method: 'POST', body: fd, credentials: 'include' });
    const txt = await res.text();
    try {
      const json = JSON.parse(txt);
      if (!res.ok) throw json;
      setPdfMsg(`Imported ${json.imported?.length ?? 0} PDFs`);
    } catch {
      setPdfMsg(`Error: ${txt || res.status}`);
    }
  }

  function fmt(dt?: string) {
    if (!dt) return '';
    const d = new Date(dt);
    return d.toLocaleString();
  }

  if (stage !== 'dashboard') {
    return (
      <div style={{ maxWidth: 520, margin: '80px auto', fontFamily: 'system-ui, -apple-system, Segoe UI, Roboto' }}>
        <h1 style={{ marginBottom: 8 }}>Flight Movements</h1>
        <p style={{ color: '#666', marginTop: 0 }}>Sign in to view movements and itineraries.</p>
        <form onSubmit={doLogin} style={{ display: 'grid', gap: 10 }}>
          <label>
            <div>Username</div>
            <input value={username} onChange={e => setUsername(e.target.value)} required style={{ width: '100%', padding: 8 }} />
          </label>
          <label>
            <div>Password</div>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} required style={{ width: '100%', padding: 8 }} />
          </label>
          {loginErr && <div style={{ color: '#b00020' }}>{loginErr}</div>}
          <button type="submit" style={{ padding: '10px 14px' }}>Log in</button>
        </form>
      </div>
    );
  }

  const isAdmin = who?.role === 'ADMIN';

  return (
    <div style={{ maxWidth: 1000, margin: '30px auto', fontFamily: 'system-ui, -apple-system, Segoe UI, Roboto' }}>
      <h2 style={{ marginBottom: 8 }}>Welcome {who?.name ? who.name : isAdmin ? 'Admin' : ''}</h2>

      {isAdmin && (
        <div style={{ padding: 16, border: '1px solid #eee', borderRadius: 8, marginBottom: 18 }}>
          <h3 style={{ marginTop: 0 }}>Admin</h3>
          <div style={{ display: 'grid', gap: 12 }}>
            <div>
              <strong>Upload Roster (.xlsx)</strong><br />
              <input type="file" accept=".xlsx" onChange={e => e.target.files && e.target.files[0] && uploadRoster(e.target.files[0])} />
              <div style={{ fontSize: 12, color: '#555' }}>{rosterMsg}</div>
            </div>
            <div>
              <strong>Upload Itinerary PDFs</strong><br />
              <input type="file" accept=".pdf" multiple onChange={e => e.target.files && e.target.files.length && uploadPdfs(e.target.files)} />
              <div style={{ fontSize: 12, color: '#555' }}>{pdfMsg}</div>
            </div>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 16 }}>
        {isAdmin && (
          <>
            <input
              placeholder="Search members…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              style={{ padding: 8, flex: 1 }}
            />
            <button onClick={() => loadMovements(q)}>Search</button>
          </>
        )}
        {!isAdmin && <button onClick={() => loadMovements('')}>Refresh</button>}
      </div>

      {movements.length === 0 ? (
        <div style={{ color: '#666' }}>No movement data yet. Upload a roster and PDF itineraries from the Admin box above.</div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #ddd' }}>
              <th>Name</th>
              <th>Next Flight</th>
              <th>Departure</th>
              <th>Arrival</th>
              <th>Itinerary</th>
            </tr>
          </thead>
          <tbody>
            {movements.map(m => (
              <tr key={m.id} style={{ borderBottom: '1px solid #f0f0f0' }}>
                <td>{m.fullName}</td>
                <td>{m.nextFlight ? `${m.nextFlight.carrier} ${m.nextFlight.flightNum}` : '-'}</td>
                <td>{m.nextFlight ? `${m.nextFlight.depart.iata} – ${fmt(m.nextFlight.depart.at)}` : '-'}</td>
                <td>{m.nextFlight ? `${m.nextFlight.arrive.iata} – ${fmt(m.nextFlight.arrive.at)}` : '-'}</td>
                <td>
                  {m.latestItineraryId
                    ? <a href={`/api/itineraries/${m.latestItineraryId}/pdf`} target="_blank" rel="noreferrer">Download PDF</a>
                    : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
