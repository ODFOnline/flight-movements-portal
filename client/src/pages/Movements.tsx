import React from 'react'
type Row = {
  id:number; fullName:string; latestItineraryId:number|null;
  nextFlight: null | { carrier:string;flightNum:string;
    depart:{iata:string,name:string,at:string}; arrive:{iata:string,name:string,at:string}; }
}
export default function Movements(){
  const [q,setQ]=React.useState(''); const [rows,setRows]=React.useState<Row[]>([]); const [loading,setLoading]=React.useState(false);
  async function load(){ setLoading(true); const res = await fetch(`/api/movements?q=${encodeURIComponent(q)}`, { credentials:'include' }); const j = await res.json(); setRows(j.data); setLoading(false); }
  React.useEffect(()=>{ load(); },[]);
  return (<div className="card"><h2>Find your flight</h2>
    <div style={{display:'flex',gap:12,margin:'12px 0'}}>
      <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search name (ADMIN only)" />
      <button className="btn" onClick={load}>{loading? 'Loading…':'Search'}</button></div>
    <table><thead><tr><th>Member</th><th>Departs</th><th>Arrives</th><th>Carrier</th><th>Itinerary</th></tr></thead>
      <tbody>{rows.map(r=>{ const nf=r.nextFlight; return (<tr key={r.id}>
        <td>{r.fullName}</td>
        <td>{nf? `${nf.depart.iata} — ${new Date(nf.depart.at).toLocaleString()}`: '—'}</td>
        <td>{nf? `${nf.arrive.iata} — ${new Date(nf.arrive.at).toLocaleString()}`: '—'}</td>
        <td>{nf? `${nf.carrier} ${nf.flightNum}`: '—'}</td>
        <td>{r.latestItineraryId ? <a className="btn" href={`/api/itineraries/${r.latestItineraryId}/pdf`} target="_blank" rel="noreferrer">Get PDF</a> : '—'}</td>
      </tr>)})}</tbody></table></div>)
}