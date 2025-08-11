import React from 'react'
export default function Admin(){
  const [files,setFiles]=React.useState<File[]>([]); const [busy,setBusy]=React.useState(false); const [log,setLog]=React.useState<any[]>([]);
  const [roster,setRoster]=React.useState<File|null>(null);
  function onDrop(e: React.DragEvent){ e.preventDefault(); const list = Array.from(e.dataTransfer.files).filter(f=>/\.pdf$/i.test(f.name)); setFiles(prev=>[...prev, ...list]); }
  async function upload(){ setBusy(true); const fd = new FormData(); files.forEach(f=>fd.append('pdfs', f)); const res = await fetch('/api/upload',{ method:'POST', body: fd, credentials:'include' }); const j = await res.json(); setLog(j.imported||[]); setBusy(false); }
  async function uploadRoster(){ if (!roster) return; const fd = new FormData(); fd.append('file', roster); const res = await fetch('/api/admin/allowlist/import',{ method:'POST', body:fd, credentials:'include' }); const j = await res.json(); alert('Created tokens: ' + j.created); }
  return (<div className="card"><h2>Admin · Daily PDF Upload</h2>
    <p style={{color:'#99a3b3'}}>Drag and drop itinerary PDFs below.</p>
    <div onDragOver={e=>e.preventDefault()} onDrop={onDrop} style={{border:'2px dashed #2d497a',borderRadius:16,padding:24,display:'grid',placeItems:'center',margin:'12px 0'}}><div>Drop PDFs here</div></div>
    <div style={{display:'flex',gap:12,alignItems:'center'}}><div className="pill">Selected: {files.length}</div>
      <button className="btn" onClick={upload} disabled={!files.length||busy}>{busy? 'Uploading…':'Upload & Ingest'}</button></div>
    <h3 style={{marginTop:24}}>Allowlist Roster (.xlsx)</h3>
    <input type="file" accept=".xlsx" onChange={e=>setRoster(e.target.files?.[0] || null)} />
    <button className="btn" onClick={uploadRoster} disabled={!roster}>Upload Roster</button>
    {log.length>0 && (<div style={{marginTop:16}}><h3>Import results</h3><ul>{log.map((r,i)=>(<li key={i}>{r.file} → {r.member} ({r.segments} segment(s))</li>))}</ul></div>)}
  </div>)
}