import React from 'react'
export default function Register({ onDone }:{ onDone:()=>void }){
  const [code,setCode]=React.useState(''); const [username,setU]=React.useState(''); const [password,setP]=React.useState(''); const [msg,setMsg]=React.useState('');
  async function submit(){ setMsg(''); const r = await fetch('/api/auth/register',{ method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ code, username, password }), credentials:'include' }); const j = await r.json(); if (!r.ok){ setMsg(j.error||'Registration failed'); return; } onDone(); location.reload(); }
  return (<div><h2>Create your account</h2><div style={{display:'grid',gap:12,maxWidth:380}}>
    <input value={code} onChange={e=>setCode(e.target.value)} placeholder="Enrollment code"/>
    <input value={username} onChange={e=>setU(e.target.value)} placeholder="Preferred username (optional)"/>
    <input type="password" value={password} onChange={e=>setP(e.target.value)} placeholder="New password (min 12 chars)"/>
    {msg && <div style={{color:'#ffb4b4'}}>{msg}</div>}
    <button className="btn" onClick={submit}>Create account</button></div></div>)
}