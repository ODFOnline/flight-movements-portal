import React from 'react'
export default function Login({ onAuthed }:{ onAuthed:(me:any)=>void }){
  const [username,setU]=React.useState(''); const [password,setP]=React.useState(''); const [err,setErr]=React.useState('');
  async function submit(){ setErr(''); const r = await fetch('/api/auth/login',{ method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ username, password }), credentials:'include' }); const j = await r.json(); if (!r.ok){ setErr(j.error||'Login failed'); return; } onAuthed(j); }
  return (<div><h2>Sign in</h2><div style={{display:'grid',gap:12,maxWidth:360}}>
    <input value={username} onChange={e=>setU(e.target.value)} placeholder="Username"/>
    <input type="password" value={password} onChange={e=>setP(e.target.value)} placeholder="Password"/>
    {err && <div style={{color:'#ffb4b4'}}>{err}</div>}
    <button className="btn" onClick={submit}>Sign in</button></div></div>)
}