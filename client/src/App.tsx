import React from 'react'
import Movements from './pages/Movements'
import Admin from './pages/Admin'
import Login from './pages/Login'
import Register from './pages/Register'

export default function App(){
  const [route,setRoute] = React.useState(location.hash || '#/');
  const [me,setMe] = React.useState<any>(null);
  const [loaded,setLoaded] = React.useState(false);
  React.useEffect(()=>{
    const f=()=>setRoute(location.hash||'#/');
    window.addEventListener('hashchange', f);
    (async()=>{
      const r = await fetch('/api/me', { credentials:'include' });
      if (r.ok) setMe(await r.json());
      setLoaded(true);
    })();
    return ()=>window.removeEventListener('hashchange', f);
  },[]);

  if (!loaded) return <div className="wrap"><div className="card">Loading…</div></div>;

  if (!me){
    if (route==='#/register') return <div className="wrap"><div className="nav card"><strong>Flight Movements</strong></div><div className="card"><Register onDone={()=>location.hash='#/'} /></div></div>;
    return <div className="wrap"><div className="nav card"><strong>Flight Movements</strong></div><div className="card"><Login onAuthed={(m)=>setMe(m)} /></div><div className="card" style={{marginTop:12}}><a className="btn" href="#/register">Create account</a></div></div>;
  }

  const isAdmin = me?.role === 'ADMIN';
  return (
    <div className="wrap">
      <div className="nav card">
        <div style={{display:'flex',gap:12,alignItems:'center'}}>
          <strong>Flight Movements</strong>
          <span className="pill">PDF‑backed</span>
        </div>
        <div style={{display:'flex',gap:12}}>
          <a href="#/">Deployer View</a>
          {isAdmin && <a href="#/admin">Admin</a>}
        </div>
      </div>
      {route === '#/admin' ? <Admin/> : <Movements/>}
    </div>
  )
}