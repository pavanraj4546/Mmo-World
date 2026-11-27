import { getStore } from '@netlify/blobs';
import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';
const store = () => getStore({ name: 'mmoworld-games', consistency: 'strong' });
const cookieName = 'mmoworld_admin'; const maxAge = 60 * 60 * 24 * 7;
const json = (data,status=200,headers={}) => new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const secret=()=>Netlify.env.get('SESSION_SECRET'); const adminPassword=()=>Netlify.env.get('ADMIN_PASSWORD');
function sign(v){return createHmac('sha256',secret()).update(v).digest('base64url')}
function makeSession(){const p=Buffer.from(JSON.stringify({exp:Date.now()+maxAge*1000,nonce:randomBytes(12).toString('hex')})).toString('base64url');return `${p}.${sign(p)}`}
function isAdmin(req){if(!secret()||!adminPassword())return false;const raw=req.headers.get('cookie')||'';const part=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith(cookieName+'='));if(!part)return false;const token=decodeURIComponent(part.slice(cookieName.length+1));const [p,s]=token.split('.');if(!p||!s)return false;const expected=sign(p),a=Buffer.from(s),b=Buffer.from(expected);if(a.length!==b.length||!timingSafeEqual(a,b))return false;try{return JSON.parse(Buffer.from(p,'base64url').toString()).exp>Date.now()}catch{return false}}
function cookie(v,age=maxAge){return `${cookieName}=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`}
async function readGames(){return (await store().get('games',{type:'json'}))||[]}
function clean(body){if(!body||!String(body.name||'').trim()||!String(body.link||'').trim())throw Error('Game name and game link are required.');let u;try{u=new URL(body.link)}catch{throw Error('Enter a valid game URL.')}if(!['http:','https:'].includes(u.protocol))throw Error('Only HTTP or HTTPS links are allowed.');return {name:String(body.name).trim().slice(0,100),cat:String(body.cat||'Other').slice(0,60),desc:String(body.desc||'').slice(0,1000),link:u.href,photo:String(body.photo||'').slice(0,1500),disclosure:String(body.disclosure||'').slice(0,300)}}
export default async req=>{const path=new URL(req.url).pathname.replace(/^\/api\/?/,'');

 if(req.method==='GET'&&path.startsWith('images/')){
  const key=path.slice('images/'.length);
  if(!/^([a-f0-9]{24})\.(jpg|png|webp|gif)$/.test(key))return json({error:'Image not found.'},404);
  const ext=key.split('.').pop();
  const types={jpg:'image/jpeg',png:'image/png',webp:'image/webp',gif:'image/gif'};
  const data=await store().get(`images/${key}`,{type:'arrayBuffer'});
  if(!data)return json({error:'Image not found.'},404);
  return new Response(data,{headers:{'content-type':types[ext],'cache-control':'public, max-age=31536000, immutable','x-content-type-options':'nosniff'}});
 }

 if(req.method==='GET'&&path==='games')return json(await readGames());
 if(req.method==='POST'&&path==='admin/login'){if(!secret()||!adminPassword())return json({error:'Admin setup incomplete. Set ADMIN_PASSWORD and SESSION_SECRET in Netlify.'},503);const body=await req.json().catch(()=>({}));const given=Buffer.from(String(body.password||'')),actual=Buffer.from(adminPassword());if(given.length!==actual.length||!timingSafeEqual(given,actual))return json({error:'Incorrect access code.'},401);return json({ok:true},200,{'set-cookie':cookie(makeSession())})}
 if(req.method==='GET'&&path==='admin/session')return json({authenticated:isAdmin(req)});
 if(req.method==='POST'&&path==='admin/logout')return json({ok:true},200,{'set-cookie':cookie('',0)});
 if(!isAdmin(req))return json({error:'Admin access required.'},401);

 if(req.method==='POST'&&path==='upload'){
  const body=await req.json().catch(()=>null);
  if(!body||typeof body.data!=='string')return json({error:'No image data received.'},400);
  const types={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif'};
  const ext=types[body.type];
  if(!ext)return json({error:'Only JPG, PNG, WEBP and GIF images are supported.'},400);
  const bytes=Buffer.from(body.data,'base64');
  if(!bytes.length||bytes.length>4*1024*1024)return json({error:'Image must be smaller than 4 MB.'},400);
  const id=randomBytes(12).toString('hex');
  const key=`images/${id}.${ext}`;
  await (await store()).set(key,bytes);
  return json({ok:true,url:`/api/images/${id}.${ext}`},201);
 }

 if(req.method==='POST'&&path==='games'){const body=await req.json().catch(()=>null);let fields;try{fields=clean(body)}catch(e){return json({error:e.message},400)}const games=await readGames();const item={id:randomBytes(12).toString('hex'),...fields,created:Date.now()};games.unshift(item);await(await store()).setJSON('games',games);return json(item,201)}
 if(req.method==='PUT'&&path.startsWith('games/')){const id=path.slice(6),body=await req.json().catch(()=>null);let fields;try{fields=clean(body)}catch(e){return json({error:e.message},400)}const games=await readGames(),i=games.findIndex(g=>g.id===id);if(i<0)return json({error:'Game not found.'},404);games[i]={...games[i],...fields};await(await store()).setJSON('games',games);return json(games[i])}
 if(req.method==='DELETE'&&path.startsWith('games/')){const id=path.slice(6),games=await readGames(),next=games.filter(g=>g.id!==id);if(next.length===games.length)return json({error:'Game not found.'},404);await(await store()).setJSON('games',next);return json({ok:true})}
 return json({error:'Not found.'},404)};
