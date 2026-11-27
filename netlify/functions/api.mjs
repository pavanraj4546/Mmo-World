import { getStore } from '@netlify/blobs';
import { createHmac, createHash, timingSafeEqual, randomBytes } from 'node:crypto';
const store = () => getStore({ name: 'mmoworld-games', consistency: 'strong' });
const cookieName = 'mmoworld_admin'; const maxAge = 60 * 60 * 24 * 7;
const json = (data,status=200,headers={}) => new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const secret=()=>Netlify.env.get('SESSION_SECRET'); const adminPassword=()=>Netlify.env.get('ADMIN_PASSWORD');
function sign(v){return createHmac('sha256',secret()).update(v).digest('base64url')}
function makeSession(){const p=Buffer.from(JSON.stringify({exp:Date.now()+maxAge*1000,nonce:randomBytes(12).toString('hex')})).toString('base64url');return `${p}.${sign(p)}`}
function isAdmin(req){if(!secret()||!adminPassword())return false;const raw=req.headers.get('cookie')||'';const part=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith(cookieName+'='));if(!part)return false;const token=decodeURIComponent(part.slice(cookieName.length+1));const [p,s]=token.split('.');if(!p||!s)return false;const expected=sign(p),a=Buffer.from(s),b=Buffer.from(expected);if(a.length!==b.length||!timingSafeEqual(a,b))return false;try{return JSON.parse(Buffer.from(p,'base64url').toString()).exp>Date.now()}catch{return false}}
function cookie(v,age=maxAge){return `${cookieName}=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`}
async function readGames(){return (await store().get('games',{type:'json'}))||[]}
const voteStore=()=>getStore({name:'mmoworld-votes',consistency:'strong'});
const voteCooldown=12*60*60*1000;
async function readVotes(){return (await voteStore().get('votes',{type:'json'}))||{counts:{},voters:{}}}
function voterKey(req,id){
 const ip=req.headers.get('x-nf-client-connection-ip')||(req.headers.get('x-forwarded-for')||'').split(',')[0].trim()||'unknown';
 const ua=req.headers.get('user-agent')||'';
 return createHash('sha256').update(`${secret()||'mmoworld-public'}|${ip}|${ua}|${id}`).digest('hex');
}
function clean(body){if(!body||!String(body.name||'').trim()||!String(body.link||'').trim())throw Error('Game name and game link are required.');let u;try{u=new URL(body.link)}catch{throw Error('Enter a valid game URL.')}if(!['http:','https:'].includes(u.protocol))throw Error('Only HTTP or HTTPS links are allowed.');return {name:String(body.name).trim().slice(0,100),cat:String(body.cat||'Other').slice(0,60),desc:String(body.desc||'').slice(0,1000),link:u.href,photo:String(body.photo||'').slice(0,1500),disclosure:String(body.disclosure||'').slice(0,300)}}
export default async req=>{const path=new URL(req.url).pathname.replace(/^\/api\/?/,'');
 if(req.method==='GET'&&path==='games'){
  const [games,votes]=await Promise.all([readGames(),readVotes()]);
  return json(games.map(g=>{
   const entry=votes.counts[g.id]||{likes:0,dislikes:0};
   const last=votes.voters[voterKey(req,g.id)]||0;
   return {...g,likes:Number(entry.likes||0),dislikes:Number(entry.dislikes||0),canVote:Date.now()-last>=voteCooldown};
  }));
 }
 if(req.method==='POST'&&path.startsWith('vote/')){
  const id=path.slice(5),body=await req.json().catch(()=>({})),type=body.type;
  if(!['like','dislike'].includes(type))return json({error:'Choose like or dislike.'},400);
  const games=await readGames();if(!games.some(g=>g.id===id))return json({error:'Game not found.'},404);
  const votes=await readVotes(),key=voterKey(req,id),now=Date.now(),last=votes.voters[key]||0;
  if(now-last<voteCooldown){const mins=Math.ceil((voteCooldown-(now-last))/60000);return json({error:`You can vote again in about ${mins} minutes.`},429)}
  const entry=votes.counts[id]||(votes.counts[id]={likes:0,dislikes:0});
  entry[type==='like'?'likes':'dislikes']++;
  votes.voters[key]=now;
  await(await voteStore()).setJSON('votes',votes);
  return json({ok:true,likes:entry.likes,dislikes:entry.dislikes,nextVoteAt:now+voteCooldown});
 }
 if(req.method==='POST'&&path==='admin/login'){if(!secret()||!adminPassword())return json({error:'Admin setup incomplete. Set ADMIN_PASSWORD and SESSION_SECRET in Netlify.'},503);const body=await req.json().catch(()=>({}));const given=Buffer.from(String(body.password||'')),actual=Buffer.from(adminPassword());if(given.length!==actual.length||!timingSafeEqual(given,actual))return json({error:'Incorrect access code.'},401);return json({ok:true},200,{'set-cookie':cookie(makeSession())})}
 if(req.method==='GET'&&path==='admin/session')return json({authenticated:isAdmin(req)});
 if(req.method==='POST'&&path==='admin/logout')return json({ok:true},200,{'set-cookie':cookie('',0)});
 if(!isAdmin(req))return json({error:'Admin access required.'},401);
 if(req.method==='POST'&&path==='games'){const body=await req.json().catch(()=>null);let fields;try{fields=clean(body)}catch(e){return json({error:e.message},400)}const games=await readGames();const item={id:randomBytes(12).toString('hex'),...fields,created:Date.now()};games.unshift(item);await(await store()).setJSON('games',games);return json(item,201)}
 if(req.method==='PUT'&&path.startsWith('games/')){const id=path.slice(6),body=await req.json().catch(()=>null);let fields;try{fields=clean(body)}catch(e){return json({error:e.message},400)}const games=await readGames(),i=games.findIndex(g=>g.id===id);if(i<0)return json({error:'Game not found.'},404);games[i]={...games[i],...fields};await(await store()).setJSON('games',games);return json(games[i])}
 if(req.method==='DELETE'&&path.startsWith('games/')){const id=path.slice(6),games=await readGames(),next=games.filter(g=>g.id!==id);if(next.length===games.length)return json({error:'Game not found.'},404);await(await store()).setJSON('games',next);return json({ok:true})}
 return json({error:'Not found.'},404)};
