

import { getStore } from '@netlify/blobs';
import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';

const store = () => getStore({ name: 'mmoworld-games', consistency: 'strong' });
const cookieName = 'mmoworld_admin';
const maxAge = 60 * 60 * 24 * 7;
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
const secret = () => Netlify.env.get('SESSION_SECRET');
const adminPassword = () => Netlify.env.get('ADMIN_PASSWORD');

function sign(value) {
  return createHmac('sha256', secret()).update(value).digest('base64url');
}

function makeSession() {
  const payload = Buffer.from(JSON.stringify({
    exp: Date.now() + maxAge * 1000,
    nonce: randomBytes(12).toString('hex')
  })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function isAdmin(req) {
  if (!secret() || !adminPassword()) return false;
  const raw = req.headers.get('cookie') || '';
  const part = raw.split(';').map(x => x.trim()).find(x => x.startsWith(cookieName + '='));
  if (!part) return false;
  const token = decodeURIComponent(part.slice(cookieName.length + 1));
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return false;
  const expected = sign(payload);
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return false;
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now();
  } catch {
    return false;
  }
}

function cookie(value, age = maxAge) {
  return `${cookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
}

async function readGames() {
  return (await store().get('games', { type: 'json' })) || [];
}

export default async (req) => {
  const path = new URL(req.url).pathname.replace(/^\/api\/?/, '');

  if (req.method === 'GET' && path === 'games')
    return json(await readGames());

  if (req.method === 'POST' && path === 'admin/login') {
    if (!secret() || !adminPassword())
      return json({ error: 'Admin setup is incomplete.' }, 503);

    const body = await req.json().catch(() => ({}));
    const given = Buffer.from(String(body.password || ''));
    const actual = Buffer.from(adminPassword());

    if (given.length !== actual.length || !timingSafeEqual(given, actual))
      return json({ error: 'Incorrect access code.' }, 401);

    return json({ ok: true }, 200, {
      'set-cookie': cookie(makeSession())
    });
  }

  if (req.method === 'GET' && path === 'admin/session')
    return json({ authenticated: isAdmin(req) });

  if (req.method === 'POST' && path === 'admin/logout')
    return json({ ok: true }, 200, { 'set-cookie': cookie('', 0) });

  if (!isAdmin(req))
    return json({ error: 'Admin access required.' }, 401);

  if (req.method === 'POST' && path === 'games') {
    const body = await req.json().catch(() => null);

    if (!body || !String(body.name || '').trim() || !String(body.link || '').trim())
      return json({ error: 'Game name and game link are required.' }, 400);

    let url;
    try { url = new URL(body.link); }
    catch { return json({ error: 'Enter a valid game URL.' }, 400); }

    if (!['http:', 'https:'].includes(url.protocol))
      return json({ error: 'Only HTTP or HTTPS links are allowed.' }, 400);

    const games = await readGames();
    const item = {
      id: randomBytes(12).toString('hex'),
      name: String(body.name).trim().slice(0, 100),
      cat: String(body.cat || 'Other').slice(0, 60),
      desc: String(body.desc || '').slice(0, 1000),
      link: url.href,
      photo: String(body.photo || '').slice(0, 1500),
      disclosure: String(body.disclosure || '').slice(0, 300),
      created: Date.now()
    };

    games.unshift(item);
    await (await store()).setJSON('games', games);
    return json(item, 201);
  }

  if (req.method === 'DELETE' && path.startsWith('games/')) {
    const id = path.slice('games/'.length);
    const games = await readGames();
    const next = games.filter(g => g.id !== id);

    if (next.length === games.length)
      return json({ error: 'Game not found.' }, 404);

    await (await store()).setJSON('games', next);
    return json({ ok: true });
  }

  return json({ error: 'Not found.' }, 404);
};
