import 'dotenv/config';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { URL } from 'node:url';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import OpenAI from 'openai';
import { google } from 'googleapis';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const JWT_SECRET = process.env.JWT_SECRET || 'development-only-secret';
const APP_ENCRYPTION_KEY = crypto.createHash('sha256').update(process.env.APP_ENCRYPTION_KEY || 'development-only-key').digest();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const send = (res, status, body, headers = {}) => {
  if (res.headersSent || res.writableEnded) return true;
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, { 'content-type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8', ...headers });
  res.end(payload);
  return true;
};
const json = (res, status, body, headers = {}) => send(res, status, body, { 'cache-control': 'no-store', ...headers });
const parseCookies = (value = '') => Object.fromEntries(value.split(';').map(part => part.trim().split('=').map(decodeURIComponent)).filter(([key]) => key));
const cookie = (name, value, maxAge = 60 * 60 * 24 * 30) => `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
const clearCookie = name => `${name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
const sign = payload => jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
const verify = token => { try { return jwt.verify(token, JWT_SECRET); } catch { return null; } };
const deriveUser = (req) => verify(parseCookies(req.headers.cookie || '').tf_session);

async function readBody(req) {
  let data = '';
  for await (const chunk of req) {
    data += chunk;
    if (data.length > 5_000_000) throw new Error('Payload muito grande');
  }
  if (!data) return {};
  return JSON.parse(data);
}

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT,
      google_sub TEXT UNIQUE,
      display_name TEXT,
      avatar_url TEXT,
      app_state JSONB NOT NULL DEFAULT '{}'::jsonb,
      google_tokens_encrypted TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query('ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub TEXT UNIQUE');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT');
}

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', APP_ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map(part => part.toString('base64url')).join('.');
}

function decrypt(value) {
  const [iv, tag, encrypted] = String(value || '').split('.').map(part => Buffer.from(part, 'base64url'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', APP_ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8'));
}

async function userFromRequest(req) {
  const identity = deriveUser(req);
  if (!identity?.id) return null;
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [identity.id]);
  return rows[0] || null;
}

function googleClient() {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_REDIRECT_URI) return null;
  return new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
}

function googleRedirect(origin = '') {
  return String(process.env.APP_ORIGIN || origin || '/').replace(/\/$/, '');
}

function googleAuthUrl(state) {
  const client = googleClient();
  if (!client) return null;
  return client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: true,
    scope: ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/calendar'],
    state
  });
}

function googleStateCookie(state) {
  return cookie('tf_google_state', state, 600);
}

function originFromRequest(req) {
  const forwarded = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  return `${forwarded || (process.env.NODE_ENV === 'production' ? 'https' : 'http')}://${req.headers.host || 'localhost'}`;
}

function publicUser(user) {
  return { id: user.id, email: user.email, name: user.display_name || '', avatar: user.avatar_url || '' };
}

async function api(req, res, url) {
  if (url.pathname === '/api/health' && req.method === 'GET') {
    try { await pool.query('SELECT 1'); json(res, 200, { ok: true, database: 'up' }); }
    catch { json(res, 503, { ok: false, database: 'down' }); }
    return true;
  }

  if (url.pathname === '/api/auth/login' && req.method === 'POST') {
    return json(res, 410, { error: 'O Training Fighter usa somente o login com Google.' });
  }

  if (url.pathname === '/api/auth/google' && req.method === 'GET') {
    const state = sign({ nonce: crypto.randomBytes(18).toString('hex'), intent: 'login' });
    const authUrl = googleAuthUrl(state);
    if (!authUrl) return json(res, 503, { error: 'O login com Google ainda não foi configurado no servidor.' });
    res.writeHead(302, { location: authUrl, 'set-cookie': googleStateCookie(state) });
    res.end();
    return true;
  }

  if (url.pathname === '/api/auth/logout' && req.method === 'POST') {
    json(res, 200, { ok: true }, { 'set-cookie': clearCookie('tf_session') });
    return true;
  }

  if (url.pathname === '/api/me' && req.method === 'GET') {
    const user = await userFromRequest(req);
    if (!user) return json(res, 401, { error: 'Sessão ausente.' });
    json(res, 200, { user: publicUser(user), state: user.app_state || {} });
    return true;
  }

  const user = await userFromRequest(req);
  if (url.pathname.startsWith('/api/') && !user && !['/api/health', '/api/auth/login', '/api/auth/google', '/api/google/callback', '/api/auth/logout'].includes(url.pathname)) {
    json(res, 401, { error: 'Faça login para continuar.' });
    return true;
  }

  if (url.pathname === '/api/state' && req.method === 'GET') { json(res, 200, { state: user.app_state || {} }); return true; }
  if (url.pathname === '/api/state' && req.method === 'PUT') {
    const body = await readBody(req);
    await pool.query('UPDATE users SET app_state = $1, updated_at = NOW() WHERE id = $2', [body.state || {}, user.id]);
    json(res, 200, { ok: true });
    return true;
  }

  if (url.pathname === '/api/ai/coach' && req.method === 'POST') {
    if (!process.env.OPENAI_API_KEY) return json(res, 503, { error: 'A IA ainda não está configurada no servidor.' });
    const { prompt, context } = await readBody(req);
    if (!String(prompt || '').trim()) return json(res, 400, { error: 'Escreva uma pergunta.' });
    try {
      const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
      const response = await client.responses.create({
        model: process.env.OPENAI_MODEL || 'gpt-4.1-mini',
        instructions: 'Você é o coach virtual do Training Fighter. Responda em português brasileiro, com objetividade, incentivo e segurança. Não faça diagnóstico médico. Sugira procurar profissional quando houver dor, lesão ou condição de saúde.',
        input: `Contexto do atleta:\n${JSON.stringify(context || {})}\n\nPergunta:\n${String(prompt).slice(0, 2000)}`,
        max_output_tokens: 600
      });
      json(res, 200, { answer: response.output_text || 'Não consegui gerar uma resposta agora.' });
    } catch (error) { json(res, 502, { error: 'A IA não respondeu agora. Tente novamente.' }); }
    return true;
  }

  if (url.pathname === '/api/google/status' && req.method === 'GET') { json(res, 200, { connected: Boolean(user.google_tokens_encrypted) }); return true; }
  if (url.pathname === '/api/google/start' && req.method === 'GET') {
    const client = googleClient();
    if (!client) return json(res, 503, { error: 'O Google Calendar ainda não foi configurado no servidor.' });
    const state = sign({ id: user.id, nonce: crypto.randomBytes(18).toString('hex'), intent: 'calendar' });
    const authUrl = googleAuthUrl(state);
    json(res, 200, { url: authUrl }, { 'set-cookie': cookie('tf_google_state', state, 600) });
    return true;
  }
  if (url.pathname === '/api/google/callback' && req.method === 'GET') {
    const oauthState = verify(url.searchParams.get('state'));
    const cookies = parseCookies(req.headers.cookie || '');
    const cookieState = verify(cookies.tf_google_state);
    if (!oauthState || !cookieState || oauthState.nonce !== cookieState.nonce || oauthState.intent !== cookieState.intent) return send(res, 400, 'Autorização do Google inválida.');
    const client = googleClient();
    if (!client || !url.searchParams.get('code')) return send(res, 400, 'Código de autorização ausente.');
    try {
      const { tokens } = await client.getToken(url.searchParams.get('code'));
      client.setCredentials(tokens);
      const { data: profile } = await google.oauth2({ version: 'v2', auth: client }).userinfo.get();
      if (!profile.id || !profile.email || profile.verified_email === false) return send(res, 400, 'A conta Google precisa ter um e-mail verificado.');
      const storedTokens = encrypt(tokens);
      const existing = await pool.query('SELECT * FROM users WHERE google_sub = $1 OR email = $2 ORDER BY google_sub NULLS LAST LIMIT 1', [profile.id, String(profile.email).toLowerCase()]);
      let userRecord = existing.rows[0];
      if (userRecord) {
        const result = await pool.query('UPDATE users SET google_sub = $1, email = $2, display_name = $3, avatar_url = $4, google_tokens_encrypted = $5, updated_at = NOW() WHERE id = $6 RETURNING *', [profile.id, String(profile.email).toLowerCase(), profile.name || '', profile.picture || '', storedTokens, userRecord.id]);
        userRecord = result.rows[0];
      } else {
        const result = await pool.query('INSERT INTO users(email, google_sub, display_name, avatar_url, google_tokens_encrypted) VALUES($1, $2, $3, $4, $5) RETURNING *', [String(profile.email).toLowerCase(), profile.id, profile.name || '', profile.picture || '', storedTokens]);
        userRecord = result.rows[0];
      }
      const nextState = userRecord.app_state && Object.keys(userRecord.app_state).length ? userRecord.app_state : {};
      if (!Object.keys(nextState).length || !nextState.profile) nextState.profile = {};
      nextState.profile.name = nextState.profile.name || profile.name || '';
      nextState.profile.photo = nextState.profile.photo || profile.picture || '';
      await pool.query('UPDATE users SET app_state = $1, updated_at = NOW() WHERE id = $2', [nextState, userRecord.id]);
      const redirect = `${googleRedirect(originFromRequest(req))}/?google=connected`;
      res.writeHead(302, { location: redirect, 'set-cookie': [clearCookie('tf_google_state'), cookie('tf_session', sign({ id: userRecord.id, email: userRecord.email }))] });
      res.end();
    }
    catch (error) { console.error('Google OAuth callback failed:', error.message); send(res, 502, 'Não foi possível conectar o Google Calendar.'); }
    return true;
  }
  if (url.pathname === '/api/google/events' && req.method === 'GET') {
    if (!user.google_tokens_encrypted) return json(res, 409, { error: 'Google Calendar não conectado.' });
    const client = googleClient();
    try { client.setCredentials(decrypt(user.google_tokens_encrypted)); const calendar = google.calendar({ version: 'v3', auth: client }); const result = await calendar.events.list({ calendarId: 'primary', timeMin: new Date().toISOString(), maxResults: 20, singleEvents: true, orderBy: 'startTime' }); json(res, 200, { events: result.data.items || [] }); }
    catch { json(res, 502, { error: 'Não foi possível ler o Google Calendar.' }); }
    return true;
  }
  if (url.pathname === '/api/google/events' && req.method === 'POST') {
    if (!user.google_tokens_encrypted) return json(res, 409, { error: 'Google Calendar não conectado.' });
    const body = await readBody(req); const client = googleClient();
    try { client.setCredentials(decrypt(user.google_tokens_encrypted)); const calendar = google.calendar({ version: 'v3', auth: client }); const result = await calendar.events.insert({ calendarId: 'primary', requestBody: body }); json(res, 201, { event: result.data }); }
    catch { json(res, 502, { error: 'Não foi possível criar o evento.' }); }
    return true;
  }
  return false;
}

const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.webmanifest': 'application/manifest+json' };
async function serveStatic(req, res, url) {
  let requested = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
  if (requested.includes('..')) return send(res, 400, 'Bad request');
  try { const file = await fs.readFile(path.join(__dirname, requested)); res.writeHead(200, { 'content-type': mime[path.extname(requested)] || 'application/octet-stream', 'cache-control': requested.endsWith('.html') ? 'no-cache' : 'public, max-age=300' }); res.end(file); }
  catch { const file = await fs.readFile(path.join(__dirname, 'index.html')); res.writeHead(200, { 'content-type': mime['.html'] }); res.end(file); }
}

const server = http.createServer(async (req, res) => {
  try { const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`); if (url.pathname.startsWith('/api/')) { if (await api(req, res, url)) return; return json(res, 404, { error: 'Rota não encontrada.' }); } await serveStatic(req, res, url); }
  catch (error) { if (!res.headersSent && !res.writableEnded) json(res, 500, { error: 'Erro interno do servidor.' }); else console.error('Request failed after response:', error.message); }
});

ensureSchema().then(() => server.listen(PORT, () => console.log(`Training Fighter listening on :${PORT}`))).catch(error => { console.error('Database initialization failed:', error.message); process.exit(1); });
