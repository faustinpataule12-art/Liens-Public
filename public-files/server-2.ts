import express from 'express';
import { GoogleGenAI } from '@google/genai';
import crypto from 'crypto';
import path from 'path';
import { Firestore } from '@google-cloud/firestore';

/* ============================================================
   Fable Fast — serveur (version corrigée : vraie connexion TikTok)
   Variables d'environnement À DÉFINIR (jamais dans le code) :
     GEMINI_API_KEY        clé Gemini
     TIKTOK_CLIENT_KEY     Client key TikTok (App details > Credentials)
     TIKTOK_CLIENT_SECRET  Client secret TikTok (JAMAIS dans le front)
     TIKTOK_REDIRECT_URI   ex. https://TON-SITE.run.app/api/auth/tiktok/callback
                           (doit être IDENTIQUE à celle enregistrée chez TikTok)
     FIRESTORE_DATABASE_ID (facultatif) nom de la base Firestore, "(default)" par défaut.
                           Si ton projet AI Studio utilise une base nommée, vois
                           firestoreDatabaseId dans firebase-applet-config.json.
   ============================================================ */

const TIKTOK_AUTH = 'https://www.tiktok.com/v2/auth/authorize/';
const TIKTOK_API = 'https://open.tiktokapis.com';
const SCOPES = (process.env.TIKTOK_SCOPES || 'user.info.basic,user.info.profile,user.info.stats,video.list').split(',');

type Tok = { access: string; refresh: string; exp: number; refreshExp: number; openId: string; scope: string };

/* ---------- Stockage des connexions : Firestore (survit aux redémarrages) + mémoire en secours ---------- */
const mem = new Map<string, Tok>();
let fsdb: Firestore | null = null;
try { fsdb = new Firestore({ databaseId: process.env.FIRESTORE_DATABASE_ID || '(default)' }); } catch (e) { console.warn('Firestore indisponible, repli sur la mémoire :', (e as Error).message); }
// Les jetons sont chiffrés (AES-256-GCM) avant d'être écrits ; la clé dérive du Client secret.
const encKey = () => crypto.createHash('sha256').update('ff-sessions|' + (process.env.TIKTOK_CLIENT_SECRET || '')).digest();
function enc(plain: string): string {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', encKey(), iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function dec(b64: string): string {
  const raw = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', encKey(), raw.subarray(0, 12));
  d.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8');
}
const docId = (sid: string) => crypto.createHash('sha256').update(sid).digest('hex'); // le cookie n'est jamais stocké en clair
async function saveSession(sid: string, t: Tok) {
  mem.set(sid, t);
  if (!fsdb) return;
  try { await fsdb.collection('ff_tiktok_sessions').doc(docId(sid)).set({ data: enc(JSON.stringify(t)), updated: Date.now() }); }
  catch (e) { console.error('Firestore écriture :', (e as Error).message); }
}
async function loadSession(sid: string): Promise<Tok | undefined> {
  const m = mem.get(sid);
  if (m) return m;
  if (!fsdb) return undefined;
  try {
    const d = await fsdb.collection('ff_tiktok_sessions').doc(docId(sid)).get();
    if (!d.exists) return undefined;
    const t = JSON.parse(dec((d.data() as any).data)) as Tok;
    mem.set(sid, t);
    return t;
  } catch (e) { console.error('Firestore lecture :', (e as Error).message); return undefined; }
}
async function deleteSession(sid: string) {
  mem.delete(sid);
  if (!fsdb) return;
  try { await fsdb.collection('ff_tiktok_sessions').doc(docId(sid)).delete(); } catch (e) { console.error('Firestore suppression :', (e as Error).message); }
}

function parseCookies(h?: string): Record<string, string> {
  const o: Record<string, string> = {};
  (h || '').split(';').forEach((p) => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return o;
}
function setCookie(res: express.Response, name: string, val: string, maxAgeS: number) {
  res.append('Set-Cookie', `${name}=${encodeURIComponent(val)}; Max-Age=${maxAgeS}; Path=/; HttpOnly; Secure; SameSite=Lax`);
}
function clearCookie(res: express.Response, name: string) {
  res.append('Set-Cookie', `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

async function tiktokToken(body: Record<string, string>): Promise<any> {
  const r = await fetch(`${TIKTOK_API}/v2/oauth/token/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_key: process.env.TIKTOK_CLIENT_KEY || '', client_secret: process.env.TIKTOK_CLIENT_SECRET || '', ...body }),
  });
  const j: any = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error(j.error_description || j.error || `HTTP ${r.status}`);
  return j;
}
function toTok(j: any): Tok {
  const now = Date.now();
  return { access: j.access_token, refresh: j.refresh_token, exp: now + (j.expires_in || 0) * 1000, refreshExp: now + (j.refresh_expires_in || 0) * 1000, openId: j.open_id, scope: j.scope || '' };
}
// Renvoie un jeton valide (le renouvelle si besoin) ou null
async function validToken(sid?: string): Promise<Tok | null> {
  const t = sid ? await loadSession(sid) : undefined;
  if (!t) return null;
  if (Date.now() < t.exp - 60_000) return t;
  if (Date.now() >= t.refreshExp) { await deleteSession(sid!); return null; }
  try {
    const n = toTok(await tiktokToken({ grant_type: 'refresh_token', refresh_token: t.refresh }));
    await saveSession(sid!, n);
    return n;
  } catch (e) {
    console.error('Renouvellement du jeton TikTok :', (e as Error).message);
    await deleteSession(sid!);
    return null;
  }
}

// Limiteur très simple (par IP) pour protéger ta clé Gemini
const hits = new Map<string, number[]>();
function limited(ip: string, max = 30, windowMs = 60_000) {
  const now = Date.now();
  const a = (hits.get(ip) || []).filter((x) => now - x < windowMs);
  a.push(now); hits.set(ip, a);
  return a.length > max;
}

async function startServer() {
  const app = express();
  app.set('trust proxy', true); // derrière Cloud Run : sinon req.protocol vaut "http"
  app.use(express.json({ limit: '100mb' }));
  app.use(express.urlencoded({ limit: '100mb', extended: true }));

  const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY, httpOptions: { headers: { 'User-Agent': 'aistudio-build' } } });

  /* ---------- Gemini ---------- */
  app.post('/api/gemini/generate', async (req, res) => {
    if (limited(req.ip || 'x')) return res.status(429).json({ error: 'Trop de requêtes' });
    try {
      const { prompt, contents, model, system_instruction } = req.body;
      const payload: any = { model: model || 'gemini-2.5-flash', contents: contents || prompt };
      if (system_instruction) payload.config = { systemInstruction: typeof system_instruction === 'string' ? system_instruction : JSON.stringify(system_instruction) };
      const response = await ai.models.generateContent(payload);
      res.json({ text: response.text });
    } catch (error) {
      console.error('Gemini API Error:', error);
      res.status(500).json({ error: 'Failed to generate content' });
    }
  });

  /* ---------- Recherche web FIABLE (Gemini + Google Search) ---------- */
  app.post('/api/research', async (req, res) => {
    if (limited(req.ip || 'x', 10)) return res.status(429).json({ error: 'Trop de requêtes' });
    try {
      const { question, data, model } = req.body || {};
      if (!question) return res.status(400).json({ error: 'question manquante' });
      const system = `Tu es analyste de croissance sur les réseaux sociaux. Utilise la recherche Google.
RÈGLES : sources officielles d'abord (centres d'aide TikTok / Instagram / YouTube), puis recoupement. Un avis isolé n'est jamais un fait.
Chaque affirmation porte un niveau : "officiel", "recoupé", "avis" ou "hypothèse". N'invente AUCUN chiffre ni pourcentage ; si tu ne trouves pas, écris "non trouvé".
Distingue cause au niveau de la VIDÉO, du COMPTE et de la PLATEFORME. Chaque solution se teste (action + métrique + durée). Aucun résultat garanti.`;
      const response: any = await ai.models.generateContent({
        model: model || 'gemini-2.5-flash',
        contents: `${question}${data ? '\n\nDONNÉES RÉELLES DU COMPTE :\n' + JSON.stringify(data) : ''}`,
        config: { systemInstruction: system, tools: [{ googleSearch: {} }], temperature: 0.3 },
      });
      const gm = response.candidates?.[0]?.groundingMetadata || {};
      const seen = new Set<string>();
      const sources = (gm.groundingChunks || []).map((c: any) => c.web).filter((w: any) => w?.uri && !seen.has(w.uri) && seen.add(w.uri)).map((w: any) => ({ title: w.title || w.uri, url: w.uri }));
      res.json({ text: response.text, sources, queries: gm.webSearchQueries || [], grounded: sources.length > 0 });
    } catch (e) {
      console.error('Research error:', e);
      res.status(500).json({ error: 'Recherche indisponible' });
    }
  });

  /* ---------- Analyse de vidéo (inchangé sauf prudence sur le score) ---------- */
  app.post('/api/analyze-video', async (req, res) => {
    if (limited(req.ip || 'x', 10)) return res.status(429).json({ error: 'Trop de requêtes' });
    try {
      const { title, frames, count, model } = req.body;
      const prompt = `Tu es Fable Fast, expert en croissance d'audience sur TikTok et Instagram Reels.
Tu as reçu ${frames?.length || count || 0} captures réparties sur la durée de la vidéo "${title || 'vidéo'}".
Tu ne vois QUE des images fixes : tu ne connais ni le son, ni la rétention réelle, ni les statistiques. Dis-le quand c'est le cas, n'invente aucun chiffre.
Analyse : 1) l'accroche (0-3 s) avec le texte exact à afficher, 2) le rythme et les coupes, 3) les sous-titres, 4) hashtags par groupes (4 à 6 par groupe), 5) un potentiel noté sur 100 avec les raisons visibles à l'image, 6) quoi corriger étape par étape, 7) pistes de monétisation réalistes, sans promesse de revenu.`;
      const contents: any[] = [{ text: prompt }];
      (frames || []).forEach((f: string) => { if (f && f.includes(',')) contents.push({ inlineData: { data: f.split(',')[1], mimeType: 'image/jpeg' } }); });
      const response = await ai.models.generateContent({ model: model || 'gemini-2.5-flash', contents });
      res.json({ text: response.text });
    } catch (error) {
      console.error('Video Analysis Error:', error);
      res.status(500).json({ error: 'Failed to analyze video' });
    }
  });

  /* ---------- TikTok : VRAIE connexion OAuth ---------- */
  app.get('/api/auth/tiktok/initiate', (req, res) => {
    const clientKey = process.env.TIKTOK_CLIENT_KEY;
    const redirectUri = process.env.TIKTOK_REDIRECT_URI || `${req.protocol}://${req.get('host')}/api/auth/tiktok/callback`;
    if (!clientKey) return res.status(500).json({ error: 'TIKTOK_CLIENT_KEY non défini sur le serveur' });
    const state = crypto.randomBytes(24).toString('base64url');
    setCookie(res, 'ff_state', state, 600);
    const url = `${TIKTOK_AUTH}?client_key=${encodeURIComponent(clientKey)}&response_type=code&scope=${encodeURIComponent(SCOPES.join(','))}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
    res.json({ authUrl: url, redirectUri });
  });

  app.get('/api/auth/tiktok/callback', async (req, res) => {
    const { code, error, error_description, state } = req.query as Record<string, string>;
    const ck = parseCookies(req.headers.cookie);
    clearCookie(res, 'ff_state');
    if (error) return res.redirect('/?auth_error=' + encodeURIComponent(error_description || error));
    if (!code || !state || !ck.ff_state || state !== ck.ff_state) return res.redirect('/?auth_error=' + encodeURIComponent('Vérification de sécurité échouée (state)'));
    try {
      const redirectUri = process.env.TIKTOK_REDIRECT_URI || `${req.protocol}://${req.get('host')}/api/auth/tiktok/callback`;
      const tok = toTok(await tiktokToken({ grant_type: 'authorization_code', code: decodeURIComponent(code), redirect_uri: redirectUri }));
      const sid = crypto.randomBytes(24).toString('base64url');
      await saveSession(sid, tok);
      setCookie(res, 'ff_sid', sid, 60 * 60 * 24 * 30);
      res.redirect('/?connected=tiktok');
    } catch (e: any) {
      console.error('TikTok token error:', e?.message);
      res.redirect('/?auth_error=' + encodeURIComponent('Échec de la connexion TikTok : ' + (e?.message || 'inconnu')));
    }
  });

  app.post('/api/auth/tiktok/disconnect', async (req, res) => {
    const sid = parseCookies(req.headers.cookie).ff_sid;
    if (sid) await deleteSession(sid);
    clearCookie(res, 'ff_sid');
    res.json({ ok: true });
  });

  // État RÉEL : aucune donnée inventée
  app.get('/api/auth/status', async (req, res) => {
    const t = await validToken(parseCookies(req.headers.cookie).ff_sid);
    res.json({ tiktok: { connected: !!t, scope: t?.scope || '' } });
  });

  app.get('/api/tiktok/me', async (req, res) => {
    const t = await validToken(parseCookies(req.headers.cookie).ff_sid);
    if (!t) return res.status(401).json({ error: 'Non connecté à TikTok' });
    const has = (s: string) => t.scope.split(',').includes(s);
    const fields = ['open_id', 'display_name', 'avatar_url'];
    if (has('user.info.profile')) fields.push('bio_description', 'username');
    if (has('user.info.stats')) fields.push('follower_count', 'following_count', 'likes_count', 'video_count');
    const r = await fetch(`${TIKTOK_API}/v2/user/info/?fields=${fields.join(',')}`, { headers: { Authorization: `Bearer ${t.access}` } });
    const j: any = await r.json().catch(() => ({}));
    if (!r.ok || (j.error && j.error.code && j.error.code !== 'ok')) return res.status(502).json({ error: j.error?.message || `HTTP ${r.status}` });
    res.json(j.data?.user || {});
  });

  app.get('/api/tiktok/videos', async (req, res) => {
    const t = await validToken(parseCookies(req.headers.cookie).ff_sid);
    if (!t) return res.status(401).json({ error: 'Non connecté à TikTok' });
    const fields = 'id,title,video_description,create_time,duration,view_count,like_count,comment_count,share_count,share_url,cover_image_url';
    const body: any = { max_count: 20 };
    if (req.query.cursor) body.cursor = Number(req.query.cursor);
    const r = await fetch(`${TIKTOK_API}/v2/video/list/?fields=${fields}`, { method: 'POST', headers: { Authorization: `Bearer ${t.access}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const j: any = await r.json().catch(() => ({}));
    if (!r.ok || (j.error && j.error.code && j.error.code !== 'ok')) return res.status(502).json({ error: j.error?.message || `HTTP ${r.status}` });
    res.json({ videos: j.data?.videos || [], cursor: j.data?.cursor, has_more: !!j.data?.has_more });
  });

  /* ---------- Front ---------- */
  if (process.env.NODE_ENV === 'production') {
    const dist = path.join(process.cwd(), 'dist');
    app.use(express.static(dist));
    app.get('*', (_req, res) => res.sendFile(path.join(dist, 'index.html')));
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa' });
    app.use(vite.middlewares);
  }

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, '0.0.0.0', () => console.log(`Server running on port ${port}`));
}

startServer();
