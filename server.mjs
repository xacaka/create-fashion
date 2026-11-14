import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import pg from "pg";

const { Pool } = pg;
const scrypt = promisify(crypto.scrypt);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "public");
const PORT = Number(process.env.PORT || 3000);
const GENLOOK_BASE = "https://api.genlook.app/tryon/v1";
const MAX_BODY = 35 * 1024 * 1024;
const SESSION_DAYS = 7;
const DAILY_TRYON_LIMIT = 3;
const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000
}) : null;
const tempImages = new Map();
const rateBuckets = new Map();

function send(res, status, data, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(JSON.stringify(data));
}
function cookieOptions(req, maxAge = SESSION_DAYS * 86400) {
  const secure = process.env.NODE_ENV === "production" || String(req.headers["x-forwarded-proto"] || "").includes("https");
  return `cf_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}
function setSessionCookie(req, res, token) {
  const secure = process.env.NODE_ENV === "production" || String(req.headers["x-forwarded-proto"] || "").includes("https");
  res.setHeader("Set-Cookie", `cf_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure ? "; Secure" : ""}`);
}
function clearSessionCookie(req, res) { res.setHeader("Set-Cookie", cookieOptions(req, 0)); }
function getCookie(req, name) {
  const raw = String(req.headers.cookie || "");
  const entry = raw.split(";").map(v => v.trim()).find(v => v.startsWith(`${name}=`));
  return entry ? decodeURIComponent(entry.slice(name.length + 1)) : null;
}
function assertSameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return;
  const expected = `${String(req.headers["x-forwarded-proto"] || "https").split(",")[0].trim()}://${req.headers.host}`;
  if (new URL(origin).host !== new URL(expected).host) throw Object.assign(new Error("Запрос отклонён: неверный источник."), { status: 403 });
}
function requireDatabase() {
  if (!pool) throw Object.assign(new Error("База данных не подключена. Добавьте DATABASE_URL в Render."), { status: 503 });
}
async function initDatabase() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);
    CREATE TABLE IF NOT EXISTS generations (
      generation_id TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS daily_usage (
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      usage_day DATE NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY(user_id, usage_day)
    );
  `);
}
async function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", chunk => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(Object.assign(new Error("Фотографии слишком большие. Попробуйте изображения меньшего размера."), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { reject(Object.assign(new Error("Некорректный JSON-запрос."), { status: 400 })); }
    });
    req.on("error", reject);
  });
}
function parseDataUrl(value, label) {
  if (typeof value !== "string") throw new Error(`Не найдено изображение: ${label}.`);
  const match = value.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=\r\n]+)$/i);
  if (!match) throw new Error(`Формат изображения «${label}» не поддерживается. Используйте JPG, PNG или WebP.`);
  const buffer = Buffer.from(match[2], "base64");
  if (!buffer.length || buffer.length > 10 * 1024 * 1024) throw new Error(`Изображение «${label}» должно быть меньше 10 МБ.`);
  return { buffer, mimeType: match[1].toLowerCase() };
}
function publicBaseUrl(req) {
  if (process.env.RENDER_EXTERNAL_URL) return process.env.RENDER_EXTERNAL_URL.replace(/\/$/, "");
  const proto = String(req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
  const host = req.headers.host;
  if (!host) throw new Error("Не удалось определить адрес сайта для передачи фото в Genlook.");
  return `${proto}://${host}`;
}
async function genlookFetch(url, options = {}) {
  const key = process.env.GENLOOK_API_KEY;
  if (!key) throw Object.assign(new Error("Сервер ещё не настроен: добавьте GENLOOK_API_KEY в переменные окружения Render."), { status: 503 });
  const response = await fetch(url, {
    ...options,
    headers: { "x-api-key": key, ...(options.headers || {}) },
    signal: options.signal || AbortSignal.timeout(95000)
  });
  const raw = await response.text();
  let data = {};
  try { data = raw ? JSON.parse(raw) : {}; } catch { data = { message: raw.slice(0, 500) }; }
  if (!response.ok && response.status !== 202) {
    const message = data.message || data.error || data.detail || `Genlook вернул ошибку ${response.status}.`;
    const error = new Error(response.status === 402 ? "В аккаунте Genlook закончились кредиты. Проверьте баланс в кабинете Genlook." : message);
    error.status = response.status === 402 ? 402 : 502;
    throw error;
  }
  return { status: response.status, data };
}
function rateLimit(req, keyPrefix = "ip", max = 12) {
  const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").split(",")[0].trim();
  const key = `${keyPrefix}:${ip}`;
  const now = Date.now();
  const bucket = rateBuckets.get(key) || { start: now, count: 0 };
  if (now - bucket.start > 60 * 60 * 1000) { bucket.start = now; bucket.count = 0; }
  bucket.count += 1;
  rateBuckets.set(key, bucket);
  return bucket.count <= max;
}
async function currentUser(req) {
  requireDatabase();
  const token = getCookie(req, "cf_session");
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const result = await pool.query(
    "SELECT u.id, u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW()",
    [tokenHash]
  );
  return result.rows[0] || null;
}
async function createSession(req, res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  await pool.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '7 days')", [tokenHash, userId]);
  setSessionCookie(req, res, token);
}
async function reserveDailyTryon(userId) {
  const result = await pool.query(
    `INSERT INTO daily_usage(user_id,usage_day,count) VALUES($1,CURRENT_DATE,1)
     ON CONFLICT(user_id,usage_day) DO UPDATE SET count=daily_usage.count+1
     WHERE daily_usage.count < $2 RETURNING count`,
    [userId, DAILY_TRYON_LIMIT]
  );
  return result.rows[0]?.count || null;
}
async function releaseDailyTryon(userId) {
  await pool.query("UPDATE daily_usage SET count=GREATEST(count-1,0) WHERE user_id=$1 AND usage_day=CURRENT_DATE", [userId]);
}
function serveStatic(req, res, pathname) {
  const requested = pathname === "/" ? "/index.html" : decodeURIComponent(pathname);
  const target = path.resolve(PUBLIC_DIR, "." + requested);
  if (!target.startsWith(PUBLIC_DIR + path.sep) && target !== path.join(PUBLIC_DIR, "index.html")) {
    res.writeHead(403); res.end("Forbidden"); return;
  }
  fs.readFile(target, (error, content) => {
    if (error) { res.writeHead(404); res.end("Not found"); return; }
    const ext = path.extname(target).toLowerCase();
    const types = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".ico": "image/x-icon" };
    res.writeHead(200, { "Content-Type": types[ext] || "application/octet-stream", "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=3600" });
    res.end(content);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  try {
    if (req.method === "GET" && url.pathname === "/api/health") {
      return send(res, 200, { ok: true, genlookConfigured: Boolean(process.env.GENLOOK_API_KEY), databaseConfigured: Boolean(pool) });
    }

    if (req.method === "POST" && url.pathname === "/api/auth/register") {
      assertSameOrigin(req);
      if (!rateLimit(req, "register", 8)) return send(res, 429, { error: "Слишком много попыток регистрации. Попробуйте позже." });
      requireDatabase();
      const body = await readJson(req);
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 254) return send(res, 400, { error: "Введите корректный email." });
      if (password.length < 10 || password.length > 128) return send(res, 400, { error: "Пароль должен содержать от 10 до 128 символов." });
      const salt = crypto.randomBytes(16).toString("hex");
      const hash = (await scrypt(password, salt, 64)).toString("hex");
      let created;
      try { created = await pool.query("INSERT INTO users(email,password_hash,password_salt) VALUES($1,$2,$3) RETURNING id,email", [email, hash, salt]); }
      catch (error) { if (error.code === "23505") return send(res, 409, { error: "Аккаунт с таким email уже существует. Войдите в него." }); throw error; }
      await createSession(req, res, created.rows[0].id);
      return send(res, 201, { authenticated: true, user: created.rows[0], dailyTryonLimit: DAILY_TRYON_LIMIT });
    }

    if (req.method === "POST" && url.pathname === "/api/auth/login") {
      assertSameOrigin(req);
      if (!rateLimit(req, "login", 12)) return send(res, 429, { error: "Слишком много попыток входа. Попробуйте позже." });
      requireDatabase();
      const body = await readJson(req);
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      const found = await pool.query("SELECT id,email,password_hash,password_salt FROM users WHERE email=$1", [email]);
      const user = found.rows[0];
      if (!user) return send(res, 401, { error: "Неверный email или пароль." });
      const hash = (await scrypt(password, user.password_salt, 64)).toString("hex");
      if (!crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.password_hash, "hex"))) return send(res, 401, { error: "Неверный email или пароль." });
      await createSession(req, res, user.id);
      return send(res, 200, { authenticated: true, user: { id: user.id, email: user.email }, dailyTryonLimit: DAILY_TRYON_LIMIT });
    }

    if (req.method === "GET" && url.pathname === "/api/auth/me") {
      if (!pool) return send(res, 503, { error: "База данных не подключена." });
      const user = await currentUser(req);
      if (!user) return send(res, 200, { authenticated: false });
      const usage = await pool.query("SELECT count FROM daily_usage WHERE user_id=$1 AND usage_day=CURRENT_DATE", [user.id]);
      return send(res, 200, { authenticated: true, user, dailyTryonLimit: DAILY_TRYON_LIMIT, dailyTryonsUsed: usage.rows[0]?.count || 0 });
    }

    if (req.method === "POST" && url.pathname === "/api/auth/logout") {
      assertSameOrigin(req);
      if (pool) {
        const token = getCookie(req, "cf_session");
        if (token && /^[a-f0-9]{64}$/.test(token)) {
          const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
          await pool.query("DELETE FROM sessions WHERE token_hash=$1", [tokenHash]);
        }
      }
      clearSessionCookie(req, res);
      return send(res, 200, { ok: true });
    }

    if (req.method === "GET" && url.pathname.startsWith("/_genlook-assets/")) {
      const token = url.pathname.split("/").pop();
      const item = tempImages.get(token);
      if (!item || item.expiresAt < Date.now()) {
        tempImages.delete(token);
        res.writeHead(404); res.end("Image expired"); return;
      }
      res.writeHead(200, { "Content-Type": item.mimeType, "Content-Length": item.buffer.length, "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" });
      res.end(item.buffer);
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/tryon") {
      assertSameOrigin(req);
      const user = await currentUser(req);
      if (!user) return send(res, 401, { error: "Войдите в аккаунт, чтобы запустить примерку." });
      if (!rateLimit(req, "tryon", 10)) return send(res, 429, { error: "Слишком много запросов. Попробуйте позже." });
      const body = await readJson(req);
      const person = parseDataUrl(body.personImage, "фото человека");
      const products = Array.isArray(body.products) ? body.products : [];
      if (!products.length || products.length > 4) return send(res, 400, { error: "Выберите от одной до четырёх вещей." });
      const reservedCount = await reserveDailyTryon(user.id);
      if (!reservedCount) return send(res, 429, { error: `Достигнут дневной лимит: ${DAILY_TRYON_LIMIT} примерки на один аккаунт. Попробуйте завтра.` });
      let completed = false;
      try {
        const form = new FormData();
        const extension = person.mimeType.split("/")[1].replace("jpeg", "jpg");
        form.append("file", new Blob([person.buffer], { type: person.mimeType }), `person.${extension}`);
        const uploaded = await genlookFetch(`${GENLOOK_BASE}/images/upload`, { method: "POST", body: form });
        const imageId = uploaded.data.imageId;
        if (!imageId) throw Object.assign(new Error("Genlook не вернул imageId для фотографии."), { status: 502 });
        const baseUrl = publicBaseUrl(req);
        const productTokens = [];
        const apiProducts = products.map((product, index) => {
          const image = parseDataUrl(product.image, product.title || `вещь ${index + 1}`);
          const token = crypto.randomBytes(24).toString("hex");
          productTokens.push(token);
          tempImages.set(token, { buffer: image.buffer, mimeType: image.mimeType, expiresAt: Date.now() + 5 * 60 * 1000 });
          return {
            externalId: `create-fashion-${crypto.randomUUID()}`,
            title: String(product.title || `Fashion item ${index + 1}`).slice(0, 120),
            description: `Fashion item in category: ${String(product.zone || "clothing").slice(0, 40)}.`,
            images: [{ source: { url: `${baseUrl}/_genlook-assets/${token}` } }]
          };
        });
        const result = await genlookFetch(`${GENLOOK_BASE}/try-on/sync`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ products: apiProducts, person: { image: { source: { id: imageId } } }, externalUserId: String(user.id) }),
          signal: AbortSignal.timeout(95000)
        });
        const generationId = result.data.generationId || result.data.id;
        if (generationId) await pool.query("INSERT INTO generations(generation_id,user_id) VALUES($1,$2) ON CONFLICT(generation_id) DO UPDATE SET user_id=EXCLUDED.user_id", [String(generationId), user.id]);
        completed = true;
        return send(res, result.status === 202 ? 202 : 200, { ...result.data, dailyTryonsUsed: reservedCount, dailyTryonLimit: DAILY_TRYON_LIMIT });
      } finally {
        if (!completed) await releaseDailyTryon(user.id).catch(() => {});
      }
    }

    if (req.method === "GET" && url.pathname.startsWith("/api/generations/")) {
      const user = await currentUser(req);
      if (!user) return send(res, 401, { error: "Войдите в аккаунт, чтобы открыть результат." });
      const generationId = url.pathname.split("/").pop();
      if (!/^[A-Za-z0-9_-]{4,200}$/.test(generationId)) return send(res, 400, { error: "Некорректный ID генерации." });
      const owned = await pool.query("SELECT 1 FROM generations WHERE generation_id=$1 AND user_id=$2", [generationId, user.id]);
      if (!owned.rowCount) return send(res, 404, { error: "Генерация не найдена для этого аккаунта." });
      const result = await genlookFetch(`${GENLOOK_BASE}/generations/${encodeURIComponent(generationId)}`, { method: "GET", signal: AbortSignal.timeout(20000) });
      return send(res, result.status, result.data);
    }

    if (req.method === "GET" || req.method === "HEAD") return serveStatic(req, res, url.pathname);
    return send(res, 404, { error: "Маршрут не найден." });
  } catch (error) {
    console.error("Request failed:", error.message);
    return send(res, error.status || 500, { error: error.message || "Внутренняя ошибка сервера." });
  }
});

setInterval(() => {
  const now = Date.now();
  for (const [key, value] of tempImages) if (value.expiresAt < now) tempImages.delete(key);
  for (const [key, value] of rateBuckets) if (now - value.start > 2 * 60 * 60 * 1000) rateBuckets.delete(key);
  if (pool) pool.query("DELETE FROM sessions WHERE expires_at < NOW()").catch(() => {});
}, 60 * 60 * 1000).unref();

try {
  await initDatabase();
  server.listen(PORT, "0.0.0.0", () => console.log(`Create Fashion is running on port ${PORT}`));
} catch (error) {
  console.error("Database initialization failed:", error.message);
  process.exit(1);
}
