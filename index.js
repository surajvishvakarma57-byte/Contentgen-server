import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { readFileSync, writeFileSync, existsSync } from "fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret_change_this";
const GROQ_KEY = process.env.GROQ_API_KEY || "";
const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
// Use a fast Groq model — llama-3.3-70b-versatile is excellent and fast
const GROQ_MODEL = "llama-3.3-70b-versatile";

app.use(cors({ origin: "*", credentials: false }));
app.use(express.json());

// ─── JSON Database ────────────────────────────────────────────────────────────
const DB_PATH = join(__dirname, "content-db.json");

function loadDB() {
  if (!existsSync(DB_PATH)) {
    const empty = { users: [], content: [], analytics_events: [], _nextId: { user: 1, content: 1, analytics: 1 } };
    writeFileSync(DB_PATH, JSON.stringify(empty, null, 2));
    return empty;
  }
  try {
    const data = JSON.parse(readFileSync(DB_PATH, "utf8"));
    if (!data.users) data.users = [];
    if (!data._nextId) data._nextId = { user: 1, content: 1, analytics: 1 };
    if (!data._nextId.user) data._nextId.user = 1;
    return data;
  } catch {
    return { users: [], content: [], analytics_events: [], _nextId: { user: 1, content: 1, analytics: 1 } };
  }
}

function saveDB(data) {
  writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function makeToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "7d" });
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer "))
    return res.status(401).json({ error: "Not authenticated" });
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "Name, email and password are required" });
  if (password.length < 6)
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  const data = loadDB();
  if (data.users.find((u) => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(409).json({ error: "An account with this email already exists" });
  const password_hash = await bcrypt.hash(password, 10);
  const id = data._nextId.user++;
  const user = { id, name, email: email.toLowerCase(), password_hash, created_at: new Date().toISOString() };
  data.users.push(user);
  saveDB(data);
  const token = makeToken(id);
  const { password_hash: _, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password are required" });
  const data = loadDB();
  const user = data.users.find((u) => u.email === email.toLowerCase());
  if (!user) return res.status(401).json({ error: "No account found with this email" });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "Incorrect password" });
  const token = makeToken(user.id);
  const { password_hash: _, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  const data = loadDB();
  const user = data.users.find((u) => u.id === req.userId);
  if (!user) return res.status(404).json({ error: "User not found" });
  const { password_hash: _, ...safeUser } = user;
  res.json(safeUser);
});

app.put("/api/auth/profile", requireAuth, async (req, res) => {
  const { name, email } = req.body;
  const data = loadDB();
  const idx = data.users.findIndex((u) => u.id === req.userId);
  if (idx === -1) return res.status(404).json({ error: "User not found" });
  if (email && email.toLowerCase() !== data.users[idx].email) {
    const taken = data.users.find((u) => u.email === email.toLowerCase() && u.id !== req.userId);
    if (taken) return res.status(409).json({ error: "Email already in use" });
  }
  if (name) data.users[idx].name = name.trim();
  if (email) data.users[idx].email = email.toLowerCase().trim();
  saveDB(data);
  const { password_hash: _, ...safeUser } = data.users[idx];
  res.json({ user: safeUser });
});

app.put("/api/auth/password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword)
    return res.status(400).json({ error: "Both current and new password are required" });
  if (newPassword.length < 6)
    return res.status(400).json({ error: "New password must be at least 6 characters" });
  const data = loadDB();
  const idx = data.users.findIndex((u) => u.id === req.userId);
  if (idx === -1) return res.status(404).json({ error: "User not found" });
  const valid = await bcrypt.compare(currentPassword, data.users[idx].password_hash);
  if (!valid) return res.status(401).json({ error: "Current password is incorrect" });
  data.users[idx].password_hash = await bcrypt.hash(newPassword, 10);
  saveDB(data);
  res.json({ message: "Password updated successfully" });
});

// ─── DB helpers ───────────────────────────────────────────────────────────────
const db = {
  insertContent(row) {
    const data = loadDB();
    const id = data._nextId.content++;
    const record = { id, ...row, created_at: new Date().toISOString() };
    data.content.push(record);
    saveDB(data);
    return { lastInsertRowid: id };
  },
  insertEvent(row) {
    const data = loadDB();
    const id = data._nextId.analytics++;
    data.analytics_events.push({ id, ...row, created_at: new Date().toISOString() });
    saveDB(data);
  },
  getContent({ type, search, limit = 50, offset = 0, userId } = {}) {
    const data = loadDB();
    let items = [...data.content].filter((i) => i.user_id === userId).reverse();
    if (type && type !== "all")
      items = items.filter((i) => i.type.toLowerCase() === type.toLowerCase());
    if (search) {
      const s = search.toLowerCase();
      items = items.filter((i) => i.title.toLowerCase().includes(s) || i.content.toLowerCase().includes(s));
    }
    const total = items.length;
    const paginated = items.slice(offset, offset + limit).map((i) => {
      const { content, ...rest } = i;
      return { ...rest, preview: content.substring(0, 200) };
    });
    return { items: paginated, total };
  },
  getContentById(id, userId) {
    const data = loadDB();
    return data.content.find((i) => i.id === parseInt(id) && i.user_id === userId) || null;
  },
  deleteContent(id, userId) {
    const data = loadDB();
    const item = data.content.find((i) => i.id === parseInt(id) && i.user_id === userId);
    if (!item) return false;
    data.content = data.content.filter((i) => i.id !== parseInt(id));
    data.analytics_events = data.analytics_events.filter((e) => e.content_id !== parseInt(id));
    saveDB(data);
    return true;
  },
  getAnalytics(userId) {
    const data = loadDB();
    const content = data.content.filter((i) => i.user_id === userId);
    const totalContent = content.length;
    const totalWords = content.reduce((s, i) => s + (i.word_count || 0), 0);
    const typeMap = {};
    content.forEach((i) => {
      if (!typeMap[i.type]) typeMap[i.type] = { type: i.type, count: 0, words: 0 };
      typeMap[i.type].count++;
      typeMap[i.type].words += i.word_count || 0;
    });
    const sixMonthsAgo = new Date(); sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
    const monthMap = {};
    content.filter((i) => new Date(i.created_at) >= sixMonthsAgo).forEach((i) => {
      const d = new Date(i.created_at);
      const month = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
      const key = `${month}__${i.type}`;
      if (!monthMap[key]) monthMap[key] = { month, type: i.type, count: 0, words: 0 };
      monthMap[key].count++;
      monthMap[key].words += i.word_count || 0;
    });
    const sixWeeksAgo = new Date(); sixWeeksAgo.setDate(sixWeeksAgo.getDate() - 42);
    const weekMap = {};
    content.filter((i) => new Date(i.created_at) >= sixWeeksAgo).forEach((i) => {
      const d = new Date(i.created_at);
      const startOfYear = new Date(d.getFullYear(), 0, 1);
      const weekNum = Math.ceil(((d - startOfYear) / 86400000 + startOfYear.getDay() + 1) / 7);
      const week = `${d.getFullYear()}-W${String(weekNum).padStart(2, "0")}`;
      if (!weekMap[week]) weekMap[week] = { week, words: 0, count: 0 };
      weekMap[week].words += i.word_count || 0;
      weekMap[week].count++;
    });
    const topContent = [...content].sort((a, b) => (b.word_count || 0) - (a.word_count || 0)).slice(0, 5)
      .map(({ id, title, type, word_count, char_count, created_at }) => ({ id, title, type, word_count, char_count, created_at }));
    const now = new Date();
    const d7 = new Date(now); d7.setDate(d7.getDate() - 7);
    const d14 = new Date(now); d14.setDate(d14.getDate() - 14);
    const recent7 = content.filter((i) => new Date(i.created_at) >= d7).length;
    const prev7 = content.filter((i) => new Date(i.created_at) >= d14 && new Date(i.created_at) < d7).length;
    const changePercent = prev7 > 0 ? (((recent7 - prev7) / prev7) * 100).toFixed(1) : 0;
    const recentWords = content.filter((i) => new Date(i.created_at) >= d7).reduce((s, i) => s + (i.word_count || 0), 0);
    const prevWords = content.filter((i) => new Date(i.created_at) >= d14 && new Date(i.created_at) < d7).reduce((s, i) => s + (i.word_count || 0), 0);
    const wordsChange = prevWords > 0 ? (((recentWords - prevWords) / prevWords) * 100).toFixed(1) : 0;
    return {
      stats: { totalContent, totalWords, changePercent: `${changePercent >= 0 ? "+" : ""}${changePercent}%`, wordsChange: `${wordsChange >= 0 ? "+" : ""}${wordsChange}%` },
      byType: Object.values(typeMap),
      byMonth: Object.values(monthMap).sort((a, b) => a.month.localeCompare(b.month)),
      byWeek: Object.values(weekMap).sort((a, b) => a.week.localeCompare(b.week)),
      topContent,
    };
  },
};

// ─── Prompt builder ───────────────────────────────────────────────────────────
function buildSystemPrompt(platform, tone) {
  const platforms = {
    blog: "Write a comprehensive blog post with a headline, intro, body sections with ## headers, and conclusion.",
    instagram: "Write an Instagram caption with emojis, a hook, and 5-10 relevant hashtags at the end.",
    linkedin: "Write a professional LinkedIn post with a compelling hook and call-to-action.",
    twitter: "Write a Twitter/X thread. Start with 1/, then 2/, 3/ etc. Keep each tweet under 280 chars.",
    email: "Write a marketing email with Subject line, Preview text, body sections, and CTA.",
    marketing: "Write marketing copy with headline, value proposition, key benefits, and CTA.",
  };
  const tones = {
    professional: "Use a professional, authoritative tone.",
    casual: "Use a friendly, conversational tone.",
    persuasive: "Use persuasive language with a sense of urgency.",
    "seo-optimized": "Use SEO best practices with relevant keywords and proper headings.",
  };
  return `You are an expert content creator.\n${platforms[platform] || platforms.blog}\n${tones[tone] || tones.professional}\nWrite original, ready-to-publish content.`;
}

// ─── SSE broadcast ────────────────────────────────────────────────────────────
let sseClients = [];
function broadcastAnalytics(data) {
  sseClients.forEach((res) => res.write(`data: ${JSON.stringify(data)}\n\n`));
}

// ─── POST /api/generate — Groq streaming ─────────────────────────────────────
app.post("/api/generate", requireAuth, async (req, res) => {
  const { prompt, platform = "blog", tone = "professional" } = req.body;
  if (!prompt?.trim()) return res.status(400).json({ error: "Prompt is required" });
  if (!GROQ_KEY) return res.status(500).json({ error: "GROQ_API_KEY is not set in server/.env" });

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  let fullContent = "";

  try {
    console.log(`▶ [user:${req.userId}] Groq generating ${platform}/${tone}`);

    // Call Groq with stream: true
    const groqRes = await fetch(GROQ_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${GROQ_KEY}`,
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        stream: true,
        max_tokens: 2048,
        temperature: 0.7,
        messages: [
          { role: "system", content: buildSystemPrompt(platform, tone) },
          { role: "user", content: prompt },
        ],
      }),
    });

    if (!groqRes.ok) {
      const errData = await groqRes.json().catch(() => ({}));
      throw new Error(errData?.error?.message || `Groq API error: ${groqRes.status}`);
    }

    // Stream chunks to client
    const reader = groqRes.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const lines = decoder.decode(value, { stream: true }).split("\n");
      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const payload = line.slice(6).trim();
        if (payload === "[DONE]") continue;
        try {
          const parsed = JSON.parse(payload);
          const text = parsed.choices?.[0]?.delta?.content;
          if (text) {
            fullContent += text;
            res.write(`data: ${JSON.stringify({ type: "chunk", text })}\n\n`);
          }
        } catch { }
      }
    }

    // Generate title using Groq (non-streaming)
    const titleRes = await fetch(GROQ_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${GROQ_KEY}` },
      body: JSON.stringify({
        model: GROQ_MODEL,
        max_tokens: 20,
        messages: [
          { role: "user", content: `Write a short title (max 8 words) for this content. Reply with ONLY the title, no quotes or explanation:\n\n${fullContent.substring(0, 500)}` },
        ],
      }),
    });
    const titleData = await titleRes.json();
    const title = (titleData.choices?.[0]?.message?.content || "Generated Content").trim().replace(/["'.]/g, "");

    const wordCount = fullContent.split(/\s+/).filter(Boolean).length;
    const charCount = fullContent.length;

    // Save with user_id for isolation
    const { lastInsertRowid: contentId } = db.insertContent({
      title, type: platform, platform, tone, prompt,
      content: fullContent, word_count: wordCount, char_count: charCount,
      user_id: req.userId,
    });
    db.insertEvent({ event_type: "generate", content_id: contentId, content_type: platform, platform, word_count: wordCount, user_id: req.userId });
    broadcastAnalytics({ type: "new_content", platform, wordCount, contentId });

    res.write(`data: ${JSON.stringify({ type: "done", contentId, title, wordCount, charCount })}\n\n`);
    res.end();
    console.log(`✓ Saved ID ${contentId}: "${title}" (${wordCount} words)`);

  } catch (err) {
    console.error("❌ Generate error:", err.message);
    res.write(`data: ${JSON.stringify({ type: "error", message: err.message })}\n\n`);
    res.end();
  }
});

// ─── Content routes ───────────────────────────────────────────────────────────
app.get("/api/content", requireAuth, (req, res) => {
  const { type, search, limit = 50, offset = 0 } = req.query;
  res.json(db.getContent({ type, search, limit: parseInt(limit), offset: parseInt(offset), userId: req.userId }));
});

app.get("/api/content/:id", requireAuth, (req, res) => {
  const item = db.getContentById(req.params.id, req.userId);
  if (!item) return res.status(404).json({ error: "Not found" });
  res.json(item);
});

app.delete("/api/content/:id", requireAuth, (req, res) => {
  const deleted = db.deleteContent(req.params.id, req.userId);
  if (!deleted) return res.status(404).json({ error: "Not found" });
  broadcastAnalytics({ type: "deleted", contentId: parseInt(req.params.id) });
  res.json({ success: true });
});

// ─── Analytics ────────────────────────────────────────────────────────────────
app.get("/api/analytics", requireAuth, (req, res) => {
  res.json(db.getAnalytics(req.userId));
});

app.get("/api/analytics/stream", requireAuth, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.flushHeaders();
  res.write(`data: ${JSON.stringify({ type: "connected" })}\n\n`);
  sseClients.push(res);
  req.on("close", () => { sseClients = sseClients.filter((c) => c !== res); });
});

// ─── Health ───────────────────────────────────────────────────────────────────
app.get("/api/health", (_, res) => res.json({ status: "ok", ai: "groq", model: GROQ_MODEL, timestamp: new Date().toISOString() }));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ Backend running on http://localhost:${PORT}`);
  console.log(`🤖 AI: Groq (${GROQ_MODEL})`);
  if (!GROQ_KEY) console.log(`⚠️  GROQ_API_KEY not set in server/.env`);
  else console.log(`🔑 Groq key loaded ✓`);
  console.log(`🔐 Auth: JWT enabled ✓\n`);
});