import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import multer from 'multer';
import path from 'node:path';
import { verifyPassword } from './admin-config.js';

dotenv.config();

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '1mb' }));

const upload = multer({ storage: multer.memoryStorage() });

const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120 });

// Tokens
const adminTokens = new Set<string>();
function issueAdminToken() {
  return Math.random().toString(36).slice(2) + '.' + Date.now().toString(36);
}

function requireAdminAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = (req.headers.authorization || '') as string;
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice('Bearer '.length) : '';
  if (!token || !adminTokens.has(token)) {
    return res.status(401).json({ success: false, message: 'UNAUTHORIZED' });
  }
  next();
}

// ---- HEALTH ----
app.get('/health', (_req, res) => res.json({ ok: true }));

// ---- LOGIN ----
app.post('/api/admin/login', adminLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  try {
    const config = await import('./admin-config.js').then(m => m.getAdminConfig());
    if (username !== config.username) {
      return res.status(401).json({ success: false, message: 'ACCESS DENIED: INVALID USERNAME' });
    }
    const valid = await verifyPassword(password);
    if (!valid) {
      return res.status(401).json({ success: false, message: 'ACCESS DENIED: WRONG PASSWORD' });
    }
    const token = issueAdminToken();
    adminTokens.add(token);
    return res.json({ success: true, token });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message || 'Login error' });
  }
});

// ---- UPLOAD IMAGE (generic) ----
app.post('/api/admin/upload-image', adminLimiter, requireAdminAuth, upload.single('file'), async (req, res) => {
  const supabaseUrl = process.env.SUPABASE_URL || '';
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  const bucket = process.env.SUPABASE_STORAGE_BUCKET_PROJECTS || 'portfolio-project-images';

  if (!supabaseUrl || !supabaseKey) {
    return res.status(500).json({ success: false, message: 'Supabase not configured' });
  }
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'Missing file' });
  }

  const file = req.file;
  const folder = String(req.body?.folder || 'projects').trim();

  try {
    const supabase = createClient(supabaseUrl, supabaseKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const ext = path.extname(file.originalname || '').toLowerCase() || '.png';
    const safeExt = ext.startsWith('.') ? ext.slice(1) : ext;
    const objectPath = `${folder}/${Date.now()}-${Math.random().toString(36).slice(2)}.${safeExt}`;

    const { error: uploadErr } = await supabase.storage
      .from(bucket)
      .upload(objectPath, file.buffer, { contentType: file.mimetype, upsert: true });
    if (uploadErr) throw uploadErr;

    const { data, error: signedErr } = await supabase.storage
      .from(bucket)
      .createSignedUrl(objectPath, 7 * 24 * 60 * 60);
    if (signedErr) throw signedErr;
    if (!data?.signedUrl) return res.status(500).json({ success: false, message: 'Signed URL missing' });

    return res.json({ success: true, imageUrl: data.signedUrl });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message || 'Upload failed' });
  }
});

// ---- SAVE PROFILE TO SUPABASE ----
app.post('/api/admin/profile', adminLimiter, requireAdminAuth, async (req, res) => {
  const supabaseUrl = process.env.SUPABASE_URL || '';
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!supabaseUrl || !supabaseKey) {
    return res.status(500).json({ success: false, message: 'Supabase not configured' });
  }

  try {
    const p = req.body;
    const supabase = createClient(supabaseUrl, supabaseKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { error } = await supabase.from('profile').upsert({
      id: 'main',
      name: p.name || '',
      title: p.title || '',
      bio: p.bio || '',
      about_long: p.aboutLong || '',
      school: p.school || '',
      major: p.major || '',
      avatar: p.avatar || '',
      cv_url: p.cvUrl || '',
      email: p.email || '',
      whatsapp: p.whatsapp || '',
      github: p.github || '',
      linkedin: p.linkedin || '',
      instagram: p.instagram || '',
    }, { onConflict: 'id' });
    if (error) throw error;
    return res.json({ success: true });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message });
  }
});

// ---- SYNC ALL DATA TO SUPABASE ----
app.post('/api/admin/sync-all', adminLimiter, requireAdminAuth, async (req, res) => {
  const supabaseUrl = process.env.SUPABASE_URL || '';
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!supabaseUrl || !supabaseKey) {
    return res.status(500).json({ success: false, message: 'Supabase not configured' });
  }

  try {
    const { projects, skills, experiences } = req.body || {};
    const supabase = createClient(supabaseUrl, supabaseKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    if (Array.isArray(projects)) {
      await supabase.from('projects').delete().neq('id', 'keep-all-dummy');
      const dbProjects = projects.map((p: any) => ({
        id: p.id, title: p.title, description: p.description || '', image: p.image || '',
        tech_stack: p.techStack || [], github_url: p.githubUrl || '', featured: !!p.featured,
      }));
      if (dbProjects.length) {
        const { error } = await supabase.from('projects').insert(dbProjects);
        if (error) throw error;
      }
    }

    if (Array.isArray(skills)) {
      await supabase.from('skills').delete().neq('id', 'keep-all-dummy');
      const dbSkills = skills.map((s: any) => ({
        id: s.id, name: s.name, category: s.category || 'Frontend', level: Number(s.level) || 80,
      }));
      if (dbSkills.length) {
        const { error } = await supabase.from('skills').insert(dbSkills);
        if (error) throw error;
      }
    }

    if (Array.isArray(experiences)) {
      await supabase.from('experiences').delete().neq('id', 'keep-all-dummy');
      const dbExps = experiences.map((e: any) => ({
        id: e.id, role: e.role, company: e.company, period: e.period,
        description: e.description || '', current: !!e.current,
      }));
      if (dbExps.length) {
        const { error } = await supabase.from('experiences').insert(dbExps);
        if (error) throw error;
      }
    }

    return res.json({ success: true });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message });
  }
});

// ---- PUBLIC DATA ----
app.get('/api/public/data', async (_req, res) => {
  try {
    const supabaseUrl = process.env.SUPABASE_URL || '';
    const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
    if (!supabaseUrl || !supabaseKey) {
      return res.json({ success: true, payload: { profile: null, projects: [], skills: [], experiences: [] } });
    }
    const supabase = createClient(supabaseUrl, supabaseKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    let profileDb: any = null;
    let projectsDb: any[] = [];
    let skillsDb: any[] = [];
    let expDb: any[] = [];
    try { const r = await supabase.from('profile').select('*').eq('id', 'main').single(); profileDb = r.data; } catch {}
    try { const r = await supabase.from('projects').select('*'); projectsDb = r.data || []; } catch {}
    try { const r = await supabase.from('skills').select('*'); skillsDb = r.data || []; } catch {}
    try { const r = await supabase.from('experiences').select('*'); expDb = r.data || []; } catch {}

    function mapProfile(p: any) {
      return { name: p.name || '', title: p.title || '', bio: p.bio || '', aboutLong: p.about_long || '',
        school: p.school || '', major: p.major || '', avatar: p.avatar || '', cvUrl: p.cv_url || '',
        email: p.email || '', whatsapp: p.whatsapp || '', github: p.github || '',
        linkedin: p.linkedin || '', instagram: p.instagram || '' };
    }
    function mapProject(p: any) {
      return { id: p.id, title: p.title, description: p.description || '', image: p.image || '',
        techStack: p.tech_stack || [], githubUrl: p.github_url || '', featured: !!p.featured };
    }
    function mapSkill(s: any) {
      return { id: s.id, name: s.name || '', category: s.category || 'Frontend', level: Number(s.level) || 80 };
    }
    function mapExp(e: any) {
      return { id: e.id, role: e.role || '', company: e.company || '', period: e.period || '',
        description: e.description || '', current: !!e.current };
    }

    return res.json({
      success: true,
      payload: {
        profile: profileDb ? mapProfile(profileDb) : null,
        projects: projectsDb.map(mapProject),
        skills: skillsDb.map(mapSkill),
        experiences: expDb.map(mapExp),
      },
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message });
  }
});

const port = process.env.PORT ? Number(process.env.PORT) : 4000;
app.listen(port, () => console.log(`[backend] listening on :${port}`));
