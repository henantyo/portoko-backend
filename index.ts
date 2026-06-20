import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import multer from 'multer';
import path from 'node:path';
import { getAdminConfig, verifyPassword, updateAdminPassword } from './admin-config.js';


dotenv.config({ path: './.env' });



const app = express();

app.use(
  cors({
    origin: '*',
  })
);
app.use(express.json({ limit: '1mb' }));

// Multer in-memory storage for multipart uploads (admin)
const upload = multer({ storage: multer.memoryStorage() });

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/debug', (_req, res) => {
  res.json({
    hasSupabaseUrl: !!process.env.SUPABASE_URL,
    hasSupabaseKey: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
    port: process.env.PORT,
    cwd: process.cwd(),
  });
});

// Basic rate limiting (admin endpoints)
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
});

function requireSupabaseConfig(res: express.Response) {
  const supabaseUrl = process.env.SUPABASE_URL || '';
  const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

  if (!supabaseUrl || !supabaseServiceRoleKey) {
    res.status(500).json({
      success: false,
      message: 'Supabase is not configured on backend. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.',
    });
    return null;
  }

  return createClient(supabaseUrl, supabaseServiceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

type AdminTokenSet = Set<string>;

function getAdminTokens(): AdminTokenSet {
  const g = globalThis as any;
  if (!g.__PORTOKO_ADMIN_TOKENS__) {
    g.__PORTOKO_ADMIN_TOKENS__ = new Set<string>();
  }
  return g.__PORTOKO_ADMIN_TOKENS__ as Set<string>;
}

function issueAdminToken() {
  // Simple opaque token (educational/local)
  return Math.random().toString(36).slice(2) + '.' + Date.now().toString(36);
}

app.post('/api/admin/login', adminLimiter, async (req, res) => {
  const { username, password } = req.body || {};

  const { username: expectedUsername } = getAdminConfig();

  if (username !== expectedUsername) {
    return res.status(401).json({ success: false, message: 'ACCESS DENIED: INVALID USERNAME' });
  }

  try {
    const isPasswordValid = await verifyPassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'ACCESS DENIED: CRYPTOGRAPHIC DECRYPTION FAILED' });
    }

    const token = issueAdminToken();
    getAdminTokens().add(token);

    return res.json({ success: true, token });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: 'AUTH_ERROR: Internal authentication service error' });
  }
});

app.post('/api/admin/change-password', adminLimiter, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ success: false, message: 'Missing currentPassword or newPassword' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ success: false, message: 'New password must be at least 6 characters long' });
  }

  try {
    // Verify current password
    const isCurrentPasswordValid = await verifyPassword(currentPassword);
    if (!isCurrentPasswordValid) {
      return res.status(401).json({ success: false, message: 'CURRENT_PASSWORD_INVALID: Cryptographic verification failed' });
    }

    // Update password
    const success = await updateAdminPassword(newPassword);
    if (!success) {
      throw new Error('Failed to write new password');
    }

    return res.json({ success: true, message: 'PASSWORD_UPDATED: Admin password changed successfully' });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message || 'Failed to change password' });
  }
});

function requireAdminAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = (req.headers.authorization || '') as string;
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice('Bearer '.length) : '';

  if (!token || !getAdminTokens().has(token)) {
    return res.status(401).json({ success: false, message: 'UNAUTHORIZED' });
  }

  next();
}

// Mapping helpers to keep payload aligned with existing frontend types
function mapProfileToDb(p: any) {
  return {
    id: 'main',
    name: p.name,
    title: p.title,
    bio: p.bio,
    about_long: p.aboutLong,
    school: p.school,
    major: p.major,
    avatar: p.avatar,
    cv_url: p.cvUrl,
    email: p.email,
    whatsapp: p.whatsapp,
    github: p.github,
    linkedin: p.linkedin,
    instagram: p.instagram,
  };
}

function mapDbToProfile(db: any) {
  return {
    name: db.name || '',
    title: db.title || '',
    bio: db.bio || '',
    aboutLong: db.about_long || '',
    school: db.school || '',
    major: db.major || '',
    avatar: db.avatar || '',
    cvUrl: db.cv_url || '',
    email: db.email || '',
    whatsapp: db.whatsapp || '',
    github: db.github || '',
    linkedin: db.linkedin || '',
    instagram: db.instagram || '',
  };
}

function mapProjectToDb(p: any) {
  return {
    id: p.id,
    title: p.title,
    description: p.description,
    image: p.image,
    tech_stack: p.techStack,
    github_url: p.githubUrl || '',
    featured: p.featured,
  };
}

function mapDbToProject(db: any) {
  return {
    id: db.id,
    title: db.title,
    description: db.description || '',
    image: db.image || '',
    techStack: db.tech_stack || [],
    githubUrl: db.github_url || '',
    featured: !!db.featured,
  };
}

function mapSkillToDb(s: any) {
  return {
    id: s.id,
    name: s.name,
    category: s.category,
    level: Number(s.level) || 80,
  };
}

function mapDbToSkill(db: any) {
  return {
    id: db.id,
    name: db.name || '',
    category: db.category || 'Frontend',
    level: Number(db.level) || 80,
  };
}

function mapExperienceToDb(e: any) {
  return {
    id: e.id,
    role: e.role,
    company: e.company,
    period: e.period,
    description: e.description || '',
    current: !!e.current,
  };
}

function mapDbToExperience(db: any) {
  return {
    id: db.id,
    role: db.role || '',
    company: db.company || '',
    period: db.period || '',
    description: db.description || '',
    current: !!db.current,
  };
}

app.post('/api/supabase/push', adminLimiter, requireAdminAuth, async (req, res) => {
  const supabase = requireSupabaseConfig(res);
  if (!supabase) return;

  try {
    const { profile, projects, skills, experiences } = req.body || {};

    if (profile) {
      const dbProfile = mapProfileToDb(profile);
      const { error } = await supabase.from('profile').upsert(dbProfile);
      if (error) throw error;
    }

    if (Array.isArray(projects)) {
      const dbProjects = projects.map(mapProjectToDb);
      await supabase.from('projects').delete().neq('id', 'keep-all-dummy');
      const { error } = await supabase.from('projects').insert(dbProjects);
      if (error) throw error;
    }

    if (Array.isArray(skills)) {
      const dbSkills = skills.map(mapSkillToDb);
      await supabase.from('skills').delete().neq('id', 'keep-all-dummy');
      const { error } = await supabase.from('skills').insert(dbSkills);
      if (error) throw error;
    }

    if (Array.isArray(experiences)) {
      const dbExperiences = experiences.map(mapExperienceToDb);
      await supabase.from('experiences').delete().neq('id', 'keep-all-dummy');
      const { error } = await supabase.from('experiences').insert(dbExperiences);
      if (error) throw error;
    }

    return res.json({ success: true, message: 'All local data successfully pushed to Supabase Cloud!' });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message || 'Unknown error' });
  }
});

// ----------------------------------------------------
// INDIVIDUAL CRUD ENDPOINTS
// ----------------------------------------------------

// GET all data
app.get('/api/admin/data', adminLimiter, requireAdminAuth, async (_req, res) => {
  const supabase = requireSupabaseConfig(res);
  if (!supabase) return;

  try {
    const { data: profileDb } = await supabase.from('profile').select('*').eq('id', 'main').single();
    const { data: projectsDb } = await supabase.from('projects').select('*');
    const { data: skillsDb } = await supabase.from('skills').select('*');
    const { data: expDb } = await supabase.from('experiences').select('*');

    return res.json({
      success: true,
      payload: {
        profile: profileDb ? mapDbToProfile(profileDb) : null,
        projects: Array.isArray(projectsDb) ? projectsDb.map(mapDbToProject) : [],
        skills: Array.isArray(skillsDb) ? skillsDb.map(mapDbToSkill) : [],
        experiences: Array.isArray(expDb) ? expDb.map(mapDbToExperience) : [],
      },
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message || 'Unknown error' });
  }
});

// Save profile
app.post('/api/admin/profile', adminLimiter, requireAdminAuth, async (req, res) => {
  const supabase = requireSupabaseConfig(res);
  if (!supabase) return;

  try {
    const dbProfile = mapProfileToDb(req.body);
    const { error } = await supabase.from('profile').upsert(dbProfile);
    if (error) throw error;
    return res.json({ success: true });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message });
  }
});

// Save projects (bulk upsert)
app.post('/api/admin/projects', adminLimiter, requireAdminAuth, async (req, res) => {
  const supabase = requireSupabaseConfig(res);
  if (!supabase) return;

  try {
    const projects = req.body;
    if (!Array.isArray(projects)) return res.status(400).json({ success: false, message: 'Expected array' });
    const dbProjects = projects.map(mapProjectToDb);
    await supabase.from('projects').delete().neq('id', 'keep-all-dummy');
    const { error } = await supabase.from('projects').insert(dbProjects);
    if (error) throw error;
    return res.json({ success: true });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message });
  }
});

// Save skills (bulk upsert)
app.post('/api/admin/skills', adminLimiter, requireAdminAuth, async (req, res) => {
  const supabase = requireSupabaseConfig(res);
  if (!supabase) return;

  try {
    const skills = req.body;
    if (!Array.isArray(skills)) return res.status(400).json({ success: false, message: 'Expected array' });
    const dbSkills = skills.map(mapSkillToDb);
    await supabase.from('skills').delete().neq('id', 'keep-all-dummy');
    const { error } = await supabase.from('skills').insert(dbSkills);
    if (error) throw error;
    return res.json({ success: true });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message });
  }
});

// Save experiences (bulk upsert)
app.post('/api/admin/experiences', adminLimiter, requireAdminAuth, async (req, res) => {
  const supabase = requireSupabaseConfig(res);
  if (!supabase) return;

  try {
    const experiences = req.body;
    if (!Array.isArray(experiences)) return res.status(400).json({ success: false, message: 'Expected array' });
    const dbExps = experiences.map(mapExperienceToDb);
    await supabase.from('experiences').delete().neq('id', 'keep-all-dummy');
    const { error } = await supabase.from('experiences').insert(dbExps);
    if (error) throw error;
    return res.json({ success: true });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message });
  }
});

// Upload project image to Supabase Storage (bucket private + signed URL)
// Expects multipart/form-data with fields:
// - file: image
// - projectId (optional): to build object path
//
// Returns: { success: true, imageUrl: <signed-url> }
app.post(
  '/api/admin/upload-project-image',
  adminLimiter,
  requireAdminAuth,
  upload.single('file'),
  async (req, res) => {
    const supabaseUrl = process.env.SUPABASE_URL || '';
    const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

    const bucket = process.env.SUPABASE_STORAGE_BUCKET_PROJECTS || 'portfolio-project-images';

    const projectId = String(req.body?.projectId || '').trim();
    const originalName = req.file?.originalname || '';
    const mimetype = req.file?.mimetype || '';
    const fileSize = req.file?.size ?? 0;

    if (!supabaseUrl || !supabaseServiceRoleKey) {
      console.error('[upload-project-image] Supabase env missing:', {
        SUPABASE_URL_present: !!supabaseUrl,
        SUPABASE_SERVICE_ROLE_KEY_present: !!supabaseServiceRoleKey,
        bucket,
        projectId,
        originalName,
      });
      return res.status(500).json({
        success: false,
        message: 'Supabase is not configured on backend. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.',
      });
    }

    if (!req.file) {
      console.warn('[upload-project-image] Missing file field (multipart/form-data)', {
        projectId,
      });
      return res.status(400).json({ success: false, message: 'Missing file field (multipart/form-data)' });
    }

    // TS typing guard for multer single file uploads
    const file = req.file;

    try {
      const supabase = createClient(supabaseUrl, supabaseServiceRoleKey, {
        auth: { persistSession: false, autoRefreshToken: false },
      });

      const ext = path.extname(file.originalname || '').toLowerCase() || '.png';
      const safeExt = ext.startsWith('.') ? ext.slice(1) : ext;
      const objectPath = `projects/${projectId ? projectId + '/' : ''}${Date.now()}-${Math.random().toString(36).slice(2)}.${safeExt}`;

      console.log('[upload-project-image] Attempt upload to Supabase Storage:', {
        bucket,
        objectPath,
        projectId,
        file: {
          originalName: file.originalname,
          mimetype: file.mimetype,
          size: file.size,
        },
      });

      const { error: uploadErr } = await supabase.storage
        .from(bucket)
        .upload(objectPath, file.buffer, {
          contentType: file.mimetype,
          upsert: true,
        });

      if (uploadErr) {
        console.error('[upload-project-image] Storage upload failed:', {
          message: uploadErr.message,
          status: (uploadErr as any).status,
          name: uploadErr.name,
        });
        throw uploadErr;
      }

      // signed URL for 7 days
      const expiresInSeconds = 7 * 24 * 60 * 60;
      console.log('[upload-project-image] Creating signed URL:', {
        bucket,
        objectPath,
        expiresInSeconds,
      });

      const { data, error: signedUrlErr } = await supabase.storage
        .from(bucket)
        .createSignedUrl(objectPath, expiresInSeconds);

      if (signedUrlErr) {
        console.error('[upload-project-image] createSignedUrl failed:', {
          message: signedUrlErr.message,
          status: (signedUrlErr as any).status,
          name: signedUrlErr.name,
        });
        return res.status(500).json({
          success: false,
          message: `Failed to create signed URL: ${signedUrlErr.message || 'unknown error'}`,
        });
      }

      if (!data?.signedUrl) {
        console.error('[upload-project-image] Signed URL missing in response:', { bucket, objectPath });
        return res.status(500).json({ success: false, message: 'Failed to create signed URL (signedUrl missing)' });
      }

      return res.json({ success: true, imageUrl: data.signedUrl });

    } catch (err: any) {
      console.error('[upload-project-image] Unexpected error:', {
        projectId,
        bucket,
        file: {
          originalName,
          mimetype,
          fileSize,
        },
        errorMessage: err?.message,
        errorName: err?.name,
      });
      return res.status(500).json({
        success: false,
        message: err?.message || 'Upload failed',
      });
    }
  }
);

app.post('/api/supabase/pull', adminLimiter, requireAdminAuth, async (_req, res) => {
  const supabase = requireSupabaseConfig(res);
  if (!supabase) return;

  try {
    const { data: profileDb, error: profErr } = await supabase
      .from('profile')
      .select('*')
      .eq('id', 'main')
      .single();

    const { data: projectsDb, error: projErr } = await supabase.from('projects').select('*');
    const { data: skillsDb, error: skillErr } = await supabase.from('skills').select('*');
    const { data: expDb, error: expErr } = await supabase.from('experiences').select('*');

    if (profErr) throw profErr;
    if (projErr) throw projErr;
    if (skillErr) throw skillErr;
    if (expErr) throw expErr;

    const payload = {
      profile: profileDb ? mapDbToProfile(profileDb) : null,
      projects: Array.isArray(projectsDb) ? projectsDb.map(mapDbToProject) : [],
      skills: Array.isArray(skillsDb) ? skillsDb.map(mapDbToSkill) : [],
      experiences: Array.isArray(expDb) ? expDb.map(mapDbToExperience) : [],
    };

    return res.json({
      success: true,
      message: 'Database successfully synchronized from Supabase Cloud!',
      payload,
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message || 'Unknown error' });
  }
});

// ----------------------------------------------------
// PUBLIC API (no auth needed)
// ----------------------------------------------------
app.get('/api/public/data', async (_req, res) => {
  try {
    const supabaseUrl = process.env.SUPABASE_URL || '';
    const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

    if (!supabaseUrl || !supabaseServiceRoleKey) {
      return res.status(500).json({ success: false, message: 'Supabase not configured' });
    }

    const supabase = createClient(supabaseUrl, supabaseServiceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const { data: profileDb } = await supabase.from('profile').select('*').eq('id', 'main').single().catch(() => ({ data: null }));
    const { data: projectsDb } = await supabase.from('projects').select('*').catch(() => ({ data: [] }));
    const { data: skillsDb } = await supabase.from('skills').select('*').catch(() => ({ data: [] }));
    const { data: expDb } = await supabase.from('experiences').select('*').catch(() => ({ data: [] }));

    return res.json({
      success: true,
      payload: {
        profile: profileDb ? mapDbToProfile(profileDb) : null,
        projects: Array.isArray(projectsDb) ? projectsDb.map(mapDbToProject) : [],
        skills: Array.isArray(skillsDb) ? skillsDb.map(mapDbToSkill) : [],
        experiences: Array.isArray(expDb) ? expDb.map(mapDbToExperience) : [],
      },
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err?.message || 'Unknown error' });
  }
});

const port = process.env.PORT ? Number(process.env.PORT) : 4000;
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`[backend] listening on :${port}`);
});

