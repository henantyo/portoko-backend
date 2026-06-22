import { createClient } from '@supabase/supabase-js';
import crypto from 'node:crypto';

export type AdminConfig = {
  username: string;
  passwordHash: string;
};

const DEFAULT_USERNAME = 'admin';
const DEFAULT_PASSWORD = 'admin123';

function hashPassword(password: string): string {
  return crypto.createHash('sha256').update(password + 'portoko-salt-2024').digest('hex');
}

function getSupabaseClient() {
  const url = process.env.SUPABASE_URL || '';
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!url || !key) return null;
  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

async function readHashFromDb(): Promise<string | null> {
  const supabase = getSupabaseClient();
  if (!supabase) return null;

  try {
    const { data, error } = await supabase
      .from('admin_settings')
      .select('value')
      .eq('key', 'admin_password_hash')
      .single();

    if (error || !data?.value) return null;
    return data.value;
  } catch {
    return null;
  }
}

async function writeHashToDb(hash: string): Promise<boolean> {
  const supabase = getSupabaseClient();
  if (!supabase) return false;

  try {
    const { error } = await supabase
      .from('admin_settings')
      .upsert({ key: 'admin_password_hash', value: hash, updated_at: new Date().toISOString() }, { onConflict: 'key' });

    return !error;
  } catch {
    return false;
  }
}

export async function getAdminConfig(): Promise<AdminConfig> {
  const hash = await readHashFromDb();
  if (hash) return { username: DEFAULT_USERNAME, passwordHash: hash };

  const defaultHash = hashPassword(DEFAULT_PASSWORD);
  await writeHashToDb(defaultHash);
  return { username: DEFAULT_USERNAME, passwordHash: defaultHash };
}

export async function verifyPassword(plainPassword: string): Promise<boolean> {
  const config = await getAdminConfig();
  const inputHash = hashPassword(plainPassword);
  return inputHash === config.passwordHash;
}

export async function updateAdminPassword(newPassword: string): Promise<boolean> {
  const newHash = hashPassword(newPassword);
  return writeHashToDb(newHash);
}

export function setAdminConfig(_next: AdminConfig): void {}
