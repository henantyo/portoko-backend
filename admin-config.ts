import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';

export type AdminConfig = {
  username: string;
  passwordHash: string;
};

const SALT_ROUNDS = 10;
const DEFAULT_USERNAME = 'admin';
const DEFAULT_PASSWORD = 'admin123';

function getSupabaseClient() {
  const url = process.env.SUPABASE_URL || '';
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!url || !key) return null;
  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

async function readConfigFromDb(): Promise<AdminConfig | null> {
  const supabase = getSupabaseClient();
  if (!supabase) return null;

  try {
    const { data, error } = await supabase
      .from('admin_settings')
      .select('value')
      .eq('key', 'admin_password_hash')
      .single();

    if (error || !data?.value) return null;

    return {
      username: DEFAULT_USERNAME,
      passwordHash: data.value,
    };
  } catch {
    return null;
  }
}

async function writeConfigToDb(hash: string): Promise<boolean> {
  const supabase = getSupabaseClient();
  if (!supabase) return false;

  try {
    const { error } = await supabase
      .from('admin_settings')
      .upsert({ key: 'admin_password_hash', value: hash, updated_at: new Date().toISOString() });

    return !error;
  } catch {
    return false;
  }
}

export async function getAdminConfig(): Promise<AdminConfig> {
  const dbConfig = await readConfigFromDb();
  if (dbConfig) return dbConfig;

  // First time: create default password hash and save to DB
  const defaultHash = await bcrypt.hash(DEFAULT_PASSWORD, SALT_ROUNDS);
  await writeConfigToDb(defaultHash);

  return {
    username: DEFAULT_USERNAME,
    passwordHash: defaultHash,
  };
}

export async function verifyPassword(plainPassword: string): Promise<boolean> {
  const config = await getAdminConfig();
  return bcrypt.compare(plainPassword, config.passwordHash);
}

export async function updateAdminPassword(newPassword: string): Promise<boolean> {
  const newHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  return writeConfigToDb(newHash);
}

// Kept for backward compatibility but now async
export function setAdminConfig(_next: AdminConfig): void {
  // No-op: use updateAdminPassword instead
}
