import fs from 'node:fs';
import path from 'node:path';
import bcrypt from 'bcryptjs';

export type AdminConfig = {
  username: string;
  passwordHash: string;
};

const CONFIG_PATH = path.resolve(process.cwd(), 'admin-config.json');
const SALT_ROUNDS = 10;

function safeReadConfig(): AdminConfig {
  try {
    if (!fs.existsSync(CONFIG_PATH)) {
      // Initialize with default hashed password: 'admin123'
      const defaultHash = bcrypt.hashSync('admin123', SALT_ROUNDS);
      return { username: 'admin', passwordHash: defaultHash };
    }
    const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
    const parsed = JSON.parse(raw) as Partial<AdminConfig>;

    return {
      username: String(parsed.username ?? 'admin'),
      passwordHash: String(parsed.passwordHash ?? bcrypt.hashSync('admin123', SALT_ROUNDS)),
    };
  } catch {
    const defaultHash = bcrypt.hashSync('admin123', SALT_ROUNDS);
    return { username: 'admin', passwordHash: defaultHash };
  }
}

export function getAdminConfig(): AdminConfig {
  return safeReadConfig();
}

export async function updateAdminPassword(newPassword: string): Promise<boolean> {
  try {
    const config = safeReadConfig();
    const newHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    const updated = {
      username: config.username,
      passwordHash: newHash,
    };
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(updated, null, 2), 'utf-8');
    return true;
  } catch (err) {
    console.error('Failed to update password:', err);
    return false;
  }
}

export async function verifyPassword(plainPassword: string): Promise<boolean> {
  const config = safeReadConfig();
  return bcrypt.compare(plainPassword, config.passwordHash);
}

export function setAdminConfig(next: AdminConfig): void {
  const payload: AdminConfig = {
    username: String(next.username),
    passwordHash: String(next.passwordHash),
  };

  fs.writeFileSync(CONFIG_PATH, JSON.stringify(payload, null, 2), 'utf-8');
}

