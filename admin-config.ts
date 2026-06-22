const USERNAME = 'admin';
const PASSWORD = 'admin123';

export async function getAdminConfig() {
  return { username: USERNAME, passwordHash: PASSWORD };
}

export async function verifyPassword(plainPassword: string): Promise<boolean> {
  return plainPassword === PASSWORD;
}

export async function updateAdminPassword(_newPassword: string): Promise<boolean> {
  return true;
}
