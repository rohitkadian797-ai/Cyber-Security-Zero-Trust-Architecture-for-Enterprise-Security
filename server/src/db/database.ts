import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbPath = process.env.DATABASE_PATH || './zero_trust.db';
const resolvedDbPath = path.resolve(process.cwd(), dbPath);

// Ensure directory exists
const dbDir = path.dirname(resolvedDbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

export const db: DatabaseSync = new DatabaseSync(resolvedDbPath);

// Enable WAL mode for high concurrency and performance, plus enforce foreign keys
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

export function initDatabase() {
  const possiblePaths = [
    path.join(__dirname, 'schema.sql'),
    path.resolve(process.cwd(), 'src/db/schema.sql'),
    path.resolve(process.cwd(), 'server/src/db/schema.sql')
  ];

  let schema: string | null = null;
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      schema = fs.readFileSync(p, 'utf8');
      break;
    }
  }

  if (schema) {
    db.exec(schema);
  } else {
    console.warn('⚠️ Could not locate schema.sql at known locations');
  }
}

export default db;
