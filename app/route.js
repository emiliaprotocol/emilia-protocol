import { readFileSync } from 'fs';
import { join } from 'path';

export async function GET() {
  // Try public/ first (available in standalone builds), fall back to content/
  let html;
  try {
    html = readFileSync(join(process.cwd(), 'public', 'landing.html'), 'utf8');
  } catch {
    html = readFileSync(join(process.cwd(), 'content', 'landing.html'), 'utf8');
  }
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}
