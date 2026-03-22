import { readFileSync } from 'fs';
import { join } from 'path';

export async function GET() {
  const html = readFileSync(join(process.cwd(), 'content', 'landing.html'), 'utf8');
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}
