import { redirect } from 'next/navigation';

export const metadata = {
  title: 'Quickstart — EMILIA Protocol',
  description: 'Get EP running in under 5 minutes. MCP server config, REST API, entity registration, receipt submission, and policy evaluation.',
};

export default function QuickstartPage() {
  redirect('/quickstart.html');
}
