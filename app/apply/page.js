import { redirect } from 'next/navigation';

export const metadata = {
  title: 'Apply to Become an Operator — EMILIA Protocol',
  description: 'Operators are the humans who make EP\'s appeals system real. Apply to review disputes, build a public accountability record, and become part of the trust infrastructure.',
};

export default function ApplyPage() {
  redirect('/apply.html');
}
