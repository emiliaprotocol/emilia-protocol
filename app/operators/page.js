import { redirect } from 'next/navigation';

export const metadata = {
  title: 'Operators — EMILIA Protocol',
  description: 'Operators are the humans who make EP\'s appeals system real. See who reviews disputes, their accountability metrics, and how to become one.',
};

export default function OperatorsPage() {
  redirect('/operators.html');
}
