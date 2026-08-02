/**
 * POST /api/trust-desk/triage
 *
 * @license Apache-2.0
 *
 * The free tier of the Gap Scan. Takes a questionnaire, returns how its
 * questions sort, and stops there. It answers nothing and stores nothing.
 *
 * The value it delivers is the count a vendor cannot get anywhere else: how
 * many of these questions their SOC 2 report actually covers, and how many are
 * AI-specific questions their existing evidence was never built to answer. That
 * number is the whole sales argument, and it is true whether or not they buy.
 *
 * No session, no signup, no persistence. The questionnaire is parsed in memory
 * and discarded. Nothing here is an authorization decision or a security claim.
 */

import { NextResponse, type NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { extractQuestions, ExtractionUnsupportedError } from '@/lib/trust-desk/extractor';
import { classifyQuestions, BUCKET } from '@/lib/trust-desk/classifier';
import { enforceBodyByteLimit } from '@/lib/http/body-limit';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

const MAX_BYTES = 5 * 1024 * 1024;
const MAX_ENVELOPE_BYTES = MAX_BYTES + 1024 * 1024;

/** How each classifier bucket is presented. Wording is deliberately plain. */
const PRESENTATION: Record<string, { group: string; label: string; note: string }> = {
  [BUCKET.SOC2_OVERLAP]: {
    group: 'covered',
    label: 'Your SOC 2 already covers this',
    note: 'Conventional control questions. Your existing report and evidence answer these.',
  },
  [BUCKET.AI_TEMPLATE_MATCH]: {
    group: 'ai_specific',
    label: 'AI-specific, answerable from an AI policy',
    note: 'These need a written AI policy to cite. A SOC 2 report does not contain one.',
  },
  [BUCKET.AI_SPECIFIC]: {
    group: 'ai_specific',
    label: 'AI-specific, needs a written position',
    note: 'These need a considered answer about your AI system specifically.',
  },
  [BUCKET.CUSTOMER_SPECIFIC]: {
    group: 'your_facts',
    label: 'Only you can answer this',
    note: 'Facts about your deployment: providers, regions, retention. Nobody can answer these for you.',
  },
  [BUCKET.NOVEL]: {
    group: 'unclassified',
    label: 'Could not classify',
    note: 'Unusual phrasing or a question type not seen before. Unclassified is not the same as harmless.',
  },
};

export async function POST(request: NextRequest): Promise<NextResponse> {
  const limited = await checkRateLimit(`ip:${getClientIP(request)}`, 'submit');
  if (!limited.allowed) {
    const response = epProblem(429, 'rate_limited', 'Too many questionnaire triage requests');
    response.headers.set('retry-after', String(Math.max(1, Number(limited.reset) || 60)));
    return response;
  }

  // Count the complete HTTP envelope before request.json() or formData() can
  // buffer it. The extra megabyte permits multipart boundaries and fields but
  // does not weaken the five-megabyte questionnaire limit below.
  const bodyLimit = await enforceBodyByteLimit(request, MAX_ENVELOPE_BYTES);
  if (!bodyLimit.ok) {
    return epProblem(bodyLimit.status, bodyLimit.code, bodyLimit.detail);
  }

  let content: string | Buffer | undefined;
  let filename = 'pasted.txt';

  const contentType = request.headers.get('content-type') || '';
  try {
    if (contentType.includes('multipart/form-data')) {
      const form = await request.formData();
      const file = form.get('questionnaire');
      if (file && typeof file !== 'string') {
        if (file.size > MAX_BYTES) {
          return epProblem(413, 'file_too_large', 'questionnaire must be under 5 MB');
        }
        content = Buffer.from(await file.arrayBuffer());
        filename = file.name || filename;
      } else if (typeof form.get('text') === 'string') {
        content = String(form.get('text'));
      }
    } else {
      const body = await request.json();
      content = typeof body?.text === 'string' ? body.text : undefined;
      if (typeof body?.filename === 'string') filename = body.filename;
    }
  } catch {
    return epProblem(400, 'invalid_body', 'send JSON {text} or a multipart questionnaire file');
  }

  if (!content || (typeof content === 'string' && content.trim().length === 0)) {
    return epProblem(400, 'empty_input', 'paste your questionnaire or attach the file');
  }
  if (typeof content === 'string' && Buffer.byteLength(content) > MAX_BYTES) {
    return epProblem(413, 'file_too_large', 'questionnaire must be under 5 MB');
  }

  let extraction: any;
  try {
    extraction = await extractQuestions({ content, filename });
  } catch (err: any) {
    if (err instanceof ExtractionUnsupportedError) {
      return epProblem(415, 'unsupported_format', `cannot read ${err.format} yet; paste the text instead`);
    }
    return epProblem(400, 'extraction_failed', 'could not read that file');
  }

  if (!extraction.total_questions) {
    return NextResponse.json({
      total_questions: 0,
      message: 'No questions found. If this is a spreadsheet, try pasting the question column directly.',
      warnings: extraction.warnings || [],
    });
  }

  // Classification only. Nothing is answered and nothing is stored.
  const classified = await classifyQuestions(extraction.questions, {});

  const groups: Record<string, { label: string; note: string; count: number; examples: string[] }> = {};
  for (const q of classified) {
    const p = PRESENTATION[q.bucket] || PRESENTATION[BUCKET.NOVEL];
    const g = (groups[p.group] ||= { label: p.label, note: p.note, count: 0, examples: [] });
    g.count += 1;
    if (g.examples.length < 3) g.examples.push(String(q.text || '').slice(0, 180));
  }

  const aiSpecific = groups.ai_specific?.count || 0;
  const covered = groups.covered?.count || 0;
  const unclassified = groups.unclassified?.count || 0;

  return NextResponse.json({
    total_questions: extraction.total_questions,
    source_format: extraction.source_format,
    headline: aiSpecific > 0
      ? `${aiSpecific} of ${extraction.total_questions} questions are AI-specific. Your SOC 2 report does not answer those.`
      : `No AI-specific questions detected in ${extraction.total_questions} questions.`,
    counts: {
      total: extraction.total_questions,
      ai_specific: aiSpecific,
      covered_by_soc2: covered,
      your_facts_only: groups.your_facts?.count || 0,
      unclassified,
    },
    groups,
    scope: {
      what_this_is: 'A classification of the questions in this document. Nothing was answered.',
      what_this_is_not: [
        'Not an assessment of your security posture.',
        'Not a claim that the covered questions will satisfy your buyer.',
        'Unclassified means the classifier could not place it, not that it is harmless.',
      ],
      retention: 'Parsed in memory and discarded. Nothing was stored and no account was created.',
    },
  });
}
