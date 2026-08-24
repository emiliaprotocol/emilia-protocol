'use client';

import { useEffect, type MouseEvent } from 'react';

const TARGET_ID = 'main-content';

function resolveMainTarget(): HTMLElement | null {
  const target = document.querySelector<HTMLElement>('main')
    ?? document.querySelector<HTMLElement>('h1');
  if (target && !target.id) target.id = TARGET_ID;
  return target;
}

export default function SkipToMain(): React.ReactElement {
  useEffect(() => {
    resolveMainTarget();
  }, []);

  function skip(event: MouseEvent<HTMLAnchorElement>) {
    const target = resolveMainTarget();
    if (!target) return;

    event.preventDefault();
    const previousTabIndex = target.getAttribute('tabindex');
    target.setAttribute('tabindex', '-1');
    target.focus({ preventScroll: true });
    target.scrollIntoView({ block: 'start' });

    if (previousTabIndex === null) {
      target.addEventListener('blur', () => target.removeAttribute('tabindex'), { once: true });
    }
  }

  return (
    <a className="ep-skip-link" href={`#${TARGET_ID}`} onClick={skip}>
      Skip to main content
    </a>
  );
}
