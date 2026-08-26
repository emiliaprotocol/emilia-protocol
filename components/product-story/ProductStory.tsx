// SPDX-License-Identifier: Apache-2.0
import Link from 'next/link';
import {
  PRODUCT_STORIES,
  PRODUCT_STORY_SCENARIO,
  getProductStory,
} from '@/lib/product-stories';
import type { ProductStoryKey } from '@/lib/product-stories';
import styles from './product-story.module.css';

export function ProductJourney({ active }: { active?: ProductStoryKey }): React.ReactElement {
  return (
    <nav className={styles.journey} aria-label="EMILIA product story">
      <ol className={styles.journeyList}>
        {PRODUCT_STORIES.map((story) => (
          <li key={story.key}>
            <Link
              className={styles.journeyLink}
              data-active={active === story.key ? 'true' : undefined}
              aria-current={active === story.key ? 'page' : undefined}
              href={story.href}
            >
              <span className={styles.journeyNumber}>{story.chapter}</span>
              <span className={styles.journeyName}>{story.name}</span>
            </Link>
          </li>
        ))}
      </ol>
    </nav>
  );
}

export function ProductStoryHero({ product }: { product: ProductStoryKey }): React.ReactElement {
  const story = getProductStory(product);

  return (
    <>
      <section className={styles.hero} aria-labelledby={`${story.key}-story-title`}>
        <div className={`${styles.shell} ${styles.heroGrid}`}>
          <div>
            <div className={styles.chapter}>{story.chapter} / {story.verb} / {story.name}</div>
            <h1 id={`${story.key}-story-title`}>{story.headline}</h1>
            <p className={styles.lead}>{story.lead}</p>
            <p className={styles.job}>{story.job}</p>
            <div className={styles.actions}>
              <Link className={styles.primary} href={story.primaryCta.href}>{story.primaryCta.label}</Link>
              <Link className={styles.secondary} href={story.proofCta.href}>{story.proofCta.label}</Link>
            </div>
          </div>

          <aside className={styles.scene} aria-label={`${story.name} illustrative workflow`}>
            <div className={styles.sceneHeader}>
              <span>{PRODUCT_STORY_SCENARIO.label}</span>
              <span>Not a customer claim</span>
            </div>
            <div className={styles.sceneBody}>
              <h2>{PRODUCT_STORY_SCENARIO.title}</h2>
              <p>{PRODUCT_STORY_SCENARIO.setup}</p>
              <code className={styles.actionCode}>{PRODUCT_STORY_SCENARIO.action}</code>
              <div className={styles.materialChange}>{PRODUCT_STORY_SCENARIO.materialChange}</div>
              <div className={styles.moment}>
                <span>This chapter</span>
                <strong>{story.storyMoment}</strong>
              </div>
            </div>
          </aside>
        </div>
      </section>
      <div className={styles.boundary}>
        <div className={styles.shell}>
          <strong>Claim boundary: </strong>{story.boundary}
        </div>
      </div>
      <ProductJourney active={story.key} />
    </>
  );
}

export function ProductStoryCallout({ product }: { product: ProductStoryKey }): React.ReactElement {
  const story = getProductStory(product);

  return (
    <section className={styles.chapterCallout} aria-labelledby={`${story.key}-chapter-title`}>
      <div className={`${styles.shell} ${styles.calloutGrid}`}>
        <div>
          <div className={styles.chapter}>{story.chapter} / {story.verb} / illustrative workflow</div>
          <h2 id={`${story.key}-chapter-title`}>{PRODUCT_STORY_SCENARIO.title}</h2>
          <p>{PRODUCT_STORY_SCENARIO.setup}</p>
        </div>
        <div className={styles.calloutMoment}>
          <code className={styles.actionCode}>{PRODUCT_STORY_SCENARIO.action}</code>
          <strong>{story.storyMoment}</strong>
          <span>Illustrative workflow, not a customer claim.</span>
        </div>
      </div>
    </section>
  );
}

export function ProductStoryHub(): React.ReactElement {
  return (
    <>
      <section className={styles.hubHero} aria-labelledby="products-title">
        <div className={styles.shell}>
          <div className={styles.chapter}>The EMILIA product story</div>
          <h1 id="products-title">One consequential action. Five clear jobs.</h1>
          <p>
            EMILIA is not a shelf of unrelated mechanisms. It is one customer-owned path from
            discovering a consequence, to preventing an unauthorized crossing, to preserving a
            record other people can check.
          </p>
          <div className={styles.actions}>
            <Link className={styles.primary} href="/authority-brain">Map my agent</Link>
            <Link className={styles.secondary} href="/pilot">Protect one workflow</Link>
          </div>
        </div>
      </section>

      <ProductJourney />

      <section className={styles.hubScenario} aria-labelledby="scenario-title">
        <div className={`${styles.shell} ${styles.scenarioGrid}`}>
          <div className={styles.scenarioCopy}>
            <div className={styles.chapter}>{PRODUCT_STORY_SCENARIO.label}</div>
            <h2 id="scenario-title">{PRODUCT_STORY_SCENARIO.title}</h2>
            <p>{PRODUCT_STORY_SCENARIO.setup}</p>
            <code className={styles.actionCode}>{PRODUCT_STORY_SCENARIO.action}</code>
            <div className={styles.materialChange}>{PRODUCT_STORY_SCENARIO.materialChange}</div>
          </div>

          <ol className={styles.productStack}>
            {PRODUCT_STORIES.map((story) => (
              <li key={story.key}>
                <Link className={styles.productCard} href={story.href}>
                  <span>{story.chapter}</span>
                  <strong>{story.name}</strong>
                  <em>{story.storyMoment}</em>
                  <span aria-hidden="true">→</span>
                </Link>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className={styles.hubScenario} aria-labelledby="system-jobs-title">
        <div className={styles.shell}>
          <div className={styles.scenarioCopy}>
            <div className={styles.chapter}>One system, five jobs</div>
            <h2 id="system-jobs-title">Each part says one thing it can stand behind.</h2>
          </div>
          <div className={styles.scenarioGrid}>
            {PRODUCT_STORIES.map((story) => (
              <article key={story.key} className={styles.scene}>
                <div className={styles.sceneHeader}><span>{story.chapter} / {story.verb}</span><span>{story.name}</span></div>
                <div className={styles.sceneBody}>
                  <h3>{story.job}</h3>
                  <div className={styles.output}>
                    <span>Customer receives</span>
                    <strong>{story.customerReceives}</strong>
                  </div>
                  <div className={styles.comparison}>
                    <div><span>Without</span><p>{story.withoutEmilia}</p></div>
                    <div><span>With EMILIA</span><p>{story.withEmilia}</p></div>
                  </div>
                  <div className={styles.moment}>
                    <span>What it cannot claim</span>
                    <strong>{story.boundary}</strong>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className={styles.serviceSection} aria-labelledby="services-title">
        <div className={`${styles.shell} ${styles.serviceGrid}`}>
          <div className={styles.scenarioCopy}>
            <div className={styles.chapter}>Procedures and scoped help</div>
            <h2 id="services-title">When the customer needs a defined review, not another product.</h2>
            <p>
              Chapter five is an implemented procedure. A deployment or service engagement must be
              separately scoped. Trust Desk handles scoped evidence intake and one-off technical
              review. Neither turns EMILIA into the customer&apos;s auditor.
            </p>
          </div>
          <div className={styles.serviceLinks}>
            <Link href="/assurance"><strong>Explore the Assurance procedure</strong><span>See implemented verification and re-performance procedures.</span></Link>
            <Link href="/trust-desk"><strong>Trust Desk</strong><span>Prepare scoped technical evidence for a customer-appointed reviewer.</span></Link>
          </div>
        </div>
      </section>
    </>
  );
}
