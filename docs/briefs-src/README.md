# EU brief sources

The PDFs in `public/briefs/` are generated artifacts. Rebuild the HTML-backed
briefs from the repository root with:

```sh
node scripts/render-pdf.mjs \
  docs/briefs-src/emilia-declaration-to-proof.html \
  public/briefs/emilia-declaration-to-proof.pdf

node scripts/render-pdf.mjs \
  docs/briefs-src/emilia-article-14-proof-vs-measurement.html \
  public/briefs/emilia-article-14-proof-vs-measurement.pdf

node scripts/render-pdf.mjs \
  docs/briefs-src/emilia-jtc21-human-oversight-contribution.html \
  public/briefs/emilia-jtc21-human-oversight-contribution.pdf

node scripts/render-pdf.mjs \
  docs/briefs-src/emilia-eu-ai-oversight-onepager.html \
  public/briefs/emilia-eu-ai-oversight-onepager.pdf
```

The Article 14 checklist is Markdown-backed:

```sh
pandoc docs/ART14-EVIDENCE-CHECKLIST.md \
  --standalone \
  --embed-resources \
  --css docs/briefs-src/eu-checklist-print.css \
  --metadata pagetitle='EU AI Act Article 14 Human-Oversight Evidence Checklist' \
  -o /tmp/emilia-article14-evidence-checklist.html

node scripts/render-pdf.mjs \
  /tmp/emilia-article14-evidence-checklist.html \
  public/briefs/emilia-article14-evidence-checklist.pdf
```

After rebuilding, render every PDF page to an image and inspect it before
committing. Generation success alone does not catch clipping or overflow.
