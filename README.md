# DepGuard Security Engine

A browser-based dependency vulnerability scanner for npm projects. Upload a `package.json`, and DepGuard checks every dependency version against the [Google Open Source Vulnerabilities (OSV) database](https://osv.dev/) and turns the results into an actionable report.

No backend, no API key, no account. Your manifest never leaves your browser — only package names and versions are sent to the public OSV API.

[![CI](https://github.com/Mohammad-Farhan-Shaikh/osv-dependency-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Mohammad-Farhan-Shaikh/osv-dependency-guard/actions/workflows/ci.yml)
![Vue 3](https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)
![Tailwind CSS v4](https://img.shields.io/badge/Tailwind_CSS-v4-06B6D4?logo=tailwindcss&logoColor=white)
![OSV](https://img.shields.io/badge/Security-Google_OSV-4285F4)

## Features

- **Manifest scanning** — drag and drop or pick a `package.json` (JSON only, max 2 MB), or load the built-in demo manifest with known vulnerable packages.
- **Honest results** — failed checks are reported as `Scan failed` and are never counted as clean. The health score is conservative: `clean / total × 100`, so incomplete scans can never look perfect.
- **Resilient OSV client** — bounded concurrency (6 requests), per-request 15 s timeout, automatic retries (2) with `Retry-After` support for 429/5xx responses, and cancellation.
- **Strict parsing** — only versions that can be checked safely are scanned. Unsupported specs (git, URLs, workspaces, tags, complex ranges) are listed explicitly instead of being guessed.
- **Rich results** — severity, aliases, affected version ranges, fixed versions, references and dates per advisory.
- **Search, filter and sort** — free-text search, status filters (all / vulnerable / failed / clean), severity filter and sortable columns.
- **Advisory drawer** — full advisory details with Escape-to-close, focus trapping and focus restoration, plus copy-advisory-ID.
- **Exports** — JSON (full data, schema v1), CSV (Excel-friendly UTF-8 BOM, formula-injection guarded) and a Markdown report for CI evidence or sharing.
- **Accessible UI** — landmarks, skip link, visible focus states, `aria-sort`, live regions, reduced-motion support and WCAG-conscious contrast.

## How It Works

```text
package.json
   │
   ▼
Manifest parser ──► supported dependencies + explicit "unsupported" list
   │
   ▼
OSV API client (concurrency 6, retries, timeout, cancellation)
   │
   ▼
Pinia store (metrics, progress, partial-failure tracking)
   │
   ▼
Dashboard · Results table · Advisory drawer · Exports
```

1. The parser reads `dependencies` and `devDependencies`, validates package names and normalises supported version specs.
2. Each dependency is queried against `https://api.osv.dev/v1/query` with `ecosystem: npm`.
3. Advisories are normalised: severity, fixed versions, affected ranges and references are extracted.
4. The store computes metrics and progress while results stream in.
5. The dashboard renders findings; every export is generated client-side.

### Supported version specs

| Spec | Example | Behaviour |
| --- | --- | --- |
| Exact version | `1.2.3`, `=1.2.3`, `v1.2.3` | Scanned |
| Lower-bound prefixes | `^1.2.3`, `~1.2.3`, `>=1.2.3` | Scanned as the minimum version |
| npm alias | `npm:lodash@4.17.21` | Scanned as the target package |
| Pre-release / build | `1.2.3-rc.1`, `1.2.3+build` | Scanned |

Intentionally **not** scanned (shown in the UI, never treated as clean): git/GitHub shorthand, tarball URLs, `file:`/`link:`/`workspace:` protocols, dist-tags, partial versions (`1.2`, `1.x`), wildcards and complex ranges (`<`, `<=`, `||`, hyphen ranges). Guessing a version would produce false positives or false negatives.

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) `^20.19.0` or `>=22.12.0` (see `.nvmrc`; required by Vite 8)
- npm 10 or later

### Run locally

```bash
git clone https://github.com/Mohammad-Farhan-Shaikh/osv-dependency-guard.git
cd osv-dependency-guard
npm install
npm run dev
```

Open the URL printed by Vite (default `http://localhost:5173`).

### Production build

```bash
npm run build     # type-check + bundle into dist/
npm run preview   # serve dist/ locally
```

## Scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Start the Vite dev server |
| `npm run build` | Type-check with `vue-tsc` and build to `dist/` |
| `npm run preview` | Preview the production build |
| `npm run test` | Run the Vitest suite (138 tests) |
| `npm run lint` | Run ESLint with autofix |
| `npm run lint:check` | Run ESLint without writing changes (used by CI) |
| `npm run format` | Format `src/**/*.{vue,ts,css}` with Prettier |

## Testing

The suite uses Vitest with happy-dom and covers the parser, the OSV client (mocked `fetch`), the store, the exporters and the main components.

```text
src/tests/
├── parser.spec.ts           # 45 tests — manifest parsing, version specs, aliases
├── osvApi.spec.ts           # 33 tests — timeouts, retries, concurrency, malformed responses
├── scannerStore.spec.ts     # 16 tests — metrics, cancellation, retry merging
├── exporters.spec.ts        # 13 tests — JSON/CSV/Markdown, CSV injection guards
└── components/
    ├── VulnerabilityTable.spec.ts   #  9 tests
    ├── AdvisoryDrawer.spec.ts       #  7 tests
    ├── DropzoneUploader.spec.ts     #  7 tests
    ├── ExportToolbar.spec.ts        #  3 tests
    └── App.spec.ts                  #  5 tests
```

## Project Structure

```text
osv-dependency-guard/
├── .github/workflows/ci.yml     # Lint, test and build on Node 22
├── public/favicon.svg
├── src/
│   ├── components/
│   │   ├── common/
│   │   │   ├── MetricCard.vue
│   │   │   └── StatusBadge.vue
│   │   ├── AdvisoryDrawer.vue
│   │   ├── DropzoneUploader.vue
│   │   ├── ExportToolbar.vue
│   │   ├── UnsupportedDependencies.vue
│   │   └── VulnerabilityTable.vue
│   ├── services/osvApi.ts
│   ├── stores/scannerStore.ts
│   ├── tests/
│   ├── types/vulnerability.ts
│   ├── utils/
│   │   ├── download.ts
│   │   ├── exporters.ts
│   │   ├── format.ts
│   │   ├── parser.ts
│   │   └── severity.ts
│   ├── App.vue
│   ├── main.ts
│   └── style.css
├── .nvmrc
├── index.html
├── package.json
├── vite.config.ts
└── tsconfig*.json
```

## Security and Privacy

- The manifest is parsed locally; it is never uploaded or persisted. There is no backend and no database.
- Only package name, version and ecosystem are sent to `https://api.osv.dev`. Nothing else leaves the browser.
- No API keys or secrets are used. The OSV API is public.
- Advisory links open in a new tab with `rel="noopener noreferrer nofollow"`; only `http(s)` URLs are rendered as links.
- CSV exports neutralise spreadsheet formula injection (`=`, `+`, `-`, `@`, tab, CR prefixes).
- Uploads are limited to JSON files up to 2 MB.

**Note:** package names and versions are sent to Google's public OSV API. If your manifest contains private package names, be aware they are visible to that API.

## Deployment

DepGuard is a static single-page app — no server or routing rewrites are required.

> **Status:** not deployed yet. The planned URL is `https://depguard.farhan.si`; treat it as planned until the maintainer announces it live.

Any static host works (Vercel, Netlify, Cloudflare Pages, GitHub Pages, S3 + CDN):

1. Use Node 22 (see `.nvmrc`) with `npm ci`.
2. Build command: `npm run build`.
3. Output directory: `dist`.

Notes:

- For sub-path hosting (e.g. GitHub Pages project sites), set `base` in `vite.config.ts` to the repository path.
- CI (`.github/workflows/ci.yml`) runs lint, tests and build on every push to `main` and on pull requests, so deployment can depend on a green build.

## Limitations

- npm ecosystem only (`package.json`); lockfiles and transitive dependency trees are not resolved.
- Only direct dependencies declared in the uploaded manifest are checked.
- Results reflect the OSV database at scan time; fixed versions appear only when the advisory provides them.
- Complex version ranges are skipped rather than resolved, by design.
- No automatic dependency updates — DepGuard reports, you decide.

## Contributing

Issues and pull requests are welcome. Before opening a PR, run:

```bash
npm run lint:check && npm run test && npm run build
```

## License
This project is licensed under the [MIT License](LICENSE).
