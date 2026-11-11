# OSV Dependency Guard

A browser-based dependency security scanner for JavaScript and TypeScript projects. **OSV Dependency Guard** checks project dependencies against the [Google Open Source Vulnerabilities (OSV) database](https://osv.dev/) and helps developers identify packages with known security vulnerabilities.

Upload a `package.json` file, run a scan, and review the results in one place. No API key or backend setup is required.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Vue](https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-Strict-3178C6?logo=typescript&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-v4-06B6D4?logo=tailwindcss&logoColor=white)
![OSV](https://img.shields.io/badge/Security-Google_OSV-4285F4)

---

## Overview

Project dependencies can introduce security risks, especially when packages contain known vulnerabilities that go unnoticed.

OSV Dependency Guard makes it easier to review those risks. It reads dependencies from a `package.json` file, checks their versions against the OSV database, and displays the results in a dashboard.

The scanner runs in the browser and communicates directly with the public OSV API. Project source code and complete project files are not uploaded to a separate application backend.

## 🌐 Live Demo

**[Visit DepGuard Security Engine](https://depguard.farhan.si)**

Try the application live and scan your project's dependencies for known security vulnerabilities using the Google OSV API.

## Features

- **Package.json Scanner:** Upload a local `package.json` file using drag and drop or the file picker.
- **Dependency Analysis:** Extracts packages from both `dependencies` and `devDependencies`.
- **Version Normalization:** Handles common version prefixes such as `^`, `~`, `>`, `=` and other range characters.
- **OSV API Integration:** Checks package versions against Google's public vulnerability database.
- **Parallel Scanning:** Sends multiple vulnerability queries concurrently using `Promise.all()`.
- **Vulnerability Detection:** Identifies packages with reported security advisories.
- **Advisory Details:** Displays vulnerability IDs, summaries, descriptions, aliases and severity information when available.
- **Fix Recommendations:** Shows available fixed versions from vulnerability records.
- **Scan Dashboard:** Provides an overview of scanned, vulnerable and clean packages.
- **Package Filtering:** Filter results to view all packages, vulnerable packages or clean packages.
- **Demo Scan:** Load a sample manifest containing known vulnerable package versions to test the application.

## How It Works

The scanner follows a simple workflow:

```text
        package.json
             |
             v
       Manifest Parser
             |
             v
    Dependency Extraction
             |
             v
    Version Normalization
             |
             v
       Pinia Store
             |
             v
     Parallel API Requests
             |
             v
       Google OSV API
             |
             v
    Vulnerability Analysis
             |
             v
        Dashboard
```

1. The user uploads a `package.json` file or loads the demo manifest.
2. The parser reads dependencies and development dependencies.
3. Package versions are normalized before scanning.
4. The Pinia store manages the scanning process.
5. Each dependency is checked against the OSV API.
6. The returned advisories are processed and stored.
7. Results are displayed in the dashboard with vulnerability details and available fixes.

## Tech Stack

| Technology | Purpose |
|---|---|
| Vue 3 | Frontend framework |
| TypeScript | Type safety |
| Pinia | State management |
| Tailwind CSS v4 | Styling |
| Lucide Vue Next | Icons |
| Vite | Development and build tool |
| Vitest | Unit testing |
| Happy DOM | Test environment |
| ESLint | Code quality |
| Prettier | Code formatting |

## Project Structure

```text
osv-dependency-guard/
│
├── src/
│   ├── components/
│   │   ├── common/
│   │   │   ├── MetricCard.vue
│   │   │   └── StatusBadge.vue
│   │   │
│   │   ├── AdvisoryDrawer.vue
│   │   ├── DropzoneUploader.vue
│   │   └── VulnerabilityTable.vue
│   │
│   ├── services/
│   │   └── osvApi.ts
│   │
│   ├── stores/
│   │   └── scannerStore.ts
│   │
│   ├── tests/
│   │   └── parser.spec.ts
│   │
│   ├── types/
│   │   └── vulnerability.ts
│   │
│   ├── utils/
│   │   └── parser.ts
│   │
│   ├── App.vue
│   ├── main.ts
│   └── style.css
│
├── index.html
├── eslint.config.js
├── vite.config.ts
├── tsconfig.json
├── tsconfig.app.json
├── tsconfig.node.json
├── package.json
└── .gitignore
```

### Main Modules

| File | Description |
|---|---|
| `App.vue` | Main application layout and dashboard |
| `DropzoneUploader.vue` | Handles package uploads and demo scanning |
| `VulnerabilityTable.vue` | Displays and filters scan results |
| `MetricCard.vue` | Displays scanning statistics |
| `AdvisoryDrawer.vue` | Shows detailed vulnerability information |
| `osvApi.ts` | Handles requests to the OSV API |
| `scannerStore.ts` | Manages scanning state and results using Pinia |
| `parser.ts` | Parses package manifests and normalizes versions |
| `vulnerability.ts` | Contains TypeScript interfaces for scanner data |
| `parser.spec.ts` | Tests dependency parsing and version handling |

## Getting Started

### Prerequisites

Make sure you have these installed:

- [Node.js](https://nodejs.org/) (18 or later)
- npm (9 or later)
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/Mohammad-Farhan-Shaikh/osv-dependency-guard.git
```

### 2. Navigate to the Project

```bash
cd osv-dependency-guard
```

### 3. Install Dependencies

```bash
npm install
```

### 4. Start the Development Server

```bash
npm run dev
```

Open the local URL displayed in your terminal. By default, Vite uses:

```text
http://localhost:5173
```

## Available Scripts

| Command | Description |
|---|---|
| `npm run dev` | Starts the development server |
| `npm run build` | Runs TypeScript checks and creates a production build |
| `npm run preview` | Previews the production build |
| `npm run test` | Runs unit tests using Vitest |
| `npm run lint` | Runs ESLint on the source directory |
| `npm run format` | Formats Vue, TypeScript and CSS files |

## Using the Application

1. Open the application in your browser.
2. Drag and drop a `package.json` file into the upload area, or select one manually.
3. If you don't have a manifest ready, click **Load demo vulnerable manifest**.
4. Wait for the scanner to finish checking dependencies.
5. Review the scanning metrics and package status.
6. Use the filters to view all, vulnerable or clean packages.
7. Click **Inspect** on a vulnerable package to open its advisory details.

## Security and Privacy

Privacy is an important part of how this application works.

- Package manifest parsing happens directly in the browser.
- There is no application backend or API key requirement.
- Only package names, versions and ecosystem information needed for vulnerability checks are sent to the OSV API.
- Project source code and complete project files are not uploaded to the OSV service.

**Note:** Package names and version information are sent to Google's public OSV API. Keep this in mind when scanning manifests containing private package names.

## Current Limitations

- Currently supports JavaScript and TypeScript dependency manifests through `package.json`.
- Version normalization handles common range characters but is not a complete semantic version range resolver.
- Vulnerability results depend on the advisories available in the OSV database.
- Fixed versions are displayed only when provided by the returned advisory.
- API request failures are tracked as errors.
- The scanner identifies vulnerabilities but does not automatically update dependencies.

## Future Improvements

Some features planned for future versions:

- [ ] Support Python dependencies through `requirements.txt`.
- [ ] Export an updated `package.json` with suggested dependency fixes.
- [ ] Add CVSS-based severity scoring.
- [ ] Improve vulnerability filtering and sorting.
- [ ] Add local result caching using IndexedDB.
- [ ] Introduce scan history.
- [ ] Improve semantic version range handling.
- [ ] Add better handling and reporting of API failures.

## Contributing

Suggestions, bug reports and contributions are welcome.

If you find an issue or have an idea for improving the project, feel free to open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

---

**Built with Vue 3, TypeScript and Google OSV.**