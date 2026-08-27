# 🍥 HieuuPenguin Blog

![Node.js >= 20](https://img.shields.io/badge/node.js-%3E%3D20-brightgreen)
![npm >= 9](https://img.shields.io/badge/npm-%3E%3D9-blue)
![Astro 6](https://img.shields.io/badge/Astro-6.x-BC52EE?logo=astro)
![Tailwind CSS 4](https://img.shields.io/badge/Tailwind_CSS-4.x-06B6D4?logo=tailwindcss)

A static CVE and CTF writeup blog built with [Astro](https://astro.build), based on [santisify/astro-theme-sify](https://github.com/santisify/astro-theme-sify).

[**🖥️ Original Theme Demo**](https://astro-theme-sify-demo.vercel.app/)
/
[**📦 Source Theme**](https://github.com/santisify/astro-theme-sify)

## ✨ Features

- [x] Built with [Astro](https://astro.build) and [Tailwind CSS](https://tailwindcss.com)
- [x] Markdown and MDX writeups
- [x] CVE and CTF category pages
- [x] Tag pages for filtering writeups
- [x] Full-site search index
- [x] Code highlighting with [Shiki](https://shiki.style)
- [x] Math rendering with [KaTeX](https://katex.org)
- [x] Light / dark mode
- [x] Responsive layout
- [x] GitHub Pages deployment workflow

## 🚀 Getting Started

1. Clone this repository:

   ```sh
   git clone <your-repo-url>
   cd <your-repo-name>
   ```

2. Install dependencies:

   ```sh
   npm install
   ```

3. Edit the site configuration:

   - `src/consts.ts` for title, description, author, avatar, navigation, and social links.
   - `astro.config.ts` for the final public `site` URL before deployment.

4. Create or edit posts in `src/content/blog/`.

5. Run the site locally:

   ```sh
   npm run dev
   ```

6. Deploy to GitHub Pages by pushing to the `main` branch. The workflow in `.github/workflows/deploy.yml` will build and deploy the site.

## 📝 Frontmatter of Posts

```yaml
---
title: "My First Blog Post"
description: "This is the first post of my new Astro blog."
date: 2026-05-17
updated: 2026-05-18
tags: [Foo, Bar]
category: "Front-end"
cover: ./cover.png
pinned: false
draft: false
---
```

Supported fields:

| Field | Type | Required | Description |
|:------|:-----|:---------|:------------|
| `title` | `string` | Yes | Post title |
| `description` | `string` | No | Short summary shown in post lists |
| `date` | `date` | No | Publish date |
| `updated` | `date` | No | Last update date |
| `tags` | `string[]` | No | Tags used by tag pages |
| `category` | `string` | No | Category used by category pages |
| `cover` | `string` | No | Local relative image path or remote URL |
| `pinned` | `boolean` | No | Marks a post as pinned |
| `draft` | `boolean` | No | Excludes a draft post from normal publishing |

Recommended post structure:

```text
src/content/blog/
`-- Ex Blog Post/
    |-- index.md
    |-- cover.png
```

Images can be referenced from the same post folder:

```md
![Challenge screenshot](./image.png)
```

## 🧩 Markdown Features

In addition to Astro's default Markdown support, this blog includes:

- Markdown and MDX posts
- Local images next to each post
- Syntax-highlighted code blocks
- Inline and block math through KaTeX
- Generated table of contents in post pages

Example math syntax:

```md
Inline math: $E = mc^2$

Block math:

$$
\int_{-\infty}^{\infty} e^{-x^2} dx = \sqrt{\pi}
$$
```

## ⚡ Commands

All commands are run from the root of the project:

| Command | Action |
|:--------|:-------|
| `npm install` | Install dependencies |
| `npm run dev` | Start the local dev server at `localhost:4321` |
| `npm run build` | Build the production site to `./dist/` |
| `npm run preview` | Preview the production build locally |

## 🌐 Deployment

This repository is ready for GitHub Pages deployment.

1. Make sure `astro.config.ts` uses the correct public URL:

   ```ts
   export default defineConfig({
     site: 'https://your-username.github.io',
   });
   ```

2. Push the repository to GitHub.

3. In **Settings -> Pages**, set the build and deployment source to **GitHub Actions**.

4. Push to `main` and wait for the deploy workflow to finish.

For a personal GitHub Pages site, the repository name should normally be:

```text
your-username.github.io
```

## 📁 Project Structure

```text
.
|-- .github/workflows/      # GitHub Pages workflow
|-- public/                 # Static assets
|-- src/
|   |-- components/         # Astro components
|   |-- content/blog/       # Published posts
|   |-- layouts/            # Page layouts
|   |-- pages/              # Routes
|   |-- styles/             # Global styles
|   `-- utils/              # Utilities
|-- astro.config.ts         # Astro configuration
|-- package.json            # Project scripts and dependencies
`-- src/consts.ts           # Site metadata and navigation
```

## ✏️ Credits

This blog is customized from [santisify/astro-theme-sify](https://github.com/santisify/astro-theme-sify).

## 📄 License

This project follows the license declared in `package.json`.
