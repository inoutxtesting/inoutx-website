# INOUTX EmailJS and Render Setup

## EmailJS setup

1. Create an account at [EmailJS](https://www.emailjs.com/) and add an Email Service connected to the Gmail account that should receive website enquiries.
2. Create an Email Template for the team notification. Set its recipient to the INOUTX inbox, set Reply-To to `{{email}}`, and use these template variables in the subject/body:
   - `{{name}}`
   - `{{email}}`
   - `{{subject}}`
   - `{{message}}`
3. Copy the Service ID, Template ID, and Public Key from EmailJS. The form sends the values under the exact names above. The page reports success only after EmailJS resolves the send request.
4. Optionally configure an EmailJS auto-reply if you need to retain a visitor confirmation email. The form's success message does not claim that a separate confirmation was sent.

The browser integration requires these values:

```dotenv
VITE_EMAILJS_SERVICE_ID=your_service_id
VITE_EMAILJS_TEMPLATE_ID=your_template_id
VITE_EMAILJS_PUBLIC_KEY=your_public_key
```

Vite embeds `VITE_` values into public browser assets. The EmailJS public key is intended for browser use; never put an EmailJS private key, Gmail password, or other secret in these variables or frontend code. `.env` and `.env.*` files are ignored by Git; `.env.example` contains placeholders only.

In EmailJS account security settings, restrict allowed origins to the exact production site domain(s) and local development origin(s) you use. Review the current plan's monthly send quota and usage dashboard before launch; the free plan has a finite quota and submissions stop working when limits are reached. Keep the form's honeypot and field validation, and enable EmailJS-supported CAPTCHA/abuse controls in the dashboard if available for your account. An exposed public key is not a secret, so origin restrictions and provider-side limits matter.

## Local development

From the repository root:

```powershell
npm install
npm run dev
```

Vite serves the site at the local URL it prints. Put the three EmailJS variables in `.env.local` before testing the contact form. This keeps them separate from an existing `.env` containing unrelated local settings. The provided `.env.example` is a reference template; do not replace an existing `.env` with it.

Create a production build with:

```powershell
npm run build
```

The generated static site is in `dist/`. Preview that build locally with `npm run preview`.

## Render Free Static Site

Create a **Static Site** from this repository with:

- Build command: `npm install && npm run build`
- Publish directory: `dist`

Add the following three variables in the Render service's Environment settings before its first build:

- `VITE_EMAILJS_SERVICE_ID`
- `VITE_EMAILJS_TEMPLATE_ID`
- `VITE_EMAILJS_PUBLIC_KEY`

Render must build again after any of these values change because Vite substitutes them during build. Trigger a new deploy after editing them.

This static deployment hosts the website and EmailJS-powered contact form without a Flask server. It does not host Flask APIs or any separately running INOUTX application/backend. `app.py` remains available for its Flask health check and legacy local static serving; it is not part of the Render Static Site deployment. The old `/api/contact` URL returns `410 Gone` and is no longer called by the page.

## Test an actual email

Add valid EmailJS values locally or in Render, confirm the EmailJS service is connected and the template uses all four parameter names, then submit the form with a real reply-capable email address. Verify the team notification arrives and that Reply-To points to the submitted email. A successful local build alone does not test delivery; actual delivery requires valid EmailJS configuration and a submission within the account's available quota.