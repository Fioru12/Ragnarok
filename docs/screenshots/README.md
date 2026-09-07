# Screenshot capture guide

This guide walks you through capturing the four key screenshots for the Ragnarök README.

## Prerequisites

1. **Build and run the app**:
   ```bash
   cd C:\Progetti\Asgard\Ragnarok
   npm run tauri dev
   ```
   The app opens the Tauri desktop shell (it auto-starts the Python backend).

2. **Prepare demo data** (optional but recommended for realism):
   - Run a Heimdall scan so alerts exist
   - Run a Bifrost network scan so the timeline populates
   - Let RAG auto-index once (you'll see "RAG Engine attivo" in the backend console)

3. **Login**: Use the admin account created during setup (or the default admin from first boot — password was printed to the backend console).

---

## The four screenshots

### 1. Command center overview

**File**: `docs/screenshots/overview.png`

**What to capture**: The main app window, "Overview" tab, with:
- Module health indicators (green dots = modules detected)
- Telemetry chart showing activity
- Incident timeline visible at the bottom

**How**:
1. Open the app
2. Click "Overview" in the sidebar
3. Wait 2-3 seconds for the telemetry chart to render
4. Capture the full window (Print Screen, or `Win+Shift+S` for area capture)

---

### 2. AI assistant with action proposal

**File**: `docs/screenshots/ai-assistant.png`

**What to capture**: The chat interface with an AI-proposed action and the confirmation prompt visible.

**How**:
1. Open the app → "AI Assistant" tab
2. Type: *"Show me recent security alerts"*
3. Wait for the AI to respond with a context block and a proposed action
4. Capture the chat area showing the AI response + the **confirmation button** (this proves the human-in-the-loop design)

---

### 3. RAG dashboard with KPIs

**File**: `docs/screenshots/rag-dashboard.png`

**What to capture**: The `/dashboard` page in a regular browser (larger view than Tauri):
- KPI cards (alerts indexed, uptime, etc.)
- Security score gauge
- Incident timeline with dots

**How**:
1. Open `http://localhost:8000/dashboard` in Chrome/Edge
2. Wait for KPIs to load (they auto-refresh)
3. If you see the "Setup Wizard" instead: the admin hasn't been claimed yet. Complete the wizard first, then login as admin
4. Capture the full page (or the top portion with KPIs + score)

---

### 4. RBAC account UI

**File**: `docs/screenshots/rbac-account.png`

**What to capture**: The sidebar showing the logged-in admin badge and (optionally) the login form for contrast.

**How**:
1. Open the app → scroll to the bottom of the sidebar
2. You should see the **account block** with:
   - Green badge: `admin (admin)` 
   - "Esci" (logout) button
3. For a second capture: logout to show the login form with username/password fields

---

## Adding the images to the README

Once captured:

1. Save each image as the filename listed above in `docs/screenshots/`
2. Uncomment the HTML block in the README (around line 28) by removing `<!--` and `-->`
3. Commit:
   ```bash
   git add docs/screenshots README.md
   git commit -m "docs: add product screenshots"
   ```

The README already has the table and image grid ready — once the files exist, uncomment the HTML block.

---

## Quick checklist

- [ ] Overview tab with green module dots
- [ ] AI assistant with confirmation prompt
- [ ] RAG dashboard with KPIs populated
- [ ] RBAC account badge visible (admin)
- [ ] All files named correctly in `docs/screenshots/`
- [ ] HTML block uncommented in README
- [ ] Images render correctly on GitHub (push and verify)
