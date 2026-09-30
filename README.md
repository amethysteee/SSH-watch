# sshwatch

A terminal-styled SSH authentication log analyzer and intrusion detection **simulator**. It streams synthetic `sshd` auth log events into a fake terminal and flags suspicious patterns in real time — no real logs, no real network traffic, no real risk. Built as a learning project to practice the kind of pattern recognition a SOC analyst applies to `/var/log/auth.log`.

## What it does

- Generates realistic-looking SSH log lines (`Accepted password for ...`, `Failed password for invalid user ...`) from a mix of simulated legitimate users and simulated attackers.
- Streams them into a terminal-style feed, one line at a time.
- Applies three detection rules live, as each line arrives.
- Surfaces flagged events as color-coded alerts alongside running stats, each with an expandable detail view.

## Detection rules

| Rule | Trigger | Severity |
|---|---|---|
| **Brute force** | 5 or more failed login attempts from the same source IP | Critical |
| **Credential stuffing** | 4 or more *distinct usernames* attempted from the same source IP | Warning |
| **Possible compromise** | A successful login from an IP that already has 3+ recorded failures | Critical |

These thresholds are intentionally simple and tunable (see `BRUTE_FORCE_THRESHOLD`, `STUFFING_THRESHOLD`, and `COMPROMISE_FAILED_MIN` at the top of `sshwatch.jsx`) — they mirror the kind of naive, count-based heuristics real fail2ban-style tools start with, before adding time windows, allow-lists, and geo-context.

## Running it

This is a ready-to-run Vite + React + Tailwind project.

**Local dev:**
```bash
npm install
npm run dev
```
Then open the printed `localhost` URL.

**Deploying:**
 Works out of the box on Vercel, Netlify, or any static host that builds Vite projects — no config needed. No backend, no API keys, no external calls — everything runs client-side with Math.random()-generated events.

### Project structure
```
sshwatch/
├── index.html
├── package.json
├── vite.config.js
├── tailwind.config.js
├── postcss.config.js
└── src/
    ├── main.jsx        # React entry point
    ├── index.css       # Tailwind directives
    └── SSHWatch.jsx    # the actual simulator component
```

## Why this project

Log analysis is one of the first real tasks a junior security analyst does: staring at auth logs, spotting the difference between a user who fat-fingered their password twice and an attacker spraying credentials. This project is a self-contained way to practice thinking in those terms — what pattern indicates what kind of attack, and what threshold turns "noisy but normal" into "worth an alert."

## Possible extensions

- Time-windowed detection (e.g. "5 failures in 60 seconds") instead of cumulative counts
- IP allow-listing / geo-lookup to reduce false positives from known-good ranges
- Export flagged events as a report
- A "replay" mode that ingests a real (sanitized) `auth.log` file instead of generating synthetic data

## Disclaimer

All log data is synthetically generated for demonstration purposes. This tool does not monitor, capture, or analyze any real system, network, or account activity.
