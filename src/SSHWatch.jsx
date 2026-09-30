import React, { useState, useRef, useEffect, useCallback } from "react";
import {
  Play,
  Pause,
  RotateCcw,
  ShieldAlert,
  Activity,
  Globe2,
  KeyRound,
  TerminalSquare,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

// ---- palette ------------------------------------------------------------
const C = {
  bg: "#050805",
  panel: "#0a0f0a",
  panelAlt: "#0d130d",
  border: "#1c2e1c",
  borderBright: "#2c4a2c",
  green: "#3ddc6f",
  greenDim: "#4d7a52",
  greenFaint: "#2f4a33",
  white: "#eaf5ec",
  whiteDim: "#a9bcac",
  amber: "#e8a53d",
  red: "#ff5c5c",
};

const USERS_ATTACK = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "guest", "ftpuser", "deploy", "backup"];
const USERS_LEGIT = ["jmartin", "asmith", "klee", "rpatel", "dcohen"];
const HOST_IPS_LEGIT = ["10.0.4.12", "10.0.4.31", "192.168.1.9", "192.168.1.44"];

const BRUTE_FORCE_THRESHOLD = 5;
const STUFFING_THRESHOLD = 4;
const COMPROMISE_FAILED_MIN = 3;
const MAX_LINES = 140;
const MAX_ALERTS = 40;
const TICK_MS = 730; // fixed pace, between the old "slow" and "normal" presets

function randInt(a, b) {
  return Math.floor(Math.random() * (b - a + 1)) + a;
}
function pick(arr) {
  return arr[randInt(0, arr.length - 1)];
}
function randIP() {
  // avoids private (10/8, 172.16/12, 192.168/16), loopback (127/8) and link-local (169.254/16) ranges
  while (true) {
    const a = randInt(1, 223);
    if (a === 10 || a === 127 || a === 0) continue;
    const b = randInt(0, 255);
    if (a === 172 && b >= 16 && b <= 31) continue;
    if (a === 169 && b === 254) continue;
    if (a === 192 && b === 168) continue;
    return `${a}.${b}.${randInt(0, 255)}.${randInt(1, 254)}`;
  }
}
function pad(n) {
  return String(n).padStart(2, "0");
}
function fmtTime(d) {
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${months[d.getMonth()]} ${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function buildLineText(spec, time, pid) {
  const port = randInt(32768, 60999); // linux ephemeral port range (net.ipv4.ip_local_port_range default)
  const prefix = `${time} host sshd[${pid}]:`;
  if (spec.result === "success") {
    return `${prefix} Accepted password for ${spec.user} from ${spec.ip} port ${port} ssh2`;
  }
  const invalid = USERS_ATTACK.includes(spec.user) && Math.random() < 0.6 ? "invalid user " : "";
  return `${prefix} Failed password for ${invalid}${spec.user} from ${spec.ip} port ${port} ssh2`;
}

export default function SSHWatch() {
  const [lines, setLines] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [running, setRunning] = useState(false);
  const [stats, setStats] = useState({ total: 0, failed: 0, success: 0, ips: 0 });
  const [ipTable, setIpTable] = useState([]); // [{ip, failed, success, users:[...]}]
  const [expanded, setExpanded] = useState(null); // 'total' | 'ips' | 'failed' | 'success' | null

  const queueRef = useRef([]);
  const ipStatsRef = useRef({});
  const alertedRef = useRef(new Set());
  const clockRef = useRef(new Date());
  const idRef = useRef(0);
  const pidRef = useRef(20000);
  const scrollRef = useRef(null);
  const intervalRef = useRef(null);

  const fillQueue = useCallback(() => {
    const r = Math.random();
    const q = [];
    if (r < 0.22) {
      const ip = randIP();
      const count = randInt(6, 12);
      for (let i = 0; i < count; i++) q.push({ ip, user: pick(USERS_ATTACK), result: "failed" });
      if (Math.random() < 0.4) q.push({ ip, user: "root", result: "success" });
    } else if (r < 0.36) {
      const ip = randIP();
      const shuffled = [...USERS_ATTACK].sort(() => Math.random() - 0.5).slice(0, randInt(5, 8));
      shuffled.forEach((u) => q.push({ ip, user: u, result: "failed" }));
    } else if (r < 0.72) {
      q.push({ ip: pick(HOST_IPS_LEGIT), user: pick(USERS_LEGIT), result: "success" });
    } else {
      q.push({ ip: randIP(), user: pick(USERS_ATTACK), result: "failed" });
    }
    queueRef.current.push(...q);
  }, []);

  const tick = useCallback(() => {
    if (queueRef.current.length === 0) fillQueue();
    const spec = queueRef.current.shift();
    if (!spec) return;

    clockRef.current = new Date(clockRef.current.getTime() + randInt(1000, 3200));
    const time = fmtTime(clockRef.current);
    pidRef.current += 1;
    const text = buildLineText(spec, time, pidRef.current);

    const ipMap = ipStatsRef.current;
    if (!ipMap[spec.ip]) ipMap[spec.ip] = { failed: 0, success: 0, users: new Set() };
    const rec = ipMap[spec.ip];
    rec.users.add(spec.user);

    let level = "info";
    let alert = null;

    if (spec.result === "failed") {
      rec.failed += 1;
      if (rec.failed >= BRUTE_FORCE_THRESHOLD) {
        level = "crit";
        if (!alertedRef.current.has(spec.ip + ":bf")) {
          alertedRef.current.add(spec.ip + ":bf");
          alert = { type: "BRUTE FORCE", severity: "crit", message: `${spec.ip} passed ${BRUTE_FORCE_THRESHOLD} failed attempts` };
        }
      } else if (rec.users.size >= STUFFING_THRESHOLD) {
        level = "warn";
        if (!alertedRef.current.has(spec.ip + ":cs")) {
          alertedRef.current.add(spec.ip + ":cs");
          alert = { type: "CREDENTIAL STUFFING", severity: "warn", message: `${spec.ip} tried ${rec.users.size} distinct usernames` };
        }
      }
    } else {
      rec.success += 1;
      if (rec.failed >= COMPROMISE_FAILED_MIN && !alertedRef.current.has(spec.ip + ":comp")) {
        alertedRef.current.add(spec.ip + ":comp");
        level = "crit";
        alert = { type: "POSSIBLE COMPROMISE", severity: "crit", message: `login for ${spec.user} succeeded after ${rec.failed} failures from ${spec.ip}` };
      }
    }

    const lineObj = { id: idRef.current++, text, level };
    setLines((prev) => {
      const next = [...prev, lineObj];
      return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
    });

    const entries = Object.entries(ipMap);
    setStats({
      total: idRef.current,
      failed: entries.reduce((s, [, r2]) => s + r2.failed, 0),
      success: entries.reduce((s, [, r2]) => s + r2.success, 0),
      ips: entries.length,
    });
    setIpTable(
      entries
        .map(([ip, r2]) => ({ ip, failed: r2.failed, success: r2.success, users: Array.from(r2.users) }))
        .sort((a, b) => b.failed + b.success - (a.failed + a.success))
    );

    if (alert) {
      const alertObj = { id: `a${idRef.current}`, time, ip: spec.ip, ...alert };
      setAlerts((prev) => {
        const next = [alertObj, ...prev];
        return next.length > MAX_ALERTS ? next.slice(0, MAX_ALERTS) : next;
      });
    }
  }, [fillQueue]);

  useEffect(() => {
    if (running) intervalRef.current = setInterval(tick, TICK_MS);
    return () => clearInterval(intervalRef.current);
  }, [running, tick]);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [lines]);

  const handleReset = () => {
    setRunning(false);
    clearInterval(intervalRef.current);
    setLines([]);
    setAlerts([]);
    setStats({ total: 0, failed: 0, success: 0, ips: 0 });
    setIpTable([]);
    setExpanded(null);
    queueRef.current = [];
    ipStatsRef.current = {};
    alertedRef.current = new Set();
    idRef.current = 0;
    clockRef.current = new Date();
  };

  const levelColor = (level) => (level === "crit" ? C.red : level === "warn" ? C.amber : C.white);
  const toggle = (key) => setExpanded((e) => (e === key ? null : key));

  return (
    <div
      style={{ background: C.bg, color: C.white, minHeight: "100%", fontFamily: "'JetBrains Mono','Fira Code',ui-monospace,Menlo,monospace" }}
      className="w-full min-h-screen p-4 md:p-8"
    >
      <style>{`
        @keyframes lineIn { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes blink { 0%, 49% { opacity: 1; } 50%, 100% { opacity: 0; } }
        @keyframes glowPulse {
          0% { box-shadow: 0 0 0 rgba(255,92,92,0); }
          30% { box-shadow: 0 0 14px rgba(255,92,92,0.35); }
          100% { box-shadow: 0 0 0 rgba(255,92,92,0); }
        }
        @keyframes panelOpen { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
        .line-in { animation: lineIn 180ms ease-out; }
        .cursor-blink { animation: blink 1s step-start infinite; }
        .alert-in { animation: lineIn 180ms ease-out, glowPulse 1.2s ease-out; }
        .panel-open { animation: panelOpen 150ms ease-out; }
        .scroller::-webkit-scrollbar { width: 8px; }
        .scroller::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 0px; }
        .scroller::-webkit-scrollbar-track { background: transparent; }
      `}</style>

      {/* header */}
      <div className="max-w-6xl mx-auto mb-6">
        <div className="flex items-center gap-3">
          <TerminalSquare size={22} color={C.green} strokeWidth={1.6} />
          <h1 style={{ color: C.white, letterSpacing: "0.02em" }} className="text-xl font-semibold">
            sshwatch
          </h1>
          <span style={{ color: C.greenDim }} className="text-sm font-medium">
            // ssh auth log analyzer &amp; intrusion detection simulator
          </span>
        </div>
        <div style={{ color: C.greenDim, borderTop: `1px solid ${C.border}` }} className="mt-3 pt-2 text-sm font-medium">
          guest@sshwatch:~$ ./sshwatch --watch /var/log/auth.log
        </div>
      </div>

      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* terminal panel */}
        <div className="lg:col-span-2 flex flex-col">
          <div style={{ background: C.panel, border: `1px solid ${C.border}` }} className="flex flex-col h-[520px]">
            <div style={{ borderBottom: `1px solid ${C.border}`, background: C.panelAlt }} className="flex items-center gap-2 px-3 py-2">
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: C.greenFaint, display: "inline-block" }} />
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: C.greenDim, display: "inline-block" }} />
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: C.green, display: "inline-block" }} />
              <span style={{ color: C.greenDim }} className="ml-2 text-sm font-medium">
                root@sshwatch: /var/log/auth.log — tail -f
              </span>
              <span style={{ color: running ? C.green : C.greenFaint }} className="ml-auto flex items-center gap-1 text-sm font-medium">
                <Activity size={13} />
                {running ? "live" : "paused"}
              </span>
            </div>

            <div ref={scrollRef} className="scroller flex-1 overflow-y-auto px-3 py-2 text-[14.5px] leading-[1.65] font-medium">
              {lines.length === 0 && (
                <div style={{ color: C.greenFaint }}>no events yet — press start to begin streaming auth.log</div>
              )}
              {lines.map((l) => (
                <div
                  key={l.id}
                  className="line-in"
                  style={{
                    color: levelColor(l.level),
                    background: l.level === "crit" ? "rgba(255,92,92,0.06)" : l.level === "warn" ? "rgba(232,165,61,0.06)" : "transparent",
                    borderLeft: l.level === "crit" ? `2px solid ${C.red}` : l.level === "warn" ? `2px solid ${C.amber}` : "2px solid transparent",
                    paddingLeft: 8,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                  }}
                >
                  {l.text}
                </div>
              ))}
              {running && (
                <span className="cursor-blink" style={{ color: C.green }}>
                  ▊
                </span>
              )}
            </div>
          </div>
        </div>

        {/* side panel: controls + stats + alerts */}
        <div className="flex flex-col gap-4">
          {/* controls */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setRunning((r) => !r)}
              style={{ background: running ? C.panelAlt : C.green, color: running ? C.green : "#04140a", border: `1px solid ${running ? C.borderBright : C.green}` }}
              className="flex items-center gap-1.5 px-3 py-2 text-sm font-semibold transition-colors"
            >
              {running ? <Pause size={14} /> : <Play size={14} />}
              {running ? "pause" : "start"}
            </button>
            <button
              onClick={handleReset}
              style={{ background: C.panelAlt, color: C.whiteDim, border: `1px solid ${C.border}` }}
              className="flex items-center gap-1.5 px-3 py-2 text-sm font-semibold transition-colors hover:opacity-80"
            >
              <RotateCcw size={14} />
              reset
            </button>
          </div>

          <div style={{ background: C.panel, border: `1px solid ${C.border}` }} className="p-3">
            <div style={{ color: C.greenDim, borderBottom: `1px solid ${C.border}` }} className="text-sm font-medium pb-2 mb-2">
              stats
            </div>

            <div className="grid grid-cols-2 gap-3">
              <StatCard
                label="total_events"
                value={stats.total}
                color={C.white}
                open={expanded === "total"}
                onToggle={() => toggle("total")}
              />
              <StatCard
                label="unique_ips"
                value={stats.ips}
                color={C.white}
                icon={<Globe2 size={11} color={C.greenDim} />}
                open={expanded === "ips"}
                onToggle={() => toggle("ips")}
              />
              <StatCard
                label="failed_logins"
                value={stats.failed}
                color={C.amber}
                open={expanded === "failed"}
                onToggle={() => toggle("failed")}
              />
              <StatCard
                label="success_logins"
                value={stats.success}
                color={C.green}
                icon={<KeyRound size={11} color={C.greenDim} />}
                open={expanded === "success"}
                onToggle={() => toggle("success")}
              />
            </div>

            {expanded && (
              <div
                className="panel-open mt-3 pt-3 text-[13px] font-medium"
                style={{ borderTop: `1px solid ${C.border}` }}
              >
                <DetailPanel kind={expanded} ipTable={ipTable} stats={stats} />
              </div>
            )}
          </div>

          <div style={{ background: C.panel, border: `1px solid ${C.border}` }} className="p-3 flex-1 flex flex-col min-h-[300px]">
            <div style={{ color: C.greenDim, borderBottom: `1px solid ${C.border}` }} className="flex items-center gap-1.5 text-sm font-medium pb-2 mb-2">
              <ShieldAlert size={14} />
              alerts
              <span style={{ color: C.whiteDim, marginLeft: "auto" }}>{alerts.length}</span>
            </div>
            <div className="scroller overflow-y-auto flex-1" style={{ maxHeight: 380 }}>
              {alerts.length === 0 && (
                <div style={{ color: C.greenFaint }} className="text-sm">
                  no alerts raised yet
                </div>
              )}
              {alerts.map((a) => (
                <div
                  key={a.id}
                  className="alert-in mb-2 p-2 text-[13px] font-medium"
                  style={{
                    borderLeft: `2px solid ${a.severity === "crit" ? C.red : C.amber}`,
                    background: a.severity === "crit" ? "rgba(255,92,92,0.05)" : "rgba(232,165,61,0.05)",
                  }}
                >
                  <div className="flex items-center justify-between">
                    <span style={{ color: a.severity === "crit" ? C.red : C.amber, fontWeight: 700 }}>{a.type}</span>
                    <span style={{ color: C.greenDim }}>{a.time}</span>
                  </div>
                  <div style={{ color: C.whiteDim }} className="mt-1">
                    {a.message}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div style={{ color: C.greenDim, borderTop: `1px solid ${C.border}` }} className="max-w-6xl mx-auto mt-6 pt-3 text-sm font-medium">
        simulated data only — no real network traffic is generated or observed.
      </div>
    </div>
  );
}

function StatCard({ label, value, color, icon, open, onToggle }) {
  return (
    <div>
      <div style={{ color: C.greenDim }} className="flex items-center gap-1 text-xs font-medium mb-1">
        {icon}
        {label}
      </div>
      <div className="flex items-center justify-between">
        <span style={{ color }} className="text-2xl font-bold tabular-nums">
          {value}
        </span>
        <button
          onClick={onToggle}
          style={{ color: open ? C.white : C.greenDim, border: `1px solid ${C.border}` }}
          className="flex items-center gap-0.5 px-1.5 py-1 text-[11px] font-semibold transition-colors hover:opacity-80"
        >
          details
          {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </button>
      </div>
    </div>
  );
}

function DetailPanel({ kind, ipTable, stats }) {
  const rowStyle = { borderBottom: `1px solid ${C.border}` };

  if (ipTable.length === 0) {
    return <div style={{ color: C.greenFaint }}>no data yet</div>;
  }

  if (kind === "total") {
    return (
      <div style={{ color: C.whiteDim }}>
        <div className="flex justify-between py-1" style={rowStyle}>
          <span>failed events</span>
          <span style={{ color: C.amber }}>{stats.failed}</span>
        </div>
        <div className="flex justify-between py-1" style={rowStyle}>
          <span>successful events</span>
          <span style={{ color: C.green }}>{stats.success}</span>
        </div>
        <div className="flex justify-between py-1">
          <span>events per ip (avg)</span>
          <span style={{ color: C.white }}>{stats.ips ? (stats.total / stats.ips).toFixed(1) : "0"}</span>
        </div>
      </div>
    );
  }

  if (kind === "ips") {
    return (
      <div className="max-h-48 overflow-y-auto scroller">
        {ipTable.map((r) => (
          <div key={r.ip} className="flex justify-between py-1" style={rowStyle}>
            <span style={{ color: C.white }}>{r.ip}</span>
            <span style={{ color: C.whiteDim }}>
              <span style={{ color: C.amber }}>{r.failed} failed</span> · <span style={{ color: C.green }}>{r.success} ok</span>
            </span>
          </div>
        ))}
      </div>
    );
  }

  if (kind === "failed") {
    const rows = ipTable.filter((r) => r.failed > 0).sort((a, b) => b.failed - a.failed);
    return (
      <div className="max-h-48 overflow-y-auto scroller">
        {rows.length === 0 && <div style={{ color: C.greenFaint }}>no failed attempts yet</div>}
        {rows.map((r) => (
          <div key={r.ip} className="py-1" style={rowStyle}>
            <div className="flex justify-between">
              <span style={{ color: C.white }}>{r.ip}</span>
              <span style={{ color: C.amber }}>{r.failed} failed</span>
            </div>
            <div style={{ color: C.greenDim }} className="text-[12px] font-medium">
              usernames tried: {r.users.join(", ")}
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (kind === "success") {
    const rows = ipTable.filter((r) => r.success > 0).sort((a, b) => b.success - a.success);
    return (
      <div className="max-h-48 overflow-y-auto scroller">
        {rows.length === 0 && <div style={{ color: C.greenFaint }}>no successful logins yet</div>}
        {rows.map((r) => (
          <div key={r.ip} className="flex justify-between py-1" style={rowStyle}>
            <span style={{ color: C.white }}>{r.ip}</span>
            <span style={{ color: C.green }}>
              {r.success} success{r.failed > 0 ? ` (after ${r.failed} failed)` : ""}
            </span>
          </div>
        ))}
      </div>
    );
  }

  return null;
}
