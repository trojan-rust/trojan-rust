/**
 * Surge information panel for a trojan-rust dashboard.
 *
 * Reads `GET /me` with the caller's own credentials and renders the quota, the
 * recent usage and the expiry date into a Surge information panel, which needs
 * Surge iOS 4.9.3+ or Surge Mac 5.7.5+.
 *
 *   [Script]
 *   trojan-panel = type=generic,timeout=10,script-path=https://dash.example.com/surge/panel.js,argument=url=https://dash.example.com&auth=YWxpY2U6czNjcmV0
 *
 *   [Panel]
 *   TrojanPanel = script-name=trojan-panel,update-interval=600
 *
 * Arguments, joined by `&`:
 *
 *   url         dashboard base URL                              (required)
 *   auth        base64 of `username:password`, which a           (required)
 *               subscription template renders as {{ basic_auth }}
 *   nodes       how many per-node totals to list, 0 to hide them (default 2)
 *   lang        `zh` or `en`                     (default: Surge's UI language)
 *   policy      send the request through this policy, e.g. DIRECT
 *   timeout     request timeout in seconds, below the script's   (default 8)
 *   icon        an SF Symbol shown instead of the status style
 *   icon-color  hex colour for that icon
 */

const BAR_CELLS = 10;
const UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];

// Only reached through the `icon` argument: a panel with a `style` gets its
// icon, and its colour, from Surge.
const ICON_COLORS = { good: "#34C759", alert: "#FF9500", error: "#FF3B30" };

const LOCALES = {
  en: {
    remaining: (left) => `${left} left`,
    used: (used) => `${used} used`,
    quota: (used, limit) => `Used ${used} / ${limit}`,
    unmetered: (used) => `Used ${used} · unmetered`,
    recent: (day, month) => `24h ${day} · month ${month}`,
    expiry: (date, days) => `Expires ${date} · ${days} d left`,
    perpetual: "No expiry",
    expired: "Expired",
    disabled: "Account disabled",
    nodes: (list) => `All-time ${list}`,
    unconfigured: "Set the url and auth arguments",
    unauthorized: "Wrong username or password",
    unreachable: (detail) => `Dashboard unreachable · ${detail}`,
  },
  zh: {
    remaining: (left) => `剩 ${left}`,
    used: (used) => `已用 ${used}`,
    quota: (used, limit) => `已用 ${used} / ${limit}`,
    unmetered: (used) => `已用 ${used} · 不限量`,
    recent: (day, month) => `24 小时 ${day} · 本月 ${month}`,
    expiry: (date, days) => `${date} 到期 · 剩 ${days} 天`,
    perpetual: "长期有效",
    expired: "已过期",
    disabled: "账号已停用",
    nodes: (list) => `累计 ${list}`,
    unconfigured: "请配置 url 与 auth 参数",
    unauthorized: "用户名或密码错误",
    unreachable: (detail) => `面板连接失败 · ${detail}`,
  },
};

const ARGS = parseArgs(typeof $argument === "string" ? $argument : "");
const L = LOCALES[language()] || LOCALES.en;

main();

function main() {
  if (!ARGS.url || !ARGS.auth) {
    return panel("Trojan", [L.unconfigured], "error");
  }

  const request = {
    url: `${ARGS.url.replace(/\/+$/, "")}/me`,
    headers: { Authorization: `Basic ${ARGS.auth}` },
    timeout: Number(ARGS.timeout) || 8,
  };
  // Worth setting to DIRECT: a panel that only renders while the proxy works
  // is blank exactly when its numbers matter.
  if (ARGS.policy) request.policy = ARGS.policy;

  $httpClient.get(request, (error, response, data) => {
    if (error) {
      return panel("Trojan", [L.unreachable(String(error))], "error");
    }
    if (response.status === 401) {
      return panel("Trojan", [L.unauthorized], "error");
    }
    if (response.status !== 200) {
      return panel("Trojan", [L.unreachable(`HTTP ${response.status}`)], "error");
    }
    // A reverse proxy in front of the dashboard can answer 200 with something
    // that is not the API; the panel says so rather than keeping stale numbers.
    let me;
    try {
      me = JSON.parse(data);
    } catch {
      return panel("Trojan", [L.unreachable("bad response")], "error");
    }
    render(me);
  });
}

/** Turn a `/me` response into the panel. */
function render(me) {
  const user = me.user || {};
  const limit = Number(user.traffic_limit) || 0;
  const used = Number(user.traffic_used) || 0;
  const expiresAt = Number(user.expires_at) || 0;
  // An account with no expiry never runs out of days.
  const daysLeft = expiresAt
    ? Math.ceil((expiresAt * 1000 - Date.now()) / 86400000)
    : Infinity;

  const lines = [];
  if (limit) {
    lines.push(bar(Math.min(1, used / limit)));
    lines.push(L.quota(bytes(used), bytes(limit)));
  } else {
    lines.push(L.unmetered(bytes(used)));
  }
  lines.push(L.recent(bytes(me.last_24h_bytes), bytes(me.month_bytes)));
  lines.push(
    !expiresAt
      ? L.perpetual
      : daysLeft > 0
        ? L.expiry(date(expiresAt), daysLeft)
        : L.expired,
  );

  const byNode = nodes(me.traffic_by_node);
  if (byNode) {
    lines.push(L.nodes(byNode));
  }

  let level = "good";
  if (user.enabled === false) {
    lines.unshift(L.disabled);
    level = "error";
  } else if ((limit && used >= limit) || daysLeft <= 0) {
    level = "error";
  } else if (daysLeft <= 3 || (limit && (limit - used) / limit <= 0.1)) {
    level = "alert";
  }

  const headline = limit
    ? L.remaining(bytes(Math.max(0, limit - used)))
    : L.used(bytes(used));
  panel(`${user.username || "Trojan"} · ${headline}`, lines, level);
}

/** Hand the result to Surge, which caches it until the next refresh. */
function panel(title, lines, level) {
  const result = { title, content: lines.join("\n") };
  if (ARGS.icon) {
    result.icon = ARGS.icon;
    result["icon-color"] = ARGS["icon-color"] || ICON_COLORS[level];
  } else {
    result.style = level;
  }
  $done(result);
}

/** `nodes=0` hides the line; the API already orders by descending total. */
function nodes(rows) {
  const count = ARGS.nodes === undefined ? 2 : Number(ARGS.nodes) || 0;
  if (!count || !Array.isArray(rows)) {
    return "";
  }
  return rows
    .slice(0, count)
    .map((row) => `${row.node_name} ${bytes(row.total_bytes)}`)
    .join(" · ");
}

function bar(ratio) {
  const filled = Math.round(ratio * BAR_CELLS);
  const percent = (ratio * 100).toFixed(1);
  return `${"▓".repeat(filled)}${"░".repeat(BAR_CELLS - filled)} ${percent}%`;
}

function bytes(value) {
  let n = Number(value) || 0;
  let unit = 0;
  while (n >= 1024 && unit < UNITS.length - 1) {
    n /= 1024;
    unit += 1;
  }
  // One decimal everywhere it fits: a panel line is read at a glance, and
  // 3.2 GB next to 41.0 GB compares better than 3.20 GB does.
  const digits = unit === 0 || n >= 100 ? 0 : 1;
  return `${n.toFixed(digits)} ${UNITS[unit]}`;
}

/** The expiry date in the device's own timezone, which is how it reads it. */
function date(seconds) {
  const at = new Date(seconds * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`;
}

function language() {
  const lang = ARGS.lang || ($environment && $environment.language) || "en";
  return lang.toLowerCase().startsWith("zh") ? "zh" : "en";
}

/** `key=value` pairs joined by `&`, the convention Surge modules use. */
function parseArgs(raw) {
  const args = {};
  for (const pair of raw.split("&")) {
    const at = pair.indexOf("=");
    if (at > 0) {
      args[pair.slice(0, at)] = decodeURIComponent(pair.slice(at + 1));
    }
  }
  return args;
}
