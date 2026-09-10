const decodeB64Url = (str) => {
  try {
    let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4;
    if (pad) b64 += "=".repeat(4 - pad);
    return new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
  } catch {
    return null;
  }
};

const I18N = {
  en: {
    title_verifying: "Verifying...",
    title_redirecting: "Redirecting...",
    title_done: "Done",
    title_failed: "Failed",
    initializing: "Initializing...",
    connection_retry: "Connection error. Retrying in {ms}ms...",
    request_failed: "Request Failed",
    bad_ticket: "Bad Ticket",
    turnstile_load_failed: "Turnstile Load Failed",
    loading_turnstile: "Loading Turnstile...",
    turnstile_missing: "Turnstile Missing",
    waiting_turnstile: "Waiting for Turnstile...",
    turnstile_expired_retry: "Turnstile expired. Retrying...",
    submitting_turnstile: "Submitting Turnstile...",
    submitting_turnstile_done: "Submitting Turnstile... {done}",
    turnstile_done: "Turnstile... {done}",
    turnstile_rejected_retry: "Turnstile rejected. Please try again.",
    turnstile_rejected: "Turnstile Rejected",
    turnstile_failed: "Turnstile Failed",
    turnstile_expired: "Turnstile Expired",
    loading_solver: "Loading solver...",
    worker_missing: "Worker Missing",
    solver_missing: "Solver Missing",
    bad_binding: "Bad Binding",
    challenge_failed: "Challenge Failed",
    challenge_timeout: "Challenge Timeout",
    verifying_done: "Verifying... {done}",
    pow_done: "PoW... {done}",
    no_challenge: "No Challenge",
    consume_missing: "Consume Missing",
    no_workers: "No workers",
    worker_error: "Worker error",
    worker_message_error: "Worker message error",
    solving_equihash_progress: "Solving Equihash ({elapsed}s elapsed, {remaining}s left, rows {rows}, solve {ewmaSolveMs}ms)...",
    solving_equihash_done: "Solving Equihash... {done}",
    access_granted_close: "Access granted. You may close this window.",
    access_granted_redirecting: "Access granted. {redirect}",
    session_expired_reload: "Session expired. Reloading...",
    error_prefix: "ERROR: {message}",
    done: "done",
    redirecting: "Redirecting...",
    failed: "Failed",
  },
  zh: {
    title_verifying: "验证中...",
    title_redirecting: "正在跳转...",
    title_done: "完成",
    title_failed: "失败",
    initializing: "初始化中...",
    connection_retry: "连接错误，{ms}ms 后重试...",
    request_failed: "请求失败",
    bad_ticket: "票据无效",
    turnstile_load_failed: "Turnstile 加载失败",
    loading_turnstile: "加载 Turnstile...",
    turnstile_missing: "Turnstile 不可用",
    waiting_turnstile: "等待 Turnstile...",
    turnstile_expired_retry: "Turnstile 已过期，正在重试...",
    submitting_turnstile: "提交 Turnstile...",
    submitting_turnstile_done: "提交 Turnstile... {done}",
    turnstile_done: "Turnstile... {done}",
    turnstile_rejected_retry: "Turnstile 被拒绝，请重试。",
    turnstile_rejected: "Turnstile 被拒绝",
    turnstile_failed: "Turnstile 失败",
    turnstile_expired: "Turnstile 已过期",
    loading_solver: "加载求解器...",
    worker_missing: "Worker 不可用",
    solver_missing: "求解器不可用",
    bad_binding: "绑定无效",
    challenge_failed: "挑战失败",
    challenge_timeout: "挑战超时",
    solving_equihash_progress: "Equihash 求解（已用 {elapsed}s，剩余 {remaining}s，rows {rows}，求解 {ewmaSolveMs}ms）...",
    solving_equihash_done: "Equihash 求解... {done}",
    pow_done: "PoW... {done}",
    no_challenge: "没有挑战",
    consume_missing: "缺少 consume",
    no_workers: "没有可用的 worker",
    worker_error: "Worker 错误",
    worker_message_error: "Worker 消息错误",
    access_granted_close: "已通过验证，可关闭此窗口。",
    access_granted_redirecting: "已通过验证。{redirect}",
    session_expired_reload: "会话已过期，正在刷新...",
    error_prefix: "错误：{message}",
    done: "完成",
    redirecting: "正在跳转...",
    failed: "失败",
  },
  ja: {
    title_verifying: "確認中...",
    title_redirecting: "リダイレクト中...",
    title_done: "完了",
    title_failed: "失敗",
    initializing: "初期化中...",
    connection_retry: "接続エラー。{ms}ms 後に再試行します...",
    request_failed: "リクエスト失敗",
    bad_ticket: "無効なチケット",
    turnstile_load_failed: "Turnstile の読み込みに失敗しました",
    loading_turnstile: "Turnstile を読み込み中...",
    turnstile_missing: "Turnstile が見つかりません",
    waiting_turnstile: "Turnstile を待機中...",
    turnstile_expired_retry: "Turnstile の有効期限切れ。再試行します...",
    submitting_turnstile: "Turnstile を送信中...",
    submitting_turnstile_done: "Turnstile を送信中... {done}",
    turnstile_done: "Turnstile... {done}",
    turnstile_rejected_retry: "Turnstile が拒否されました。再試行してください。",
    turnstile_rejected: "Turnstile が拒否されました",
    turnstile_failed: "Turnstile 失敗",
    turnstile_expired: "Turnstile の有効期限切れ",
    loading_solver: "ソルバーを読み込み中...",
    worker_missing: "Worker が見つかりません",
    solver_missing: "ソルバーが見つかりません",
    bad_binding: "無効なバインド",
    challenge_failed: "チャレンジ失敗",
    challenge_timeout: "チャレンジのタイムアウト",
    solving_equihash_progress: "Equihash を解いています（経過 {elapsed}s、残り {remaining}s、rows {rows}、解決 {ewmaSolveMs}ms）...",
    solving_equihash_done: "Equihash を解決... {done}",
    pow_done: "PoW... {done}",
    no_challenge: "チャレンジなし",
    consume_missing: "consume がありません",
    no_workers: "利用可能な worker がありません",
    worker_error: "Worker エラー",
    worker_message_error: "Worker メッセージエラー",
    access_granted_close: "認証に成功しました。このウィンドウを閉じてください。",
    access_granted_redirecting: "認証に成功しました。{redirect}",
    session_expired_reload: "セッション期限切れ。再読み込み中...",
    error_prefix: "エラー: {message}",
    done: "完了",
    redirecting: "リダイレクト中...",
    failed: "失敗",
  },
  zh_hant: {
    title_verifying: "驗證中...",
    title_redirecting: "正在跳轉...",
    title_done: "完成",
    title_failed: "失敗",
    initializing: "初始化中...",
    connection_retry: "連線錯誤，{ms}ms 後重試...",
    request_failed: "請求失敗",
    bad_ticket: "票據無效",
    turnstile_load_failed: "Turnstile 載入失敗",
    loading_turnstile: "載入 Turnstile...",
    turnstile_missing: "Turnstile 不可用",
    waiting_turnstile: "等待 Turnstile...",
    turnstile_expired_retry: "Turnstile 已過期，正在重試...",
    submitting_turnstile: "提交 Turnstile...",
    submitting_turnstile_done: "提交 Turnstile... {done}",
    turnstile_done: "Turnstile... {done}",
    turnstile_rejected_retry: "Turnstile 被拒絕，請重試。",
    turnstile_rejected: "Turnstile 被拒絕",
    turnstile_failed: "Turnstile 失敗",
    turnstile_expired: "Turnstile 已過期",
    loading_solver: "載入求解器...",
    worker_missing: "Worker 不可用",
    solver_missing: "求解器不可用",
    bad_binding: "繫結無效",
    challenge_failed: "挑戰失敗",
    challenge_timeout: "挑戰逾時",
    solving_equihash_progress: "Equihash 求解（已用 {elapsed}s，剩餘 {remaining}s，rows {rows}，求解 {ewmaSolveMs}ms）...",
    solving_equihash_done: "Equihash 求解... {done}",
    pow_done: "PoW... {done}",
    no_challenge: "沒有挑戰",
    consume_missing: "缺少 consume",
    no_workers: "沒有可用的 worker",
    worker_error: "Worker 錯誤",
    worker_message_error: "Worker 訊息錯誤",
    access_granted_close: "已通過驗證，可關閉此視窗。",
    access_granted_redirecting: "已通過驗證。{redirect}",
    session_expired_reload: "工作階段已過期，正在重新整理...",
    error_prefix: "錯誤：{message}",
    done: "完成",
    redirecting: "正在跳轉...",
    failed: "失敗",
  },
  ko: {
    title_verifying: "확인 중...",
    title_redirecting: "이동 중...",
    title_done: "완료",
    title_failed: "실패",
    initializing: "초기화 중...",
    connection_retry: "연결 오류. {ms}ms 후 다시 시도합니다...",
    request_failed: "요청 실패",
    bad_ticket: "잘못된 티켓",
    turnstile_load_failed: "Turnstile 로드 실패",
    loading_turnstile: "Turnstile 로드 중...",
    turnstile_missing: "Turnstile 없음",
    waiting_turnstile: "Turnstile 대기 중...",
    turnstile_expired_retry: "Turnstile 만료됨. 다시 시도합니다...",
    submitting_turnstile: "Turnstile 제출 중...",
    submitting_turnstile_done: "Turnstile 제출 중... {done}",
    turnstile_done: "Turnstile... {done}",
    turnstile_rejected_retry: "Turnstile 거부됨. 다시 시도해 주세요.",
    turnstile_rejected: "Turnstile 거부됨",
    turnstile_failed: "Turnstile 실패",
    turnstile_expired: "Turnstile 만료됨",
    loading_solver: "솔버 로드 중...",
    worker_missing: "Worker 없음",
    solver_missing: "솔버 없음",
    bad_binding: "잘못된 바인딩",
    challenge_failed: "챌린지 실패",
    challenge_timeout: "챌린지 시간 초과",
    solving_equihash_progress: "Equihash 계산 중 ({elapsed}s 경과, {remaining}s 남음, rows {rows}, 계산 {ewmaSolveMs}ms)...",
    solving_equihash_done: "Equihash 계산... {done}",
    pow_done: "PoW... {done}",
    no_challenge: "챌린지 없음",
    consume_missing: "consume 없음",
    no_workers: "사용 가능한 worker 없음",
    worker_error: "Worker 오류",
    worker_message_error: "Worker 메시지 오류",
    access_granted_close: "접근이 허용되었습니다. 이 창을 닫아도 됩니다.",
    access_granted_redirecting: "접근이 허용되었습니다. {redirect}",
    session_expired_reload: "세션이 만료되었습니다. 다시 로드합니다...",
    error_prefix: "오류: {message}",
    done: "완료",
    redirecting: "이동 중...",
    failed: "실패",
  },
  fr: {
    title_verifying: "Vérification...",
    title_redirecting: "Redirection...",
    title_done: "Terminé",
    title_failed: "Échec",
    initializing: "Initialisation...",
    connection_retry: "Erreur de connexion. Nouvelle tentative dans {ms}ms...",
    request_failed: "Échec de la requête",
    bad_ticket: "Ticket invalide",
    turnstile_load_failed: "Échec du chargement de Turnstile",
    loading_turnstile: "Chargement de Turnstile...",
    turnstile_missing: "Turnstile indisponible",
    waiting_turnstile: "En attente de Turnstile...",
    turnstile_expired_retry: "Turnstile expiré. Nouvelle tentative...",
    submitting_turnstile: "Envoi de Turnstile...",
    submitting_turnstile_done: "Envoi de Turnstile... {done}",
    turnstile_done: "Turnstile... {done}",
    turnstile_rejected_retry: "Turnstile refusé. Veuillez réessayer.",
    turnstile_rejected: "Turnstile refusé",
    turnstile_failed: "Échec de Turnstile",
    turnstile_expired: "Turnstile expiré",
    loading_solver: "Chargement du solveur...",
    worker_missing: "Worker indisponible",
    solver_missing: "Solveur indisponible",
    bad_binding: "Liaison invalide",
    challenge_failed: "Échec du défi",
    challenge_timeout: "Délai du défi dépassé",
    solving_equihash_progress: "Résolution Equihash ({elapsed}s écoulées, {remaining}s restantes, lignes {rows}, résolution {ewmaSolveMs}ms)...",
    solving_equihash_done: "Résolution Equihash... {done}",
    pow_done: "PoW... {done}",
    no_challenge: "Aucun défi",
    consume_missing: "Consume manquant",
    no_workers: "Aucun worker",
    worker_error: "Erreur du worker",
    worker_message_error: "Erreur de message du worker",
    access_granted_close: "Accès autorisé. Vous pouvez fermer cette fenêtre.",
    access_granted_redirecting: "Accès autorisé. {redirect}",
    session_expired_reload: "Session expirée. Rechargement...",
    error_prefix: "ERREUR : {message}",
    done: "terminé",
    redirecting: "Redirection...",
    failed: "Échec",
  },
};

const normalizeLocale = (value) => {
  if (!value) return "";
  const lower = String(value).toLowerCase().replace(/_/g, "-");
  if (lower.startsWith("zh")) {
    if (
      lower.includes("-hant") ||
      lower.startsWith("zh-tw") ||
      lower.startsWith("zh-hk") ||
      lower.startsWith("zh-mo")
    ) {
      return "zh_hant";
    }
    return "zh";
  }
  if (lower.startsWith("ja")) return "ja";
  if (lower.startsWith("ko") || lower.startsWith("kr")) return "ko";
  if (lower.startsWith("fr")) return "fr";
  if (lower.startsWith("en")) return "en";
  return "";
};

const resolveLocale = (languages) => {
  const list = Array.isArray(languages) ? languages : languages ? [languages] : [];
  for (const lang of list) {
    const normalized = normalizeLocale(lang);
    if (normalized) return normalized;
  }
  return "en";
};

const readNavigatorLanguages = () => {
  if (typeof navigator === "undefined") return [];
  if (Array.isArray(navigator.languages) && navigator.languages.length > 0) {
    return navigator.languages;
  }
  if (typeof navigator.language === "string" && navigator.language) {
    return [navigator.language];
  }
  return [];
};

let activeLocale = resolveLocale(readNavigatorLanguages());
const getLocale = () => activeLocale;
const setLocale = (next) => {
  const normalized = normalizeLocale(next);
  if (normalized) activeLocale = normalized;
};

const translate = (locale, key, vars) => {
  const dict = I18N[locale] || I18N.en;
  const fallback = I18N.en;
  const template = dict[key] || fallback[key] || key;
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/gu, (match, name) => {
    if (!Object.prototype.hasOwnProperty.call(vars, name)) return match;
    return String(vars[name]);
  });
};

const t = (key, vars) => translate(activeLocale, key, vars);

const wrapSpan = (klass, text) => `<span class="${klass}">${text}</span>`;
const doneMark = () => wrapSpan("green", t("done"));
const yellowMark = (text) => wrapSpan("yellow", text);

const ERROR_KEY_BY_MESSAGE = {
  "Request Failed": "request_failed",
  "Bad Ticket": "bad_ticket",
  "Turnstile Load Failed": "turnstile_load_failed",
  "Turnstile Missing": "turnstile_missing",
  "Turnstile Failed": "turnstile_failed",
  "Turnstile Expired": "turnstile_expired",
  "Turnstile Rejected": "turnstile_rejected",
  "Worker Missing": "worker_missing",
  "Solver Missing": "solver_missing",
  "Bad Binding": "bad_binding",
  "Challenge Failed": "challenge_failed",
  "Challenge Timeout": "challenge_timeout",
  "No Challenge": "no_challenge",
  "Consume Missing": "consume_missing",
  "No workers": "no_workers",
  "Worker error": "worker_error",
  "Worker message error": "worker_message_error",
};

const escapeHtml = (value) =>
  String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const localizeErrorMessage = (message) => {
  const key = ERROR_KEY_BY_MESSAGE[message];
  return escapeHtml(key ? t(key) : message);
};

const parseAtomicCfg = (raw) => {
  const parts = typeof raw === "string" && raw ? raw.split("|") : [];
  return {
    atomic: parts[0] === "1",
    q: { ts: parts[1] || "__ts", tt: parts[2] || "__tt", ct: parts[3] || "__ct" },
    h: { ts: parts[4] || "x-turnstile", tt: parts[5] || "x-ticket", ct: parts[6] || "x-consume" },
    c: parts[7] || "__Secure-pow_a",
  };
};

const normalizeApiPrefix = (prefix) => {
  if (!prefix || typeof prefix !== "string") return "/__pow";
  const trimmed = prefix.trim();
  if (!trimmed) return "/__pow";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withSlash.replace(/\/+$/u, "") || "/__pow";
};

const encodeB64UrlBytes = (bytes) => {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/gu, "");
};

const sha256Bytes = async (value) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(value ?? ""))));

const captchaTagV1 = async (turnToken) =>
  encodeB64UrlBytes((await sha256Bytes(`ctag|v1|t=${typeof turnToken === "string" ? turnToken : ""}`)).slice(0, 12));

const deriveEquihashSeed = async (ticketB64, pathHash, captchaTag) =>
  sha256Bytes(JSON.stringify(["equihash-seed-v1", ticketB64, pathHash, captchaTag]));

const formatSeconds = (valueMs) => {
  const ms = Number(valueMs);
  return Number.isFinite(ms) && ms >= 0 ? (ms / 1000).toFixed(1) : "0.0";
};

const formatEquihashProgress = (progress) => {
  const rows = Math.max(1, Math.floor(Number(progress && progress.rows) || 1));
  const ewmaSolveMs = Math.max(0, Math.round(Number(progress && progress.ewmaSolveMs) || 0));
  return t("solving_equihash_progress", {
    elapsed: formatSeconds(progress && progress.elapsedMs),
    remaining: formatSeconds(progress && progress.remainingMs),
    rows,
    ewmaSolveMs,
  });
};

const parseBootstrapEq = (nRaw, kRaw) => {
  const n = Number(nRaw);
  const k = Number(kRaw);
  if (!Number.isSafeInteger(n) || !Number.isSafeInteger(k) || n < 8 || n > 256 || n % 2 !== 0 || k < 2 || k > 8 || n % (k + 1) !== 0) return null;
  return { n, k };
};

const parseBootstrap = (bootstrapB64) => {
  const raw = decodeB64Url(String(bootstrapB64 || ""));
  if (!raw) return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const ticketB64 = typeof parsed.ticketB64 === "string" ? parsed.ticketB64 : "";
  const pathHash = typeof parsed.pathHash === "string" ? parsed.pathHash : "";
  const apiPrefix = normalizeApiPrefix(parsed.apiPrefix);
  const eq = parseBootstrapEq(parsed.eq && parsed.eq.n, parsed.eq && parsed.eq.k);
  const issuedAt = Number(parsed.issuedAt);
  const expireAt = Number(parsed.expireAt);
  const mask = Number(parsed.mask);
  if (!ticketB64 || !pathHash || !eq || !Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expireAt) || expireAt <= issuedAt || !Number.isSafeInteger(mask) || mask < 1 || mask > 3) return null;
  return { ticketB64, pathHash, apiPrefix, eq, issuedAt, expireAt, mask };
};

const throwVerifyDeny = (reason) => {
  const hint = String(reason || "stale").trim().toLowerCase() || "stale";
  const error = new Error(`verify denied: ${hint}`);
  error.name = "ApiError";
  error.status = 403;
  error.hint = hint;
  throw error;
};

const SUBMISSION_RESERVE_MS = 1500;
const TURNSTILE_TOKEN_TTL_MS = 300000;
const monotonicNow = () =>
  typeof performance !== "undefined" && typeof performance.now === "function"
    ? performance.now()
    : Date.now();

const createTokenState = () => ({
  token: "",
  expiresAtMs: Infinity,
  expired: false,
  onExpire: null,
  widgetCleanup: null,
});

const createLifecycleError = (reason) => {
  const error = new Error(`challenge lifecycle: ${reason}`);
  error.name = "PowLifecycleError";
  error.reason = reason;
  return error;
};

const createChallengeLifecycle = (expireAt, tokenState) => {
  const startedAtMs = monotonicNow();
  const numericExpireAt = Number(expireAt);
  const ticketRemainingMs = numericExpireAt === Infinity ? Infinity : numericExpireAt * 1000 - Date.now();
  const ticketDeadlineMs = Number.isFinite(ticketRemainingMs)
    ? startedAtMs + Math.max(0, ticketRemainingMs)
    : Infinity;
  const deadlineAtMs = () => Math.min(ticketDeadlineMs, Number(tokenState?.expiresAtMs) || Infinity);
  let stopped = false;
  let disposed = false;
  let reason = "";
  let computeDeadlineMs = null;
  let rejectStop;
  const stopPromise = new Promise((_, reject) => { rejectStop = reject; });
  stopPromise.catch(() => {});
  const cleanups = new Set();
  const runCleanups = () => {
    for (const cleanup of cleanups) {
      try { cleanup(); } catch {}
    }
    cleanups.clear();
  };
  const stop = (nextReason) => {
    if (stopped || disposed) return;
    stopped = true;
    reason = nextReason;
    runCleanups();
    rejectStop(createLifecycleError(nextReason));
  };
  const addCleanup = (cleanup) => {
    if (typeof cleanup !== "function") return () => {};
    if (stopped || disposed) {
      try { cleanup(); } catch {}
      return () => {};
    }
    cleanups.add(cleanup);
    return () => cleanups.delete(cleanup);
  };
  const remainingActualMs = () => Math.max(0, Math.floor(deadlineAtMs() - monotonicNow()));
  const remainingComputeMs = () => Math.max(0, remainingActualMs() - SUBMISSION_RESERVE_MS);
  const check = () => {
    if (!stopped && !disposed) {
      const now = monotonicNow();
      if (tokenState?.expired || now >= deadlineAtMs()) stop("expired");
      else if (computeDeadlineMs !== null && now >= computeDeadlineMs) stop("compute");
    }
    return reason;
  };
  const ensureActive = () => {
    check();
    if (stopped) throw createLifecycleError(reason);
  };
  const race = (value) => Promise.race([Promise.resolve(value), stopPromise]);
  let timer;
  if (typeof setInterval === "function") timer = setInterval(check, 25);

  const onPageHide = (event) => {
    if (!event || event.persisted !== true) stop("teardown");
  };
  const onPageShow = () => check();
  const onVisibilityChange = () => {
    if (typeof document !== "undefined" && document.hidden === false) check();
  };
  if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
    window.addEventListener("pagehide", onPageHide);
    window.addEventListener("pageshow", onPageShow);
  }
  if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
    document.addEventListener("visibilitychange", onVisibilityChange);
  }
  const detach = () => {
    if (timer !== undefined) clearInterval(timer);
    if (typeof window !== "undefined" && typeof window.removeEventListener === "function") {
      window.removeEventListener("pagehide", onPageHide);
      window.removeEventListener("pageshow", onPageShow);
    }
    if (typeof document !== "undefined" && typeof document.removeEventListener === "function") {
      document.removeEventListener("visibilitychange", onVisibilityChange);
    }
  };
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    detach();
    runCleanups();
  };
  const armComputeDeadline = () => {
    computeDeadlineMs = deadlineAtMs() - SUBMISSION_RESERVE_MS;
    check();
  };
  const disarmComputeDeadline = () => {
    computeDeadlineMs = null;
  };
  const refreshComputeDeadline = () => {
    if (computeDeadlineMs !== null) {
      computeDeadlineMs = deadlineAtMs() - SUBMISSION_RESERVE_MS;
      check();
    }
  };
  check();
  return {
    addCleanup,
    armComputeDeadline,
    check,
    deadlineAtMs,
    dispose,
    disarmComputeDeadline,
    ensureActive,
    race,
    reason: () => reason,
    remainingActualMs,
    remainingComputeMs,
    refreshComputeDeadline,
    stop,
  };
};

const postVerify = async (url, body, lifecycle = null) => {
  const result = await postJson(url, body, 3, lifecycle);
  if (!result || typeof result !== "object" || Array.isArray(result) || result.ok !== true) throwVerifyDeny(result && result.reason);
  return result;
};

const createWorkerRpc = (worker, onProgress) => {
  let rid = 0;
  const pending = new Map();
  let disposed = false;
  const rejectAll = (error) => {
    for (const entry of pending.values()) entry.reject(error);
    pending.clear();
  };
  const handleMessage = (event) => {
    if (disposed) return;
    const data = event && event.data ? event.data : {};
    if (data.type === "PROGRESS") {
      if (typeof onProgress === "function") onProgress(data);
      return;
    }
    const entry = pending.get(data.rid);
    if (!entry) return;
    pending.delete(data.rid);
    if (data.type === "ERROR") entry.reject(new Error(data.message || "Worker error"));
    else entry.resolve(data);
  };
  worker.addEventListener("message", handleMessage);
  worker.addEventListener("messageerror", () => rejectAll(new Error("Worker message error")));
  worker.addEventListener("error", () => rejectAll(new Error("Worker error")));
  const call = (type, payload, transfer = []) => {
    const id = ++rid;
    return new Promise((resolve, reject) => {
      if (disposed) {
        reject(new Error("Worker disposed"));
        return;
      }
      pending.set(id, { resolve, reject });
      try {
        worker.postMessage({ ...(payload || {}), type, rid: id }, transfer);
      } catch (error) {
        pending.delete(id);
        reject(error);
      }
    });
  };
  const cancel = () => {
    if (disposed) return;
    try { worker.postMessage({ type: "CANCEL" }); } catch {}
  };
  const dispose = () => {
    if (disposed) return;
    cancel();
    disposed = true;
    rejectAll(new Error("Worker disposed"));
    try { worker.postMessage({ type: "DISPOSE" }); } catch {}
    try { worker.terminate(); } catch {}
  };
  return { call, cancel, dispose };
};

const STALE_RELOAD_STORAGE_KEY = "__pow_stale_reload_v1";
const STALE_RELOAD_WINDOW_MS = 15000;
const STALE_RELOAD_MAX_ATTEMPTS = 2;

const sessionStorageSafe = () => {
  try {
    if (typeof window === "undefined" || !window.sessionStorage) return null;
    return window.sessionStorage;
  } catch {
    return null;
  }
};

const shouldAttemptStaleReload = (nowMs = Date.now()) => {
  const storage = sessionStorageSafe();
  if (!storage) return false;
  let count = 0;
  try {
    const raw = storage.getItem(STALE_RELOAD_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      const ts = Number(parsed && parsed.ts);
      const parsedCount = Number(parsed && parsed.count);
      if (Number.isFinite(ts) && nowMs - ts <= STALE_RELOAD_WINDOW_MS) {
        count = Number.isFinite(parsedCount) && parsedCount > 0 ? Math.floor(parsedCount) : 0;
      }
    }
  } catch {}

  if (count >= STALE_RELOAD_MAX_ATTEMPTS) return false;

  try {
    storage.setItem(
      STALE_RELOAD_STORAGE_KEY,
      JSON.stringify({ ts: nowMs, count: count + 1 })
    );
  } catch {
    return false;
  }
  return true;
};

const buildApiError = (url, res) => {
  let endpoint = String(url || "");
  let path = endpoint;
  try {
    const parsed = new URL(endpoint, window.location.href);
    endpoint = parsed.toString();
    path = parsed.pathname;
  } catch {}
  const err = new Error(`HTTP ${res.status}`);
  err.name = "ApiError";
  err.status = Number(res.status || 0);
  err.hint =
    res && res.headers && typeof res.headers.get === "function"
      ? String(res.headers.get("x-pow-h") || "").trim().toLowerCase()
      : "";
  err.endpoint = endpoint;
  err.path = path;
  return err;
};

const isApiError = (err) => Boolean(err && err.name === "ApiError" && Number(err.status));

const routeHintAction = ({ status, hint }) => {
  if (Number(status) !== 403) {
    return { action: "hard_fail", bounded: false };
  }
  const normalized = String(hint || "").trim().toLowerCase();
  if (normalized === "cheat") {
    return { action: "hard_fail", bounded: false };
  }
  if (normalized === "stale" || !normalized) {
    return { action: "reload", bounded: true };
  }
  return { action: "hard_fail", bounded: false };
};

const isNetworkTransportError = (err) => {
  if (!err) return false;
  if (typeof DOMException !== "undefined" && err instanceof DOMException) {
    return err.name === "AbortError";
  }
  if (err instanceof TypeError) return true;
  const name = String(err.name || "").toLowerCase();
  if (name === "aborterror") return true;
  const msg = String(err.message || "").toLowerCase();
  return /(network|fetch|connection|reset|econn|timed?\s*out|stream)/.test(msg);
};

const postJson = async (url, body, retries = 3, lifecycle = null) => {
  const abortController = lifecycle && typeof AbortController === "function" ? new AbortController() : null;
  const removeCleanup = lifecycle?.addCleanup(() => {
    try { abortController?.abort(); } catch {}
  }) || (() => {});
  try {
    for (let i = 0; i <= retries; i++) {
      try {
        const request = fetch(url, {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body || {}),
          ...(abortController ? { signal: abortController.signal } : {}),
        });
        const res = lifecycle ? await lifecycle.race(request) : await request;
        if (!res.ok) {
          throw buildApiError(url, res);
        }
        try {
          const parsed = res.json();
          const result = lifecycle ? await lifecycle.race(parsed) : await parsed;
          return result;
        } catch (error) {
          if (error?.name === "PowLifecycleError") throw error;
          if (isNetworkTransportError(error)) throw error;
          return {};
        }
      } catch (err) {
        if (isApiError(err)) throw err;
        if (lifecycle?.reason()) throw err;
        if (!isNetworkTransportError(err)) throw err;
        if (i === retries) throw err;
        const delay = 500 * Math.pow(2, i);
        log(t("connection_retry", { ms: delay }));
        const wait = new Promise((r) => setTimeout(r, delay));
        if (lifecycle) await lifecycle.race(wait);
        else await wait;
      }
    }
    return {};
  } finally {
    removeCleanup();
  }
};

const setAtomicCookie = (name, value, maxAge, path) => {
  if (!name || !value) return false;
  const cookiePath = path && path.startsWith("/") ? path : "/";
  document.cookie = `${name}=${value}; Max-Age=${maxAge}; Path=${cookiePath}; Secure; SameSite=Lax`;
  return document.cookie.includes(`${name}=`);
};

const canUseCookie = (name, value) =>
  Boolean(name && value && value.length + name.length + 1 <= 3800);

const cookiePathForTarget = (target) => {
  try {
    const url = new URL(target, window.location.href);
    return url.pathname || "/";
  } catch {
    return "/";
  }
};

const addQuery = (url, kv) => {
  const next = new URL(url, window.location.href);
  for (const [key, value] of Object.entries(kv || {})) {
    if (key && value) next.searchParams.set(key, value);
  }
  return next.toString();
};

const originFromLocation = (location) => {
  try {
    if (!location) return null;
    if (typeof location.origin === "string" && location.origin) return location.origin;
    if (typeof location.href === "string" && location.href) {
      return new URL(location.href, window.location.href).origin;
    }
    return null;
  } catch {
    return null;
  }
};

const selfOrigin = () => {
  try {
    return new URL(window.location.href).origin;
  } catch {
    return null;
  }
};

const postAtomicMessage = (payload) => {
  const msg = { type: "POW_ATOMIC", ...(payload || {}) };
  const expectedOrigin = selfOrigin();
  const postTo = (target) => {
    try {
      if (!target || typeof target.postMessage !== "function") return;
      if (target.closed) return;
      const targetOrigin = originFromLocation(target.location);
      if (!expectedOrigin || targetOrigin !== expectedOrigin) return;
      target.postMessage(msg, expectedOrigin);
    } catch {}
  };
  postTo(window.opener);
  if (window.parent && window.parent !== window) {
    postTo(window.parent);
  }
};

const initUi = () => {
  const style = document.createElement("style");
  style.textContent = [
    ":root{--bg:#050607;--card-bg:rgba(24,24,27,0.75);--border:rgba(255,255,255,0.1);--text:#f4f4f8;--sub:#9ca3af;--accent:#fff;--yellow:#fbbf24;--green:#4ade80;--font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,'SFMono-Regular',Menlo,Monaco,Consolas,monospace;--glow-x:50%;--glow-y:0%;--glow-r:62;--glow-g:110;--glow-b:255;--title-r:113;--title-g:148;--title-b:253;--breathe-opacity:1;--reflect-top:0;--reflect-bottom:0;--reflect-left:0;--reflect-right:0;}",
    "html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:var(--bg);color:var(--text);font-family:var(--font);display:flex;justify-content:center;align-items:center;-webkit-font-smoothing:antialiased;}",
    "body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(circle at var(--glow-x) var(--glow-y), rgba(var(--glow-r),var(--glow-g),var(--glow-b),0.35),transparent 55%),radial-gradient(circle at calc(100% - var(--glow-x)) calc(100% - var(--glow-y)), rgba(var(--glow-r),var(--glow-g),var(--glow-b),0.2),transparent 55%);opacity:var(--breathe-opacity);}",
    "body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse var(--glow-h-width-top,6.75%) var(--glow-v-height-top,18px) at var(--glow-x) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--reflect-top)) 0%,transparent 70%) top/100% var(--glow-v-height-top,18px) no-repeat,radial-gradient(ellipse var(--glow-h-width-bottom,6.75%) var(--glow-v-height-bottom,18px) at var(--glow-x) 100%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--reflect-bottom)) 0%,transparent 70%) bottom/100% var(--glow-v-height-bottom,18px) no-repeat,radial-gradient(ellipse var(--glow-h-width-left,18px) var(--glow-v-height-left,6.75%) at 0% var(--glow-y),rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--reflect-left)) 0%,transparent 70%) left/var(--glow-h-width-left,18px) 100% no-repeat,radial-gradient(ellipse var(--glow-h-width-right,18px) var(--glow-v-height-right,6.75%) at 100% var(--glow-y),rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--reflect-right)) 0%,transparent 70%) right/var(--glow-h-width-right,18px) 100% no-repeat;}",
    ".card{background:rgba(15,23,42,0.4);border:1px solid rgba(148,163,184,0.2);border-radius:12px;padding:32px;width:90%;max-width:360px;text-align:center;animation:fade-in 0.6s cubic-bezier(0.16,1,0.3,1) both;transition:height 0.3s ease,border-color 0.2s ease;backdrop-filter:blur(12px) saturate(130%);-webkit-backdrop-filter:blur(12px) saturate(130%);position:relative;z-index:1;}",
    ".card::after{content:'';position:absolute;top:0;left:0;right:0;bottom:0;pointer-events:none;border-radius:inherit;background:radial-gradient(ellipse var(--elem-glow-h-width-top,15%) 1px at var(--elem-glow-x,50%) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--elem-reflect-top,0)) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),calc(var(--elem-reflect-top,0) * 0.3)) 50%,transparent 100%) top/100% 1px no-repeat,radial-gradient(ellipse var(--elem-glow-h-width-bottom,15%) 1px at var(--elem-glow-x,50%) 100%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--elem-reflect-bottom,0)) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),calc(var(--elem-reflect-bottom,0) * 0.3)) 50%,transparent 100%) bottom/100% 1px no-repeat,radial-gradient(ellipse 1px var(--elem-glow-v-height-left,15%) at 0% var(--elem-glow-y,50%),rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--elem-reflect-left,0)) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),calc(var(--elem-reflect-left,0) * 0.3)) 50%,transparent 100%) left/1px 100% no-repeat,radial-gradient(ellipse 1px var(--elem-glow-v-height-right,15%) at 100% var(--elem-glow-y,50%),rgba(var(--glow-r),var(--glow-g),var(--glow-b),var(--elem-reflect-right,0)) 0%,rgba(var(--glow-r),var(--glow-g),var(--glow-b),calc(var(--elem-reflect-right,0) * 0.3)) 50%,transparent 100%) right/1px 100% no-repeat;}",
    "h1{margin:0 0 24px;font-size:16px;font-weight:600;letter-spacing:0;line-height:1.2;}",
    "#t{color:rgb(var(--title-r),var(--title-g),var(--title-b));text-shadow:0 0 10px rgba(var(--glow-r),var(--glow-g),var(--glow-b),0.26),0 0 24px rgba(var(--glow-r),var(--glow-g),var(--glow-b),0.14);transition:color 0.24s ease,text-shadow 0.24s ease;}",
    "#t[data-state='success']{color:#7ae7a6;text-shadow:0 0 10px rgba(122,231,166,0.3),0 0 24px rgba(122,231,166,0.16);}",
    "#t[data-state='error']{color:#ff8b8b;text-shadow:0 0 10px rgba(255,139,139,0.28),0 0 24px rgba(255,139,139,0.14);}",
    "#log{font-family:var(--mono);font-size:13px;color:var(--sub);text-align:left;height:120px;overflow:hidden;position:relative;mask-image:linear-gradient(to bottom,transparent,black 30%);-webkit-mask-image:linear-gradient(to bottom,transparent,black 30%);display:flex;flex-direction:column;justify-content:flex-end;background:transparent;border:none;border-radius:0;padding:0;}",
    "#ts{margin-top:16px;display:flex;justify-content:center;max-height:0;opacity:0;overflow:hidden;transition:max-height 0.4s cubic-bezier(0.16,1,0.3,1),opacity 0.3s ease,margin-top 0.4s cubic-bezier(0.16,1,0.3,1);position:relative;z-index:2;}#ts.show{max-height:400px;opacity:1;margin-top:16px;}#ts.hide{max-height:0;opacity:0;margin-top:0;}",
    ".log-line{padding:3px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:0 0 auto;}.log-line .yellow{color:var(--yellow);}.log-line .green{color:var(--green);}",
    "@keyframes fade-in{from{opacity:0;transform:scale(0.98)}to{opacity:1;transform:scale(1)}}"
  ].join("");
  (document.head || document.documentElement).appendChild(style);
  const titleText = t("title_verifying");
  document.body.innerHTML =
    `<div class="card"><h1 id="t">${titleText}</h1><div id="log"></div><div id="ts"></div></div>`;

  // --- Advanced Glow Effect Implementation (from landing) ---
  const glowState = {
    // Animation frame
    glowAnimationFrame: null,
    lastFrameTime: Date.now(),

    // Position and movement
    currentGlowX: 0.5,
    currentGlowY: 0,
    targetGlowX: 0.5,
    targetGlowY: 0,
    currentSpeedX: 0,
    currentSpeedY: 0,

    // Mode control
    isAutoGlow: true,
    isResting: false,
    restStartTime: 0,
    currentRestDuration: Math.random() * 8000,

    // Mouse tracking
    latestMouseX: 0,
    latestMouseY: 0,
    lastMouseSampleTime: 0,
    mouseIdleTimer: null,
    MOUSE_SAMPLE_INTERVAL: 1000,

    // Visibility management
    visibilityTimer: null,
    isRenderingStopped: false,
    fadeInPhase: 1,
    FADE_IN_DURATION: 2.5,

    // Color system
    colorTable: [
      { r: 62, g: 110, b: 255 },
      { r: 0, g: 191, b: 255 },
      { r: 64, g: 224, b: 208 },
      { r: 138, g: 43, b: 226 },
      { r: 147, g: 51, b: 234 },
      { r: 199, g: 21, b: 133 },
      { r: 255, g: 20, b: 147 },
      { r: 72, g: 61, b: 139 }
    ],
    currentColorIndex: 0,
    targetColorIndex: 1,
    colorTransitionPhase: Math.random(),
    colorTransitionDuration: 0,

    // Breathing animation
    breathePhase: Math.random(),
    breatheCycleDuration: 0,
    breatheMinOpacity: 0,
    breatheMaxOpacity: 0,
    targetBreatheCycleDuration: 0,
    targetBreatheMinOpacity: 0,
    targetBreatheMaxOpacity: 0,
    BREATHE_SMOOTHING_SPEED: 1.8,

    // Speed system
    MAX_SPEED: 0.08,
    WANDER_ACCELERATION: 0.12,
    MOUSE_ACCELERATION: 0.04,
    WANDER_REACHED_THRESHOLD: 0.01,

    // Helper functions
    getRandomBreatheMin() {
      return 0.5 + Math.random() * 0.2;
    },

    getRandomBreatheMax() {
      return 1.0 + Math.random() * 0.2;
    },

    getRandomBreatheDuration() {
      return 2 + Math.random() * 10;
    },

    getRandomColorIndex() {
      return Math.floor(Math.random() * this.colorTable.length);
    },

    getNextColorIndex(excludeIndex) {
      if (this.colorTable.length <= 1) return excludeIndex;
      let nextIndex = this.getRandomColorIndex();
      while (nextIndex === excludeIndex) {
        nextIndex = this.getRandomColorIndex();
      }
      return nextIndex;
    },

    getRandomColorTransitionDuration() {
      return 10 + Math.random() * 35;
    },

    getRandomWanderTarget() {
      return {
        x: 0.1 + Math.random() * 0.8,
        y: 0.05 + Math.random() * 0.2
      };
    },

    syncBreatheOpacity() {
      const body = document.body;
      if (!body) return;
      const breatheValue = 0.5 + 0.5 * Math.sin(this.breathePhase * Math.PI * 2 - Math.PI / 2);
      const currentOpacity = this.breatheMinOpacity + (this.breatheMaxOpacity - this.breatheMinOpacity) * breatheValue;
      body.style.setProperty('--breathe-opacity', (currentOpacity * this.fadeInPhase).toFixed(3));
    },

    applyGlowColor() {
      const body = document.body;
      if (!body) return;
      const currentColor = this.colorTable[this.currentColorIndex] || this.colorTable[0];
      const targetColor = this.colorTable[this.targetColorIndex] || currentColor;
      const r = Math.round(currentColor.r + (targetColor.r - currentColor.r) * this.colorTransitionPhase);
      const g = Math.round(currentColor.g + (targetColor.g - currentColor.g) * this.colorTransitionPhase);
      const b = Math.round(currentColor.b + (targetColor.b - currentColor.b) * this.colorTransitionPhase);
      const titleMix = 0.28;
      const titleR = Math.round(r + (244 - r) * titleMix);
      const titleG = Math.round(g + (244 - g) * titleMix);
      const titleB = Math.round(b + (248 - b) * titleMix);
      body.style.setProperty('--glow-r', r);
      body.style.setProperty('--glow-g', g);
      body.style.setProperty('--glow-b', b);
      body.style.setProperty('--title-r', titleR);
      body.style.setProperty('--title-g', titleG);
      body.style.setProperty('--title-b', titleB);
    },

    updateElementsEdgeGlow(glowX, glowY) {
      const w = window.innerWidth;
      const h = window.innerHeight;
      const elements = document.querySelectorAll('.card');

      elements.forEach(element => {
        const rect = element.getBoundingClientRect();
        const relativeX = ((glowX - rect.left) / rect.width) * 100;
        const relativeY = ((glowY - rect.top) / rect.height) * 100;

        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        const dx = glowX - centerX;
        const dy = glowY - centerY;
        const distance = Math.sqrt(dx * dx + dy * dy);

        const maxDistance = Math.sqrt(w * w + h * h) * 0.5;
        const normalizedDistance = distance / maxDistance;

        const ELEMENT_GLOW_RADIUS = 0.4;
        const ELEMENT_MAX_INTENSITY = 0.2;
        const ELEMENT_REFLECTION_COEFFICIENT = 0.7;

        const baseIntensity = Math.max(0, 1 - normalizedDistance / ELEMENT_GLOW_RADIUS) * ELEMENT_MAX_INTENSITY;

        const distToTop = Math.abs(glowY - rect.top) / rect.height;
        const distToBottom = Math.abs(glowY - rect.bottom) / rect.height;
        const distToLeft = Math.abs(glowX - rect.left) / rect.width;
        const distToRight = Math.abs(glowX - rect.right) / rect.width;

        const edgeThreshold = 2.0;
        const proximityTop = distToTop < edgeThreshold ? Math.pow(1 - distToTop / edgeThreshold, 1.5) : 0;
        const proximityBottom = distToBottom < edgeThreshold ? Math.pow(1 - distToBottom / edgeThreshold, 1.5) : 0;
        const proximityLeft = distToLeft < edgeThreshold ? Math.pow(1 - distToLeft / edgeThreshold, 1.5) : 0;
        const proximityRight = distToRight < edgeThreshold ? Math.pow(1 - distToRight / edgeThreshold, 1.5) : 0;

        const reflectTop = baseIntensity * ELEMENT_REFLECTION_COEFFICIENT * proximityTop;
        const reflectBottom = baseIntensity * ELEMENT_REFLECTION_COEFFICIENT * proximityBottom;
        const reflectLeft = baseIntensity * ELEMENT_REFLECTION_COEFFICIENT * proximityLeft;
        const reflectRight = baseIntensity * ELEMENT_REFLECTION_COEFFICIENT * proximityRight;

        element.style.setProperty('--elem-glow-x', relativeX.toFixed(2) + '%');
        element.style.setProperty('--elem-glow-y', relativeY.toFixed(2) + '%');
        element.style.setProperty('--elem-reflect-top', reflectTop.toFixed(3));
        element.style.setProperty('--elem-reflect-bottom', reflectBottom.toFixed(3));
        element.style.setProperty('--elem-reflect-left', reflectLeft.toFixed(3));
        element.style.setProperty('--elem-reflect-right', reflectRight.toFixed(3));

        const baseWidth = 10;
        const maxWidth = 30;
        const glowHWidthTop = baseWidth + reflectTop * (maxWidth - baseWidth);
        const glowHWidthBottom = baseWidth + reflectBottom * (maxWidth - baseWidth);
        const glowVHeightLeft = baseWidth + reflectLeft * (maxWidth - baseWidth);
        const glowVHeightRight = baseWidth + reflectRight * (maxWidth - baseWidth);

        element.style.setProperty('--elem-glow-h-width-top', glowHWidthTop + '%');
        element.style.setProperty('--elem-glow-h-width-bottom', glowHWidthBottom + '%');
        element.style.setProperty('--elem-glow-v-height-left', glowVHeightLeft + '%');
        element.style.setProperty('--elem-glow-v-height-right', glowVHeightRight + '%');
      });
    },

    updateGlowPosition(x, y) {
      const xPercent = (x / window.innerWidth * 100).toFixed(1);
      const yPercent = (y / window.innerHeight * 100).toFixed(1);
      document.body.style.setProperty('--glow-x', xPercent + '%');
      document.body.style.setProperty('--glow-y', yPercent + '%');
      this.currentGlowX = x / window.innerWidth;
      this.currentGlowY = y / window.innerHeight;

      const normalizedX = Math.max(0, Math.min(1, this.currentGlowX));
      const normalizedY = Math.max(0, Math.min(1, this.currentGlowY));

      const GLOW_MAX_INTENSITY = 0.35;
      const GLOW_RADIUS = 0.55;
      const REFLECTION_COEFFICIENT = 0.6;

      const distanceToTop = normalizedY;
      const distanceToBottom = 1 - normalizedY;
      const distanceToLeft = normalizedX;
      const distanceToRight = 1 - normalizedX;

      const glowIntensityAtTop = GLOW_MAX_INTENSITY * Math.max(0, 1 - distanceToTop / GLOW_RADIUS);
      const glowIntensityAtBottom = GLOW_MAX_INTENSITY * Math.max(0, 1 - distanceToBottom / GLOW_RADIUS);
      const glowIntensityAtLeft = GLOW_MAX_INTENSITY * Math.max(0, 1 - distanceToLeft / GLOW_RADIUS);
      const glowIntensityAtRight = GLOW_MAX_INTENSITY * Math.max(0, 1 - distanceToRight / GLOW_RADIUS);

      const edgeThreshold = 0.3;
      const proximityTop = normalizedY < edgeThreshold ? Math.pow(1 - normalizedY / edgeThreshold, 2) : 0;
      const proximityBottom = normalizedY > (1 - edgeThreshold) ? Math.pow((normalizedY - (1 - edgeThreshold)) / edgeThreshold, 2) : 0;
      const proximityLeft = normalizedX < edgeThreshold ? Math.pow(1 - normalizedX / edgeThreshold, 2) : 0;
      const proximityRight = normalizedX > (1 - edgeThreshold) ? Math.pow((normalizedX - (1 - edgeThreshold)) / edgeThreshold, 2) : 0;

      const MAX_REFLECT_INTENSITY = 0.5;
      const reflectTop = Math.min(MAX_REFLECT_INTENSITY, glowIntensityAtTop * REFLECTION_COEFFICIENT * proximityTop);
      const reflectBottom = Math.min(MAX_REFLECT_INTENSITY, glowIntensityAtBottom * REFLECTION_COEFFICIENT * proximityBottom);
      const reflectLeft = Math.min(MAX_REFLECT_INTENSITY, glowIntensityAtLeft * REFLECTION_COEFFICIENT * proximityLeft);
      const reflectRight = Math.min(MAX_REFLECT_INTENSITY, glowIntensityAtRight * REFLECTION_COEFFICIENT * proximityRight);

      document.body.style.setProperty('--reflect-top', reflectTop.toFixed(3));
      document.body.style.setProperty('--reflect-bottom', reflectBottom.toFixed(3));
      document.body.style.setProperty('--reflect-left', reflectLeft.toFixed(3));
      document.body.style.setProperty('--reflect-right', reflectRight.toFixed(3));

      const glowHWidthTop = 6.75 + reflectTop * 11.25;
      const glowVHeightTop = 18 + reflectTop * 54;
      const glowHWidthBottom = 6.75 + reflectBottom * 11.25;
      const glowVHeightBottom = 18 + reflectBottom * 54;
      const glowHWidthLeft = 18 + reflectLeft * 54;
      const glowVHeightLeft = 6.75 + reflectLeft * 11.25;
      const glowHWidthRight = 18 + reflectRight * 54;
      const glowVHeightRight = 6.75 + reflectRight * 11.25;

      document.body.style.setProperty('--glow-h-width-top', glowHWidthTop + '%');
      document.body.style.setProperty('--glow-v-height-top', glowVHeightTop + 'px');
      document.body.style.setProperty('--glow-h-width-bottom', glowHWidthBottom + '%');
      document.body.style.setProperty('--glow-v-height-bottom', glowVHeightBottom + 'px');
      document.body.style.setProperty('--glow-h-width-left', glowHWidthLeft + 'px');
      document.body.style.setProperty('--glow-v-height-left', glowVHeightLeft + '%');
      document.body.style.setProperty('--glow-h-width-right', glowHWidthRight + 'px');
      document.body.style.setProperty('--glow-v-height-right', glowVHeightRight + '%');

      this.updateElementsEdgeGlow(x, y);
    },

    initializeGlowState() {
      const initialPosition = this.getRandomWanderTarget();
      const wanderTarget = this.getRandomWanderTarget();
      this.currentGlowX = initialPosition.x;
      this.currentGlowY = initialPosition.y;
      this.targetGlowX = wanderTarget.x;
      this.targetGlowY = wanderTarget.y;
      this.updateGlowPosition(initialPosition.x * window.innerWidth, initialPosition.y * window.innerHeight);
    },

    moveTowardsTarget(currentX, currentY, targetX, targetY, deltaTime, acceleration) {
      const dx = targetX - currentX;
      const dy = targetY - currentY;
      const distance = Math.sqrt(dx * dx + dy * dy);

      if (distance < this.WANDER_REACHED_THRESHOLD) {
        this.currentSpeedX = 0;
        this.currentSpeedY = 0;
        return { x: targetX, y: targetY, reached: true };
      }

      const targetSpeedX = (dx / distance) * this.MAX_SPEED;
      const targetSpeedY = (dy / distance) * this.MAX_SPEED;

      this.currentSpeedX += (targetSpeedX - this.currentSpeedX) * acceleration;
      this.currentSpeedY += (targetSpeedY - this.currentSpeedY) * acceleration;

      const moveX = this.currentSpeedX * deltaTime;
      const moveY = this.currentSpeedY * deltaTime;
      const newX = Math.max(0, Math.min(1, currentX + moveX));
      const newY = Math.max(0, Math.min(1, currentY + moveY));

      const newDx = targetX - newX;
      const newDy = targetY - newY;
      const newDistance = Math.sqrt(newDx * newDx + newDy * newDy);

      if (newDistance < this.WANDER_REACHED_THRESHOLD) {
        this.currentSpeedX = 0;
        this.currentSpeedY = 0;
        return { x: targetX, y: targetY, reached: true };
      }

      return { x: newX, y: newY, reached: false };
    },

    enableAutoGlow() {
      if (this.isAutoGlow) return;
      this.isAutoGlow = true;
      const newTarget = this.getRandomWanderTarget();
      this.targetGlowX = newTarget.x;
      this.targetGlowY = newTarget.y;
    },

    setMouseTarget(x, y) {
      this.isAutoGlow = false;
      this.targetGlowX = x / window.innerWidth;
      this.targetGlowY = y / window.innerHeight;
    },

    handleMouseMove(e) {
      if (document.hidden) return;

      const isInBounds = e.clientX >= 0 && e.clientX <= window.innerWidth &&
                         e.clientY >= 0 && e.clientY <= window.innerHeight;

      if (isInBounds) {
        glowState.latestMouseX = e.clientX;
        glowState.latestMouseY = e.clientY;

        if (glowState.isAutoGlow) {
          glowState.isAutoGlow = false;
          glowState.lastMouseSampleTime = Date.now();
          glowState.setMouseTarget(glowState.latestMouseX, glowState.latestMouseY);
        }

        clearTimeout(glowState.mouseIdleTimer);
        glowState.mouseIdleTimer = setTimeout(() => {
          glowState.enableAutoGlow();
        }, 6000);
      } else {
        clearTimeout(glowState.mouseIdleTimer);
        glowState.enableAutoGlow();
      }
    },

    handleVisibilityChange() {
      if (document.hidden) {
        clearTimeout(glowState.mouseIdleTimer);
        glowState.enableAutoGlow();

        glowState.visibilityTimer = setTimeout(() => {
          glowState.isRenderingStopped = true;
          cancelAnimationFrame(glowState.glowAnimationFrame);

          document.body.style.setProperty('--breathe-opacity', '0');
          document.body.style.setProperty('--reflect-top', '0');
          document.body.style.setProperty('--reflect-bottom', '0');
          document.body.style.setProperty('--reflect-left', '0');
          document.body.style.setProperty('--reflect-right', '0');
        }, 10000);
      } else {
        clearTimeout(glowState.visibilityTimer);

        if (glowState.isRenderingStopped) {
          glowState.isRenderingStopped = false;
          glowState.fadeInPhase = 0;
          glowState.lastFrameTime = Date.now();
          glowState.animateGlow();
        }
      }
    },

    animateGlow() {
      if (glowState.isRenderingStopped) return;

      const now = Date.now();
      const rawDeltaTime = (now - glowState.lastFrameTime) / 1000;
      const deltaTime = Math.min(0.1, rawDeltaTime);
      glowState.lastFrameTime = now;

      const w = window.innerWidth;
      const h = window.innerHeight;

      if (glowState.fadeInPhase < 1) {
        glowState.fadeInPhase += deltaTime / glowState.FADE_IN_DURATION;
        glowState.fadeInPhase = Math.min(glowState.fadeInPhase, 1);
      }

      glowState.colorTransitionPhase += deltaTime / glowState.colorTransitionDuration;
      if (glowState.colorTransitionPhase >= 1) {
        glowState.currentColorIndex = glowState.targetColorIndex;
        glowState.targetColorIndex = glowState.getNextColorIndex(glowState.currentColorIndex);
        glowState.colorTransitionPhase = 0;
        glowState.colorTransitionDuration = 10 + Math.random() * 35;
      }

      glowState.applyGlowColor();

      const breatheSmoothing = deltaTime > 0 ? 1 - Math.exp(-glowState.BREATHE_SMOOTHING_SPEED * deltaTime) : 0;
      if (breatheSmoothing > 0) {
        glowState.breatheMinOpacity += (glowState.targetBreatheMinOpacity - glowState.breatheMinOpacity) * breatheSmoothing;
        glowState.breatheMaxOpacity += (glowState.targetBreatheMaxOpacity - glowState.breatheMaxOpacity) * breatheSmoothing;
        glowState.breatheCycleDuration += (glowState.targetBreatheCycleDuration - glowState.breatheCycleDuration) * breatheSmoothing;
      }

      const safeCycleDuration = Math.max(0.5, glowState.breatheCycleDuration);
      glowState.breathePhase += deltaTime / safeCycleDuration;
      if (glowState.breathePhase >= 1) {
        glowState.breathePhase %= 1;
        glowState.targetBreatheMinOpacity = 0.5 + Math.random() * 0.2;
        glowState.targetBreatheMaxOpacity = 1.0 + Math.random() * 0.2;
        glowState.targetBreatheCycleDuration = 2 + Math.random() * 10;
      }

      glowState.syncBreatheOpacity();

      if (glowState.isAutoGlow) {
        if (glowState.isResting) {
          if (now - glowState.restStartTime >= glowState.currentRestDuration) {
            glowState.isResting = false;
            const newTarget = glowState.getRandomWanderTarget();
            glowState.targetGlowX = newTarget.x;
            glowState.targetGlowY = newTarget.y;
            glowState.currentSpeedX = 0;
            glowState.currentSpeedY = 0;
          }
        } else {
          const result = glowState.moveTowardsTarget(
            glowState.currentGlowX, glowState.currentGlowY,
            glowState.targetGlowX, glowState.targetGlowY,
            deltaTime, glowState.WANDER_ACCELERATION
          );
          if (result.reached) {
            glowState.isResting = true;
            glowState.restStartTime = now;
            glowState.currentRestDuration = Math.random() * 8000;
          }
          glowState.updateGlowPosition(result.x * w, result.y * h);
        }
      } else {
        if (now - glowState.lastMouseSampleTime >= glowState.MOUSE_SAMPLE_INTERVAL) {
          glowState.setMouseTarget(glowState.latestMouseX, glowState.latestMouseY);
          glowState.lastMouseSampleTime = now;
        }
        const result = glowState.moveTowardsTarget(
          glowState.currentGlowX, glowState.currentGlowY,
          glowState.targetGlowX, glowState.targetGlowY,
          deltaTime, glowState.MOUSE_ACCELERATION
        );
        glowState.updateGlowPosition(result.x * w, result.y * h);
      }

      glowState.glowAnimationFrame = requestAnimationFrame(() => glowState.animateGlow());
    }
  };

  // Initialize glow effect
  glowState.breatheCycleDuration = glowState.getRandomBreatheDuration();
  glowState.breatheMinOpacity = glowState.getRandomBreatheMin();
  glowState.breatheMaxOpacity = glowState.getRandomBreatheMax();
  glowState.targetBreatheCycleDuration = glowState.breatheCycleDuration;
  glowState.targetBreatheMinOpacity = glowState.breatheMinOpacity;
  glowState.targetBreatheMaxOpacity = glowState.breatheMaxOpacity;
  glowState.colorTransitionDuration = glowState.getRandomColorTransitionDuration();
  glowState.currentColorIndex = glowState.getRandomColorIndex();
  glowState.targetColorIndex = glowState.getNextColorIndex(glowState.currentColorIndex);
  glowState.initializeGlowState();
  glowState.applyGlowColor();
  glowState.syncBreatheOpacity();
  glowState.lastFrameTime = Date.now();
  glowState.glowAnimationFrame = requestAnimationFrame(() => glowState.animateGlow());

  document.addEventListener('mousemove', (e) => glowState.handleMouseMove(e));
  document.addEventListener('visibilitychange', () => glowState.handleVisibilityChange());

  return {
    logEl: document.getElementById("log"),
    tEl: document.getElementById("t"),
    tsEl: document.getElementById("ts"),
  };
};

const ui = initUi();
const lines = [];
const MAX_VISIBLE_LINES = 6;
document.title = t("title_verifying");

const render = () => {
  const total = lines.length;
  const start = Math.max(0, total - MAX_VISIBLE_LINES);
  const visible = lines.slice(start);
  ui.logEl.innerHTML = visible
    .map((msg) => `<div class="log-line">${msg}</div>`)
    .join("");
};

const log = (msg) => {
  lines.push(msg);
  render();
  return lines.length - 1;
};

const update = (idx, msg) => {
  if (idx < 0 || idx >= lines.length) return;
  lines[idx] = msg;
  render();
};

const setStatus = (ok) => {
  if (ui.tEl && ui.tEl.dataset) {
    ui.tEl.dataset.state = ok ? "success" : "error";
  }
  if (ok) {
    ui.tEl.textContent = t("title_redirecting");
  } else {
    ui.tEl.textContent = t("title_failed");
  }
};

log(t("initializing"));

const getTicketMac = (ticketB64) => {
  const raw = decodeB64Url(String(ticketB64 || ""));
  if (!raw) return null;
  const parts = raw.split(".");
  if (parts.length !== 9 || parts[0] !== "5") return null;
  return parts[8] || null;
};

let turnstilePromise;
let turnstileScript = null;
const loadTurnstile = () => {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (turnstilePromise) return turnstilePromise;
  turnstilePromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    turnstileScript = script;
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.onload = () => {
      turnstileScript = null;
      resolve(window.turnstile);
    };
    script.onerror = () => {
      turnstileScript = null;
      turnstilePromise = null;
      reject(new Error("Turnstile Load Failed"));
    };
    (document.head || document.documentElement).appendChild(script);
  });
  return turnstilePromise;
};

const cancelTurnstileLoad = () => {
  if (!turnstileScript) return;
  const script = turnstileScript;
  turnstileScript = null;
  turnstilePromise = null;
  script.onload = null;
  script.onerror = null;
  try { script.remove(); } catch {}
};

const runTurnstile = async (ticketB64, sitekey, submitToken, tokenState, lifecycle) => {
  lifecycle?.ensureActive();
  const ticketMac = getTicketMac(ticketB64);
  if (!ticketMac) throw new Error("Bad Ticket");
  log(t("loading_turnstile"));
  const removeLoadCleanup = lifecycle?.addCleanup(cancelTurnstileLoad) || (() => {});
  const ts = lifecycle ? await lifecycle.race(loadTurnstile()) : await loadTurnstile();
  removeLoadCleanup();
  lifecycle?.ensureActive();
  if (!ts || typeof ts.render !== "function") {
    throw new Error("Turnstile Missing");
  }
  const el = ui.tsEl;
  if (el) {
    el.innerHTML = "";
  }
  log(t("waiting_turnstile"));
  const container = document.createElement("div");
  const showTurnstile = () => {
    if (!el) return;
    // Force reflow before adding .show class to trigger transition.
    void el.offsetHeight;
    requestAnimationFrame(() => {
      el.classList.add("show");
      el.classList.remove("hide");
    });
  };
  const hideTurnstile = () => {
    if (!el) return;
    el.classList.add("hide");
    el.classList.remove("show");
  };
  if (el) {
    el.appendChild(container);
    hideTurnstile();
  }
  let tokenResolve;
  let tokenReject;
  const nextToken = () =>
    new Promise((resolve, reject) => {
      tokenResolve = resolve;
      tokenReject = reject;
    });
  let tokenPromise = nextToken();
  let widgetId = null;
  let widgetRemoved = false;
  const removeWidget = () => {
    if (widgetRemoved) return;
    hideTurnstile();
    if (el) el.innerHTML = "";
    if (ts && typeof ts.remove === "function" && widgetId !== null) {
      try { ts.remove(widgetId); } catch {}
      widgetRemoved = true;
    }
  };
  if (tokenState) tokenState.widgetCleanup = removeWidget;
  lifecycle?.addCleanup(removeWidget);
  const markTokenExpired = () => {
    if (tokenState && tokenState.token) {
      tokenState.expired = true;
      tokenState.expiresAtMs = monotonicNow();
      if (typeof tokenState.onExpire === "function") tokenState.onExpire();
    }
    if (tokenReject) tokenReject(new Error("Turnstile Expired"));
  };
  try {
    lifecycle?.ensureActive();
    widgetId = ts.render(container, {
      sitekey,
      theme: "dark",
      cData: ticketMac,
      appearance: "interaction-only",
      "before-interactive-callback": showTurnstile,
      "after-interactive-callback": hideTurnstile,
      callback: (t) => {
        if (tokenState) {
          const nextToken = typeof t === "string" ? t : "";
          if (!tokenState.token) {
            tokenState.token = nextToken;
            tokenState.expired = false;
            tokenState.expiresAtMs = monotonicNow() + TURNSTILE_TOKEN_TTL_MS;
            lifecycle?.refreshComputeDeadline();
          } else if (tokenState.token !== nextToken) {
            tokenState.expired = true;
            tokenState.expiresAtMs = monotonicNow();
            if (typeof tokenState.onExpire === "function") tokenState.onExpire();
          }
        }
        hideTurnstile();
        if (tokenResolve) tokenResolve(t);
      },
      "error-callback": () => tokenReject && tokenReject(new Error("Turnstile Failed")),
      "expired-callback": markTokenExpired,
    });
  } catch (e) {
    throw e;
  }
  const maxAttempts = 5;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let token;
    try {
      token = await tokenPromise;
    } catch (e) {
      if (e && e.message === "Turnstile Expired") {
        log(t("turnstile_expired_retry"));
        tokenPromise = nextToken();
        if (ts && typeof ts.reset === "function") ts.reset(widgetId);
        continue;
      }
      throw e;
    }
    hideTurnstile();
    const submitLine = submitToken ? log(t("submitting_turnstile")) : -1;
    try {
      if (submitToken) await submitToken(token);
      if (submitLine !== -1) {
        update(submitLine, t("submitting_turnstile_done", { done: doneMark() }));
      }
      log(t("turnstile_done", { done: doneMark() }));
      if (el && !tokenState) {
        hideTurnstile();
        setTimeout(() => {
          if (el.classList.contains("hide")) {
            el.innerHTML = "";
          }
        }, 400);
      }
      if (!tokenState) removeWidget();
      return token;
    } catch (e) {
      throw e;
    }
  }
  return null;
};

const buildCaptchaEnvelope = (tokens) => {
  const out = {};
  if (tokens && typeof tokens.turnstile === "string" && tokens.turnstile) {
    out.turnstile = tokens.turnstile;
  }
  return JSON.stringify(out);
};

const runCaptcha = async (ticketB64, captchaCfg, submitToken, tokenState, lifecycle) => {
  const hasTurn = Boolean(
    captchaCfg &&
      captchaCfg.turnstile &&
      typeof captchaCfg.turnstile.sitekey === "string" &&
      captchaCfg.turnstile.sitekey
  );
  if (!hasTurn) {
    throw new Error("Turnstile Missing");
  }
  const turnToken = await runTurnstile(
    ticketB64,
    captchaCfg.turnstile.sitekey,
    submitToken
      ? async (token) => submitToken(buildCaptchaEnvelope({ turnstile: token }))
      : undefined,
    tokenState,
    lifecycle,
  );
  if (typeof turnToken !== "string" || !turnToken) throw new Error("Turnstile Failed");
  return buildCaptchaEnvelope({ turnstile: turnToken });
};

const runPowFlow = async ({ apiPrefix, bindingB64, ticketB64, pathHash, eq, esmUrl, captchaToken, lifecycle, tokenState }) => {
  log(t("loading_solver"));
  let spinTimer;
  let spinIndex = -1;
  let spinFrame = 0;
  const spinChars = "|/-\\";
  let latestProgress = null;
  let workerBlobUrl = "";
  let worker = null;
  let rpc = null;
  let assetResponse = null;
  const abortController = typeof AbortController === "function" ? new AbortController() : null;
  const terminate = () => {
    const currentRpc = rpc;
    rpc = null;
    const currentWorker = worker;
    worker = null;
    if (currentRpc) {
      currentRpc.dispose();
      return;
    }
    if (currentWorker) {
      try { currentWorker.terminate(); } catch {}
    }
  };
  const abortAssets = () => {
    try { abortController?.abort(); } catch {}
  };
  const removeAssetCleanup = lifecycle.addCleanup(abortAssets);
  const removeWorkerCleanup = lifecycle.addCleanup(terminate);
  const ensureActive = () => lifecycle.ensureActive();
  try {
    ensureActive();
    let module;
    try {
      module = await lifecycle.race(import(esmUrl));
    } catch (error) {
      if (error?.name === "PowLifecycleError") throw error;
      throw new Error("Solver Missing");
    }
    ensureActive();
    const workerUrl = module && module.workerUrl;
    const solverUrl = module && module.solverUrl;
    if (!workerUrl || !solverUrl) throw new Error("Worker Missing");
    assetResponse = await lifecycle.race(fetch(solverUrl, abortController ? { signal: abortController.signal } : undefined));
    ensureActive();
    if (!assetResponse || assetResponse.ok !== true) throw new Error("Solver Missing");
    const solverWasmBytes = new Uint8Array(await lifecycle.race(assetResponse.arrayBuffer()));
    assetResponse = null;
    ensureActive();
    if (!solverWasmBytes.byteLength) throw new Error("Solver Missing");
    if (!decodeB64Url(String(bindingB64 || ""))) throw new Error("Bad Binding");

    let captchaTag = "any";
    if (captchaToken) {
      let envelope;
      try { envelope = JSON.parse(captchaToken); } catch { throw new Error("Bad Binding"); }
      if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) || typeof envelope.turnstile !== "string") throw new Error("Bad Binding");
      captchaTag = await lifecycle.race(captchaTagV1(envelope.turnstile));
      ensureActive();
    }
    const seed = await lifecycle.race(deriveEquihashSeed(ticketB64, pathHash, captchaTag));
    ensureActive();
    const initialBudgetMs = lifecycle.remainingComputeMs();
    if (initialBudgetMs <= 0) {
      lifecycle.stop("compute");
      ensureActive();
    }

    const ensureSolvingLine = () => {
      if (spinIndex !== -1) return;
      spinIndex = log(formatEquihashProgress({ elapsedMs: 0, remainingMs: lifecycle.remainingComputeMs(), rows: 1, ewmaSolveMs: 0 }));
      spinTimer = setInterval(() => {
        const message = latestProgress ? formatEquihashProgress(latestProgress) : formatEquihashProgress({ elapsedMs: 0, remainingMs: lifecycle.remainingComputeMs(), rows: 1, ewmaSolveMs: 0 });
        update(spinIndex, `${message} <span class="yellow">${spinChars[spinFrame++ % spinChars.length]}</span>`);
      }, 120);
    };
    let workerEntryUrl;
    try { workerEntryUrl = new URL(workerUrl, window.location.href).toString(); } catch { workerEntryUrl = workerUrl; }
    const workerOrigin = originFromLocation({ href: workerEntryUrl });
    const pageOrigin = selfOrigin();
    const makeWorkerBlob = async (sourceUrl) => {
      assetResponse = await lifecycle.race(fetch(sourceUrl, abortController ? { signal: abortController.signal } : undefined));
      ensureActive();
      if (!assetResponse || assetResponse.ok !== true) throw new Error("Worker Missing");
      const workerCode = await lifecycle.race(assetResponse.text());
      assetResponse = null;
      ensureActive();
      if (!URL.createObjectURL) throw new Error("Worker Missing");
      workerBlobUrl = URL.createObjectURL(new Blob([workerCode], { type: "application/javascript" }));
      return workerBlobUrl;
    };
    if (workerOrigin && pageOrigin && workerOrigin !== pageOrigin) {
      workerEntryUrl = await makeWorkerBlob(workerEntryUrl);
    }
    ensureActive();
    try {
      worker = new Worker(workerEntryUrl, { type: "module" });
    } catch (error) {
      if (workerBlobUrl) throw error;
      workerEntryUrl = await makeWorkerBlob(workerEntryUrl);
      worker = new Worker(workerEntryUrl, { type: "module" });
    }
    rpc = createWorkerRpc(worker, (progress) => {
      if (progress.phase === "solve") ensureSolvingLine();
      if (typeof progress.elapsedMs === "number" && typeof progress.remainingMs === "number" && typeof progress.rows === "number" && typeof progress.ewmaSolveMs === "number") latestProgress = progress;
    });
    await lifecycle.race(rpc.call("INIT", {
      n: eq.n,
      k: eq.k,
      solvePolicy: { deadlineMs: initialBudgetMs },
      solverWasmBytes,
    }, [solverWasmBytes.buffer]));
    ensureActive();
    const solveBudgetMs = lifecycle.remainingComputeMs();
    if (solveBudgetMs <= 0) {
      lifecycle.stop("compute");
      ensureActive();
    }
    ensureSolvingLine();
    let solveRes;
    try {
      solveRes = await lifecycle.race(rpc.call("SOLVE", { seed, deadlineMs: solveBudgetMs }));
    } finally {
      lifecycle.disarmComputeDeadline();
    }
    ensureActive();
    if (!solveRes || solveRes.status === "timeout" || solveRes.status === "cancelled") {
      lifecycle.stop("compute");
      ensureActive();
    }
    if (solveRes.status !== "solved" || typeof solveRes.nonceB64 !== "string" || typeof solveRes.proofB64 !== "string") throw new Error("Challenge Failed");
    if (spinTimer) clearInterval(spinTimer);
    if (spinIndex !== -1) update(spinIndex, t("solving_equihash_done", { done: doneMark() }));
    const verifyBody = {
      ticketB64,
      pathHash,
      pow: { nonceB64: solveRes.nonceB64, proofB64: solveRes.proofB64 },
    };
    if (captchaToken) verifyBody.captchaToken = captchaToken;
    const result = await lifecycle.race(postVerify(`${apiPrefix}/verify`, verifyBody, lifecycle));
    ensureActive();
    log(t("pow_done", { done: doneMark() }));
    return result;
  } finally {
    removeAssetCleanup();
    removeWorkerCleanup();
    if (spinTimer) clearInterval(spinTimer);
    terminate();
    if (workerBlobUrl) {
      try { URL.revokeObjectURL(workerBlobUrl); } catch {}
    }
  }
};

export default async function runPow(bootstrapB64, bindingB64, reloadUrlB64, esmUrlB64, captchaCfgB64, atomicCfg) {
  let lifecycle = null;
  let tokenState = null;
  try {
    const bootstrap = parseBootstrap(bootstrapB64);
    if (!bootstrap) throw new Error("Bad Binding");
    const { ticketB64, pathHash, apiPrefix, eq, expireAt } = bootstrap;
    const target = decodeB64Url(String(reloadUrlB64 || "")) || "/";
    const esmUrl = decodeB64Url(String(esmUrlB64 || ""));
    const rawConfig = decodeB64Url(String(captchaCfgB64 || "")) || "";
    let captchaCfg = {};
    try {
      const parsed = rawConfig ? JSON.parse(rawConfig) : {};
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) captchaCfg = parsed;
    } catch {}

    const cfg = parseAtomicCfg(atomicCfg);
    const needPow = Boolean(esmUrl);
    const needTurn = Boolean(captchaCfg.turnstile && typeof captchaCfg.turnstile.sitekey === "string" && captchaCfg.turnstile.sitekey);
    if (!needPow && !needTurn) throw new Error("No Challenge");
    const embedded = window.parent !== window;
    tokenState = needTurn ? createTokenState() : null;
    lifecycle = needPow ? createChallengeLifecycle(expireAt, tokenState) : needTurn ? createChallengeLifecycle(Infinity, tokenState) : null;
    if (lifecycle) {
      if (tokenState) tokenState.onExpire = () => lifecycle.stop("expired");
      lifecycle.ensureActive();
      if (needPow) lifecycle.armComputeDeadline();
    }
    let captchaToken = "";
    if (needTurn) {
      const captcha = runCaptcha(ticketB64, captchaCfg, undefined, tokenState, lifecycle);
      captchaToken = lifecycle ? await lifecycle.race(captcha) : await captcha;
    }
    lifecycle?.ensureActive();
    const state = cfg.atomic && !needPow && needTurn
      ? { ok: true, mode: "direct" }
      : needPow
        ? await runPowFlow({ apiPrefix, bindingB64, ticketB64, pathHash, eq, esmUrl, captchaToken, lifecycle, tokenState })
        : lifecycle
          ? await lifecycle.race(postVerify(`${apiPrefix}/verify`, { ticketB64, pathHash, captchaToken }, lifecycle))
          : await postVerify(`${apiPrefix}/verify`, { ticketB64, pathHash, captchaToken });
    lifecycle?.ensureActive();
    if (cfg.atomic) {
      const consume = state && typeof state.consume === "string" ? state.consume : "";
      if (embedded) {
        const query = {};
        const headers = {};
        if (captchaToken) { query[cfg.q.ts] = captchaToken; headers[cfg.h.ts] = captchaToken; }
        if (ticketB64 && !needPow) { query[cfg.q.tt] = ticketB64; headers[cfg.h.tt] = ticketB64; }
        if (consume) { query[cfg.q.ct] = consume; headers[cfg.h.ct] = consume; }
        postAtomicMessage({ mode: needPow && needTurn ? "combine" : needPow ? "pow" : "turn", captchaToken, ticketB64, consume, headers, query });
        log(t("access_granted_close"));
        setStatus(true);
        document.title = t("title_done");
        return;
      }
      if (needPow && !consume) throw new Error("Consume Missing");
      const query = {};
      if (captchaToken) query[cfg.q.ts] = captchaToken;
      if (ticketB64 && !needPow) query[cfg.q.tt] = ticketB64;
      if (consume) query[cfg.q.ct] = consume;
      const cookieValue = consume ? `1|c|${captchaToken}|${consume}` : `1|t|${captchaToken}|${ticketB64}`;
      const cookiePath = cookiePathForTarget(target);
      if (canUseCookie(cfg.c, cookieValue) && setAtomicCookie(cfg.c, cookieValue, 5, cookiePath)) {
        log(t("access_granted_redirecting", { redirect: yellowMark(t("redirecting")) }));
        setStatus(true);
        document.title = t("title_redirecting");
        window.location.replace(target);
        return;
      }
      window.location.replace(addQuery(target, query));
      return;
    }
    log(t("access_granted_redirecting", { redirect: yellowMark(t("redirecting")) }));
    setStatus(true);
    document.title = t("title_redirecting");
    window.location.replace(target);
  } catch (e) {
    const lifecycleReason = lifecycle?.reason();
    if (lifecycleReason === "teardown") return;
    if (lifecycleReason === "expired" || lifecycleReason === "compute") {
      if (e?.name === "PowLifecycleError" || !isApiError(e)) {
        e = Object.assign(new Error("verify denied: stale"), { name: "ApiError", status: 403, hint: "stale" });
      }
    }
    if (routeHintAction({ status: e && e.status, hint: e && e.hint }).action === "reload") {
      if (shouldAttemptStaleReload()) {
        log(t("session_expired_reload"));
        setTimeout(() => window.location.reload(), 1000);
        return;
      }
      log(t("error_prefix", { message: localizeErrorMessage("Request Failed") }));
      setStatus(false);
      return;
    }
    log(t("error_prefix", { message: localizeErrorMessage(e && e.message ? e.message : String(e)) }));
    setStatus(false);
  } finally {
    if (tokenState?.widgetCleanup) {
      tokenState.widgetCleanup();
      tokenState.widgetCleanup = null;
    }
    lifecycle?.dispose();
  }
}

export { resolveLocale, routeHintAction, translate, getLocale, setLocale, t };
