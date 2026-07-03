// Автоматический мониторинг рабочих ссылок через RU IP.
// Проходит всю цепочку редиректов и ищет на конечной странице ключевое слово.
// Если слова нет (или сеть недоступна) — домен считается забаненным/выдающим
// заглушку, и в Telegram-чат уходит моментальный алерт.
//
// Запуск:
//   node index.js                 — демон: проверка сразу и далее по интервалу
//   node index.js --once          — один прогон и выход (для теста / cron)
//   node index.js --test-telegram — отправить тестовое сообщение в чат
//   node index.js --check-proxy   — проверить работоспособность прокси
//   node index.js --report        — отправить ежедневную сводку прямо сейчас (тест)
//
// Раз в сутки (по умолчанию 18:00 МСК, настраивается reportHourMsk в config.json)
// демон шлёт в Telegram сводку по каждой ссылке и прокси: статус + время
// последней проверки. Ту же сводку можно запросить в чате командой /stats.
//
// Конфиг (ссылки, ключевые слова, интервал, токен, прокси) — в config.json.
// Файл перечитывается на каждом цикле, поэтому правки применяются на лету.

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { chromium } from 'playwright';
import UserAgent from 'user-agents'; // Добавлено
// Telegram шлём через встроенный в Node global fetch (прокси ему не нужен).

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = join(__dirname, 'config.json');
const STATE_PATH = join(__dirname, 'state.json');

// ─────────────────────────────────────────────────────────────────────────────
// Утилиты
// ─────────────────────────────────────────────────────────────────────────────

const now = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const log = (...a) => console.log(`[${now()}]`, ...a);

// Кешируем один актуальный userAgent на сессию
let cachedUserAgent = null;

function getDefaultUserAgent() {
  if (!cachedUserAgent) {
    try {
      // Генерируем десктопный Chrome-агент с актуальной версией
      const ua = new UserAgent({
        deviceCategory: 'desktop',
        platform: 'Win32',
      });
      cachedUserAgent = ua.toString();
    } catch (e) {
      // fallback
      cachedUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36';
    }
  }
  return cachedUserAgent;
}

// Метки времени в state пишутся через toISOString() → это UTC. Для отчёта
// переводим в МСК (UTC+3, без перехода на летнее время).
const MSK_OFFSET_MS = 3 * 60 * 60 * 1000;
function nowMsk() {
  return new Date(Date.now() + MSK_OFFSET_MS).toISOString().replace('T', ' ').slice(0, 19) + ' МСК';
}
// Строку "YYYY-MM-DD HH:MM:SS" (UTC) → та же строка в МСК с пометкой.
function toMsk(ts) {
  if (!ts) return '—';
  const d = new Date(ts.replace(' ', 'T') + 'Z');
  if (isNaN(d.getTime())) return ts;
  return new Date(d.getTime() + MSK_OFFSET_MS).toISOString().replace('T', ' ').slice(0, 19) + ' МСК';
}

async function loadConfig() {
  const raw = await readFile(CONFIG_PATH, 'utf8');
  const cfg = JSON.parse(raw);
  cfg.intervalMinutes = Number(cfg.intervalMinutes) || 60;
  cfg.reportHourMsk = Number.isFinite(Number(cfg.reportHourMsk)) ? Number(cfg.reportHourMsk) : 18;
  cfg.requestTimeoutMs = Number(cfg.requestTimeoutMs) || 30000;
  cfg.settleMs = Number(cfg.settleMs) || 30000;
  cfg.attempts = Number(cfg.attempts) || 2;
  cfg.maxRedirects = Number(cfg.maxRedirects) || 10;
  if (!Array.isArray(cfg.links)) cfg.links = [];
  // Если в конфиге не задан userAgent, используем автоматический
  if (!cfg.userAgent) {
    cfg.userAgent = getDefaultUserAgent();
  }
  return cfg;
}

async function loadState() {
  try {
    return JSON.parse(await readFile(STATE_PATH, 'utf8'));
  } catch {
    return {}; // { [name]: { down: bool, reason: string, since: iso } }
  }
}

async function saveState(state) {
  await writeFile(STATE_PATH, JSON.stringify(state, null, 2));
}

// ─────────────────────────────────────────────────────────────────────────────
// Telegram
// ─────────────────────────────────────────────────────────────────────────────

async function sendTelegram(cfg, text) {
  const { botToken, chatId } = cfg.telegram || {};
  if (!botToken || botToken.startsWith('PASTE') || !chatId || String(chatId).startsWith('PASTE')) {
    log('⚠️  Telegram не настроен (нет botToken/chatId) — сообщение не отправлено:\n' + text);
    return false;
  }
  const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      }),
    });
    if (!res.ok) {
      log('⚠️  Telegram API вернул ошибку:', res.status, await res.text());
      return false;
    }
    return true;
  } catch (e) {
    log('⚠️  Не удалось отправить в Telegram:', e.message);
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Проверка одной ссылки: цепочка редиректов + поиск ключевого слова
// ─────────────────────────────────────────────────────────────────────────────

// Прокси-строку "http://user:pass@host:port" → формат Playwright.
function parseProxy(proxyUrl) {
  if (!proxyUrl) return undefined;
  const u = new URL(proxyUrl);
  const out = { server: `${u.protocol}//${u.host}` };
  if (u.username) out.username = decodeURIComponent(u.username);
  if (u.password) out.password = decodeURIComponent(u.password);
  return out;
}

// Пред-полётная проверка прокси: реально ли он пропускает трафик и какой
// выходной IP/страна. Запрос идёт через тот же browser (запущен с прокси).
// Возвращает { ok, ip, country, error }.
async function verifyProxy(cfg, browser) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  try {
    // Используем ip-api.com — он показал корректную страну для вашего IP
    const res = await ctx.request.get('http://ip-api.com/json', { timeout: cfg.requestTimeoutMs });
    if (!res.ok()) return { ok: false, error: `HTTP ${res.status()}` };
    const data = await res.json();
    return { ok: true, ip: data.query, country: data.countryCode };
  } catch (e) {
    return { ok: false, error: String(e.message).split('\n')[0] };
  } finally {
    await ctx.close().catch(() => {});
  }
}

// Функция для создания контекста с улучшенной маскировкой (обходит детектирование браузера)
function createBrowserContext(browser, cfg) {
  return browser.newContext({
    userAgent: cfg.userAgent || getDefaultUserAgent(),
    ignoreHTTPSErrors: true,
    locale: 'ru-RU',
    viewport: { width: 1280, height: 720 },
    deviceScaleFactor: 1,
    hasTouch: false,
    isMobile: false,
    extraHTTPHeaders: {
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
      'Accept-Encoding': 'gzip, deflate, br',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-User': '?1',
      'Cache-Control': 'max-age=0',
    },
  });
}

// Проверка одной ссылки через headless-браузер: реально исполняем JS,
// ждём редирект (в т.ч. JS/meta и анти-РКН гейтвеи, выбирающие живое зеркало),
// затем ищем ключевое слово в отрендеренной странице.
// Возвращает { ok, reason, finalUrl, chain }.
async function checkLink(link, cfg, browser) {
  const keyword = String(link.keyword || '').toLowerCase();
  // Используем улучшенный контекст с маскировкой
  const context = await createBrowserContext(browser, cfg);
  const page = await context.newPage();
  const chain = [];
  // Фиксируем маршрут переходов главного фрейма (URL + статус ответа)
  page.on('response', (res) => {
    try {
      const req = res.request();
      if (req.isNavigationRequest() && req.frame() === page.mainFrame()) {
        chain.push({ url: req.url(), status: res.status() });
      }
    } catch {}
  });

  try {
    const startHost = new URL(link.url).host;
    await page.goto(link.url, { waitUntil: 'domcontentloaded', timeout: cfg.requestTimeoutMs });

    // Проверяем статус последнего ответа в цепочке
    if (chain.length > 0) {
      const last = chain[chain.length - 1];
      if (last.status === 403) {
        return {
          ok: false,
          reason: 'HTTP 403 Forbidden (доступ запрещён)',
          finalUrl: page.url(),
          chain,
        };
      }
      // Можно добавить обработку других статусов, если нужно
    }

    if (!keyword) {
      // ключевого слова нет — просто дождёмся возможного редиректа на зеркало
      await page
        .waitForFunction((h) => location.host !== h, startHost, { timeout: cfg.settleMs })
        .catch(() => {});
      await page.waitForLoadState('load', { timeout: cfg.requestTimeoutMs }).catch(() => {});
      return { ok: true, reason: 'ключевое слово не задано — проверен только доступ', finalUrl: page.url(), chain };
    }

    // Ждём появления ключевого слова в DOM (после JS-редиректа и рендера SPA)
    const found = await page
      .waitForFunction(
        (kw) => document.documentElement.innerHTML.toLowerCase().includes(kw),
        keyword,
        { timeout: cfg.settleMs, polling: 1000 }
      )
      .then(() => true)
      .catch(() => false);

    const finalUrl = page.url();
    if (found) {
      return { ok: true, reason: `найдено «${keyword}»`, finalUrl, chain };
    }
    return {
      ok: false,
      reason: `ключевое слово «${keyword}» не найдено за ${Math.round(cfg.settleMs / 1000)}с (вероятно бан/заглушка)`,
      finalUrl,
      chain,
    };
  } catch (e) {
    // таймаут/обрыв/DNS/reset при заходе — типичный признак блокировки на RU IP
    let finalUrl = link.url;
    try { finalUrl = page.url(); } catch {}
    return { ok: false, reason: `ошибка загрузки: ${String(e.message).split('\n')[0]}`, finalUrl, chain };
  } finally {
    await context.close().catch(() => {});
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Один полный цикл проверки всех ссылок
// ─────────────────────────────────────────────────────────────────────────────

function fmtChain(chain) {
  if (!chain || !chain.length) return '';
  return chain.map((h) => `  → ${h.status} ${h.url}`).join('\n');
}

// Кол-во HTTP-редиректов в цепочке (переходов между URL).
function redirectCount(chain) {
  return chain && chain.length > 1 ? chain.length - 1 : 0;
}

async function runCycle(cfg, state) {
  log(`Старт проверки: ${cfg.links.length} ссылок${cfg.proxy ? ' (через прокси)' : ' (прямое соединение / RU IP сервера)'}`);
  let problems = 0;

  const browser = await chromium.launch({
    headless: true,
    proxy: parseProxy(cfg.proxy),
    args: [
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--disable-blink-features=AutomationControlled', // маскировка автоматизации
      '--disable-features=IsolateOrigins,site-per-process',
      '--disable-gpu',
      '--disable-web-security', // может помочь, но осторожно
    ],
  });

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  try {
  // Пред-полётная проверка прокси (если задан)
  if (cfg.proxy) {
    const pr = await verifyProxy(cfg, browser);
    const prevP = state['__proxy__'] || { down: false };
    if (!pr.ok) {
      log(`⛔ Прокси не работает: ${pr.error} — цикл пропущен (иначе ложные алерты по всем ссылкам)`);
      if (!prevP.down) {
        await sendTelegram(
          cfg,
          `⛔ ПРОКСИ НЕ РАБОТАЕТ\n` +
          `Ошибка: ${escapeHtml(pr.error)}`
        );
      }
      state['__proxy__'] = { down: true, since: prevP.since || now(), lastCheck: now(), error: pr.error };
      await saveState(state);
      return 0;
    }
    log(`🌐 Прокси OK — выходной IP ${pr.ip} (${pr.country || '?'})`);
    if (pr.country && pr.country !== 'RU') {
      log(`⚠️  Страна выхода ${pr.country} ≠ RU — блокировки РКН могут быть не видны!`);
    }
    if (prevP.down) {
      await sendTelegram(
        cfg,
        `✅ ПРОКСИ ВОССТАНОВЛЕН\n` +
        `IP: ${escapeHtml(pr.ip)} (${escapeHtml(pr.country || '?')})`
      );
    }
    state['__proxy__'] = { down: false, since: prevP.down ? now() : (prevP.since || now()), lastCheck: now(), ip: pr.ip, country: pr.country };
  }

  for (const link of cfg.links) {
    // Анти-флейк: перепроверяем несколько раз перед тем как считать ссылку упавшей
    let result;
    for (let attempt = 1; attempt <= cfg.attempts; attempt++) {
      result = await checkLink(link, cfg, browser);
      if (result.ok) break;
      if (attempt < cfg.attempts) {
        log(`↻ ${link.name}: попытка ${attempt}/${cfg.attempts} не удалась — повтор...`);
        await sleep(3000);
      }
    }
    const prev = state[link.name] || { down: false };

    if (result.ok) {
      log(`✅ ${link.name}: OK — ${result.reason} [редиректов: ${redirectCount(result.chain)}]`);
      if (prev.down && cfg.alertOnRecovery) {
        await sendTelegram(
          cfg,
          `✅ <b>ВОССТАНОВЛЕНО: ${escapeHtml(link.name)}</b>\n` +
          `URL: ${tgLink(link.url)}` 
        );
      }
      state[link.name] = { down: false, reason: result.reason, since: prev.down ? now() : (prev.since || now()), lastCheck: now(), url: link.url };
    } else {
      problems++;
      log(`❌ ${link.name}: ПРОБЛЕМА — ${result.reason} [редиректов: ${redirectCount(result.chain)}]`);
      if (!prev.down) {
        await sendTelegram(
          cfg,
          `🚨 <b>ПРОБЛЕМА: ${escapeHtml(link.name)}</b>\n` +
          `Причина: ${escapeHtml(result.reason)}\n` +
          `URL: ${tgLink(link.url)}\n` +
          (result.finalUrl && result.finalUrl !== link.url
            ? `Конечный URL: ${tgLink(result.finalUrl)}\n`
            : '') +
          `Редиректов: ${redirectCount(result.chain)}`
        );
        state[link.name] = { down: true, reason: result.reason, since: now(), lastCheck: now(), url: link.url };
      } else {
        // всё ещё лежит — не дублируем алерт, только обновляем причину
        state[link.name] = { down: true, reason: result.reason, since: prev.since, lastCheck: now(), url: link.url };
      }
    }
    if (result.chain && result.chain.length > 1) {
      log(`   цепочка:\n${fmtChain(result.chain)}`);
    }
  }
  } finally {
    await browser.close().catch(() => {});
  }

  await saveState(state);
  log(`Проверка завершена. Проблем: ${problems}/${cfg.links.length}`);
  return problems;
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeAttr(s) {
  return escapeHtml(s).replace(/"/g, '&quot;');
}

function tgLink(url, text = 'ссылка') {
  return `<a href="${escapeAttr(url)}">${escapeHtml(text)}</a>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Ежедневный отчёт по всем ссылкам и прокси (по умолчанию 18:00 МСК)
// ─────────────────────────────────────────────────────────────────────────────

// Сколько миллисекунд до ближайшего наступления hour:00 по МСК (UTC+3).
function msUntilNextMskHour(hour) {
  const nowMs = Date.now();
  const target = new Date(nowMs);
  target.setUTCHours(hour - 3, 0, 0, 0); // hour по МСК = (hour-3) по UTC
  if (target.getTime() <= nowMs) target.setUTCDate(target.getUTCDate() + 1);
  return target.getTime() - nowMs;
}

// Текст ежедневной сводки: статус, причина и время последней проверки
// по каждой ссылке и по прокси.
function buildDailyReport(cfg, state) {
  const lines = [`📊 <b>Ежедневная статистика</b>`, `Отчёт: ${nowMsk()}`, ''];

  if (cfg.proxy) {
    const p = state['__proxy__'] || {};
    const st = p.down ? '⛔ не работает' : '🌐 работает';
    const extra = p.down
      ? (p.error ? ` (${escapeHtml(p.error)})` : '')
      : (p.ip ? ` — IP ${escapeHtml(p.ip)} (${escapeHtml(p.country || '?')})` : '');
    lines.push(`<b>Прокси:</b> ${st}${extra}`);
    lines.push(`  Последняя проверка: ${toMsk(p.lastCheck)}`);
    lines.push('');
  }

  lines.push(`<b>Ссылки (${cfg.links.length}):</b>`);
  for (const link of cfg.links) {
    const s = state[link.name];
    if (!s) {
      lines.push(`❔ ${escapeHtml(link.name)} — ещё не проверялась`);
      continue;
    }
    const st = s.down ? '❌ не работает' : '✅ работает';
    lines.push(`${st} <b>${escapeHtml(link.name)}</b>`);
    if (s.reason) lines.push(`  ${escapeHtml(s.reason)}`);
    lines.push(`  Последняя проверка: ${toMsk(s.lastCheck || s.since)}`);
  }

  return lines.join('\n');
}

async function sendDailyReport(cfg, state) {
  const ok = await sendTelegram(cfg, buildDailyReport(cfg, state));
  log(ok ? '📊 Ежедневный отчёт отправлен.' : '⚠️  Не удалось отправить ежедневный отчёт.');
  return ok;
}

// Самопланирующийся таймер: шлёт отчёт каждый день в reportHourMsk:00 по МСК.
function scheduleDailyReport() {
  const schedule = async () => {
    const cfgPeek = await loadConfig().catch(() => ({}));
    const hour = Number.isFinite(Number(cfgPeek.reportHourMsk)) ? Number(cfgPeek.reportHourMsk) : 18;
    const wait = msUntilNextMskHour(hour);
    log(`Следующий ежедневный отчёт через ${Math.round(wait / 60000)} мин (в ${hour}:00 МСК).`);
    setTimeout(async () => {
      try {
        const cfg = await loadConfig();
        const state = await loadState();
        await sendDailyReport(cfg, state);
      } catch (e) {
        log('⚠️  Ошибка при отправке ежедневного отчёта:', e.message);
      }
      schedule(); // запланировать следующий день
    }, wait);
  };
  schedule();
}

// ─────────────────────────────────────────────────────────────────────────────
// Приём команд из чата: /stats — прислать статистику по запросу
// (long polling через getUpdates; отвечаем только в настроенный chatId)
// ─────────────────────────────────────────────────────────────────────────────

async function tgApi(botToken, method, params) {
  const url = `https://api.telegram.org/bot${botToken}/${method}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(params || {}),
    signal: AbortSignal.timeout(35_000),
  });
  return res.json();
}

async function pollTelegramCommands() {
  let cfg;
  try {
    cfg = await loadConfig();
  } catch {
    setTimeout(pollTelegramCommands, 30_000);
    return;
  }
  const { botToken } = cfg.telegram || {};
  if (!botToken || botToken.startsWith('PASTE')) {
    log('⚠️  Telegram не настроен — команда /stats недоступна.');
    return;
  }

  // Пропускаем накопившийся бэклог, чтобы не отвечать на старые сообщения.
  let offset = 0;
  try {
    const init = await tgApi(botToken, 'getUpdates', { offset: -1, timeout: 0 });
    if (init.ok && init.result.length) offset = init.result[init.result.length - 1].update_id + 1;
  } catch {}

  log('🤖 Слушаю команды в чате (/stats).');

  const loop = async () => {
    let cfgNow;
    try {
      cfgNow = await loadConfig(); // перечитываем — chatId/токен могли поменяться
    } catch {
      setTimeout(loop, 5_000);
      return;
    }
    const token = cfgNow.telegram?.botToken;
    const chatId = String(cfgNow.telegram?.chatId || '');
    try {
      const data = await tgApi(token, 'getUpdates', { offset, timeout: 30 });
      if (data.ok) {
        for (const upd of data.result) {
          offset = upd.update_id + 1;
          const msg = upd.message || upd.channel_post;
          if (!msg || !msg.text) continue;
          const from = String(msg.chat?.id || '');
          if (chatId && from !== chatId) continue; // отвечаем только в свой чат
          if (/^\/stats(@\w+)?\b/i.test(msg.text.trim())) {
            const state = await loadState();
            await sendTelegram(cfgNow, buildDailyReport(cfgNow, state));
            log(`📊 Статистика отправлена по команде /stats (чат ${from}).`);
          }
        }
      }
    } catch (e) {
      log('⚠️  Ошибка опроса Telegram:', String(e.message).split('\n')[0]);
      await new Promise((r) => setTimeout(r, 5_000));
    }
    setTimeout(loop, 500);
  };
  loop();
}

// ─────────────────────────────────────────────────────────────────────────────
// Планировщик (динамический интервал из конфига)
// ─────────────────────────────────────────────────────────────────────────────

async function daemon() {
  let timer = null;
  const tick = async () => {
    let cfg;
    try {
      cfg = await loadConfig();
    } catch (e) {
      log('⚠️  Ошибка чтения config.json:', e.message);
      timer = setTimeout(tick, 60_000);
      return;
    }
    const state = await loadState();
    try {
      await runCycle(cfg, state);
    } catch (e) {
      log('⚠️  Сбой цикла проверки:', e.message);
    }
    const ms = cfg.intervalMinutes * 60_000;
    log(`Следующая проверка через ${cfg.intervalMinutes} мин.`);
    timer = setTimeout(tick, ms);
  };

  process.on('SIGINT', () => {
    if (timer) clearTimeout(timer);
    log('Остановлено.');
    process.exit(0);
  });

  scheduleDailyReport(); // ежедневная сводка в reportHourMsk:00 МСК (по умолчанию 18:00)
  pollTelegramCommands(); // приём команды /stats из чата
  await tick();
}

// ─────────────────────────────────────────────────────────────────────────────
// Точка входа
// ─────────────────────────────────────────────────────────────────────────────

const arg = process.argv[2];

if (arg === '--test-telegram') {
  const cfg = await loadConfig();
  const ok = await sendTelegram(cfg, `🔔 Тест мониторинга ссылок. ${now()}`);
  log(ok ? 'Тестовое сообщение отправлено.' : 'Отправка не удалась (проверь токен/chatId).');
  process.exit(ok ? 0 : 1);
} else if (arg === '--check-proxy') {
  const cfg = await loadConfig();
  if (!cfg.proxy) {
    log('Прокси не задан (proxy пустой) — используется прямое соединение / RU IP сервера.');
    process.exit(0);
  }
  const browser = await chromium.launch({
    headless: true,
    proxy: parseProxy(cfg.proxy),
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-blink-features=AutomationControlled'],
  });
  try {
    const pr = await verifyProxy(cfg, browser);
    if (pr.ok) {
      log(`✅ Прокси работает — выходной IP ${pr.ip} (${pr.country || '?'})`);
      if (pr.country && pr.country !== 'RU') log(`⚠️  Страна ${pr.country} ≠ RU — блокировки РКН могут быть не видны!`);
      process.exitCode = 0;
    } else {
      log(`❌ Прокси не работает: ${pr.error}`);
      process.exitCode = 1;
    }
  } finally {
    await browser.close().catch(() => {});
  }
} else if (arg === '--report') {
  const cfg = await loadConfig();
  const state = await loadState();
  const ok = await sendDailyReport(cfg, state);
  process.exit(ok ? 0 : 1);
} else if (arg === '--once') {
  const cfg = await loadConfig();
  const state = await loadState();
  const problems = await runCycle(cfg, state);
  process.exit(problems > 0 ? 1 : 0);
} else {
  await daemon();
}