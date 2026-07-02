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

async function loadConfig() {
  const raw = await readFile(CONFIG_PATH, 'utf8');
  const cfg = JSON.parse(raw);
  cfg.intervalMinutes = Number(cfg.intervalMinutes) || 60;
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
          `Ошибка: ${escapeHtml(pr.error)}\n\n` +
          `Время: ${now()}`
        );
      }
      state['__proxy__'] = { down: true, since: prevP.since || now() };
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
        `IP: ${escapeHtml(pr.ip)} (${escapeHtml(pr.country || '?')})\n\n` +
        `Время: ${now()}`
      );
    }
    state['__proxy__'] = { down: false, since: now() };
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
          `URL: ${tgLink(link.url)}\n\n` +
          `Время: ${now()}`
        );
      }
      state[link.name] = { down: false, reason: result.reason, since: now() };
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
          `Редиректов: ${redirectCount(result.chain)}\n\n` +
          `Время: ${now()}`
        );
        state[link.name] = { down: true, reason: result.reason, since: now() };
      } else {
        state[link.name] = { down: true, reason: result.reason, since: prev.since };
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
// Планировщик
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
} else if (arg === '--once') {
  const cfg = await loadConfig();
  const state = await loadState();
  const problems = await runCycle(cfg, state);
  process.exit(problems > 0 ? 1 : 0);
} else {
  await daemon();
}