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
// последней проверки. Ту же сводку можно запросить в чате командой /status,
// а скриншоты конечных страниц всех ссылок — командой /screenshots.
//
// Конфиг (ссылки, ключевые слова, интервал, токен, прокси) — в config.json.
// Файл перечитывается на каждом цикле, поэтому правки применяются на лету.
//
// Опции на уровне ссылки (в объекте links[]):
//   keyword        — искомое слово на конечной странице
//   checkKeyword   — false: не проверять ключевое слово (только доступ/статус)
//   validStatuses  — массив допустимых HTTP-статусов, напр. [200, 403];
//                    итоговый статус обязан входить в него, иначе — проблема

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

// Паузы (мс) между попытками отправки: от 3с до 60с. 5 попыток = 4 паузы.
const TELEGRAM_RETRY_DELAYS = [3_000, 8_000, 20_000, 60_000];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function sendTelegram(cfg, text) {
  const { botToken, chatId } = cfg.telegram || {};
  if (!botToken || botToken.startsWith('PASTE') || !chatId || String(chatId).startsWith('PASTE')) {
    log('⚠️  Telegram не настроен (нет botToken/chatId) — сообщение не отправлено:\n' + text);
    return false;
  }
  const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
  const attempts = TELEGRAM_RETRY_DELAYS.length + 1; // 5 попыток

  for (let i = 1; i <= attempts; i++) {
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
        signal: AbortSignal.timeout(30_000),
      });
      if (res.ok) return true;

      const body = await res.text().catch(() => '');
      // 4xx (кроме 429) — постоянная ошибка (битый запрос/нет прав): не повторяем.
      const retriable = res.status === 429 || res.status >= 500;
      log(`⚠️  Telegram API ${res.status}${retriable ? '' : ' (не повторяем)'}: ${body}`);
      if (!retriable) return false;
    } catch (e) {
      // сетевая ошибка/таймаут — повторяемо
      log(`⚠️  Не удалось отправить в Telegram (попытка ${i}/${attempts}): ${e.message}`);
    }

    if (i < attempts) {
      const delay = TELEGRAM_RETRY_DELAYS[i - 1];
      log(`↻ Повтор отправки через ${Math.round(delay / 1000)}с...`);
      await sleep(delay);
    }
  }
  log(`⛔ Не удалось отправить сообщение в Telegram за ${attempts} попыток.`);
  return false;
}

// Отправка фото (скриншота) в Telegram с теми же ретраями, что и текст.
async function sendTelegramPhoto(cfg, buffer, caption) {
  const { botToken, chatId } = cfg.telegram || {};
  if (!botToken || botToken.startsWith('PASTE') || !chatId || String(chatId).startsWith('PASTE')) {
    log('⚠️  Telegram не настроен — фото не отправлено.');
    return false;
  }
  const url = `https://api.telegram.org/bot${botToken}/sendPhoto`;
  const attempts = TELEGRAM_RETRY_DELAYS.length + 1; // 5 попыток

  for (let i = 1; i <= attempts; i++) {
    try {
      // FormData собираем на каждой попытке заново — тело потока одноразовое.
      const form = new FormData();
      form.append('chat_id', String(chatId));
      if (caption) {
        form.append('caption', caption.slice(0, 1024)); // лимит подписи Telegram
        form.append('parse_mode', 'HTML');
      }
      form.append('photo', new Blob([buffer], { type: 'image/jpeg' }), 'shot.jpg');

      const res = await fetch(url, { method: 'POST', body: form, signal: AbortSignal.timeout(60_000) });
      if (res.ok) return true;

      const body = await res.text().catch(() => '');
      const retriable = res.status === 429 || res.status >= 500;
      log(`⚠️  Telegram sendPhoto ${res.status}${retriable ? '' : ' (не повторяем)'}: ${body}`);
      if (!retriable) return false;
    } catch (e) {
      log(`⚠️  Не удалось отправить фото (попытка ${i}/${attempts}): ${e.message}`);
    }

    if (i < attempts) {
      const delay = TELEGRAM_RETRY_DELAYS[i - 1];
      log(`↻ Повтор отправки фото через ${Math.round(delay / 1000)}с...`);
      await sleep(delay);
    }
  }
  log(`⛔ Не удалось отправить фото в Telegram за ${attempts} попыток.`);
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Проверка одной ссылки: цепочка редиректов + поиск ключевого слова
// ─────────────────────────────────────────────────────────────────────────────

// Аргументы запуска Chromium (маскировка автоматизации и т.п.).
const BROWSER_ARGS = [
  '--no-sandbox',
  '--disable-dev-shm-usage',
  '--disable-blink-features=AutomationControlled', // маскировка автоматизации
  '--disable-features=IsolateOrigins,site-per-process',
  '--disable-gpu',
  '--disable-web-security', // может помочь, но осторожно
];

function launchBrowser(cfg) {
  return chromium.launch({ headless: true, proxy: parseProxy(cfg.proxy), args: BROWSER_ARGS });
}

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
  // Проверять ли ключевое слово: по умолчанию да, если оно задано.
  // Отключается на уровне ссылки полем "checkKeyword": false.
  const checkKeyword = link.checkKeyword !== false && keyword.length > 0;
  // Список допустимых HTTP-статусов, напр. [200, 403]. Если задан — итоговый
  // статус обязан входить в него. Если не задан — старое поведение (403 = бан).
  const validStatuses = Array.isArray(link.validStatuses)
    ? link.validStatuses.map(Number).filter((n) => Number.isFinite(n))
    : null;

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

    // Ждём отработки редиректа/рендера. При проверке ключевого слова это же
    // ожидание ищет слово в DOM (переживает JS-редирект на живое зеркало).
    let found = null;
    if (checkKeyword) {
      found = await page
        .waitForFunction(
          (kw) => document.documentElement.innerHTML.toLowerCase().includes(kw),
          keyword,
          { timeout: cfg.settleMs, polling: 1000 }
        )
        .then(() => true)
        .catch(() => false);
    } else {
      await page
        .waitForFunction((h) => location.host !== h, startHost, { timeout: cfg.settleMs })
        .catch(() => {});
      await page.waitForLoadState('load', { timeout: cfg.requestTimeoutMs }).catch(() => {});
    }

    const finalUrl = page.url();
    const lastStatus = chain.length ? chain[chain.length - 1].status : null;

    // 1) Проверка HTTP-статуса по итоговому состоянию.
    if (validStatuses) {
      if (lastStatus != null && !validStatuses.includes(lastStatus)) {
        return {
          ok: false,
          reason: `HTTP ${lastStatus} не входит в допустимые [${validStatuses.join(', ')}]`,
          finalUrl,
          chain,
        };
      }
    } else if (lastStatus === 403) {
      return { ok: false, reason: 'HTTP 403 Forbidden (доступ запрещён)', finalUrl, chain };
    }

    // 2) Проверка ключевого слова (если не отключена).
    if (!checkKeyword) {
      const st = lastStatus != null ? `HTTP ${lastStatus}` : 'доступ есть';
      return { ok: true, reason: `${st} — без проверки ключевого слова`, finalUrl, chain };
    }
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

// Снимок конечной страницы ссылки (после всех редиректов).
// Возвращает { ok, buf, finalUrl, error }.
async function captureLinkScreenshot(link, cfg, browser) {
  const keyword = String(link.keyword || '').toLowerCase();
  const checkKeyword = link.checkKeyword !== false && keyword.length > 0;
  const context = await createBrowserContext(browser, cfg);
  const page = await context.newPage();
  try {
    const startHost = new URL(link.url).host;
    await page.goto(link.url, { waitUntil: 'domcontentloaded', timeout: cfg.requestTimeoutMs });

    // Доводим до конечной точки: ждём ключевое слово или смену хоста (зеркало).
    if (checkKeyword) {
      await page
        .waitForFunction(
          (kw) => document.documentElement.innerHTML.toLowerCase().includes(kw),
          keyword,
          { timeout: cfg.settleMs, polling: 1000 }
        )
        .catch(() => {});
    } else {
      await page
        .waitForFunction((h) => location.host !== h, startHost, { timeout: cfg.settleMs })
        .catch(() => {});
    }
    await page.waitForLoadState('load', { timeout: cfg.requestTimeoutMs }).catch(() => {});

    const buf = await page.screenshot({ type: 'jpeg', quality: 70 }); // видимая область (1280×720)
    return { ok: true, buf, finalUrl: page.url() };
  } catch (e) {
    // даже при ошибке попробуем снять то, что успело отрисоваться
    try {
      const buf = await page.screenshot({ type: 'jpeg', quality: 70 });
      return { ok: true, buf, finalUrl: page.url(), error: String(e.message).split('\n')[0] };
    } catch {}
    return { ok: false, finalUrl: link.url, error: String(e.message).split('\n')[0] };
  } finally {
    await context.close().catch(() => {});
  }
}

// Снять и отправить скриншоты всех ссылок в чат.
async function sendAllScreenshots(cfg) {
  const links = cfg.links || [];
  if (!links.length) {
    await sendTelegram(cfg, 'Нет ссылок для скриншотов.');
    return;
  }
  await sendTelegram(cfg, `📷 Делаю скриншоты (${links.length})…`);
  const browser = await launchBrowser(cfg);
  try {
    for (const link of links) {
      const r = await captureLinkScreenshot(link, cfg, browser);
      if (r.ok && r.buf) {
        await sendTelegramPhoto(cfg, r.buf, `📷 ${tgLink(r.finalUrl, link.name)}`);
      } else {
        await sendTelegram(cfg, `⚠️ ${tgLink(link.url, link.name)} — скриншот не удался: ${escapeHtml(r.error || 'неизвестно')}`);
      }
    }
  } finally {
    await browser.close().catch(() => {});
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

  const browser = await launchBrowser(cfg);

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

// Короткое время в МСК: "DD.MM HH:MM".
function shortMsk(ts) {
  if (!ts) return '—';
  const d = ts === true ? new Date(Date.now() + MSK_OFFSET_MS)
    : new Date(new Date(ts.replace(' ', 'T') + 'Z').getTime() + MSK_OFFSET_MS);
  if (isNaN(d.getTime())) return '—';
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getUTCDate())}.${p(d.getUTCMonth() + 1)} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
}

// Компактная сводка: одна строка на ссылку, время проверки — в шапке.
function buildDailyReport(cfg, state) {
  const lines = [`📊 <b>Статистика</b> · ${shortMsk(true)} МСК`, ''];

  for (const link of cfg.links) {
    const s = state[link.name];
    const name = tgLink(link.url, link.name); // название ведёт на URL ссылки
    lines.push(`${!s ? '⚪️' : s.down ? '❌' : '✅'} ${name}`);
  }

  if (cfg.proxy) {
    const p = state['__proxy__'] || {};
    lines.push('');
    if (p.down) {
      lines.push(`🌐 Прокси: ❌ не работает`);
      if (p.error) lines.push(`   ${escapeHtml(p.error)}`);
    } else {
      const geo = p.ip ? ` — ${escapeHtml(p.ip)} (${escapeHtml(p.country || '?')})` : '';
      lines.push(`🌐 Прокси: ✅ работает${geo}`);
    }
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
// Приём команд из чата: /status — статистика, /screenshots — скриншоты
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
    log('⚠️  Telegram не настроен — команда /status недоступна.');
    return;
  }

  // Пропускаем накопившийся бэклог, чтобы не отвечать на старые сообщения.
  let offset = 0;
  try {
    const init = await tgApi(botToken, 'getUpdates', { offset: -1, timeout: 0 });
    if (init.ok && init.result.length) offset = init.result[init.result.length - 1].update_id + 1;
  } catch {}

  log('🤖 Слушаю команды в чате (/status, /screenshots).');

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
          const text = msg.text.trim();
          if (/^\/status(@\w+)?\b/i.test(text)) {
            const state = await loadState();
            await sendTelegram(cfgNow, buildDailyReport(cfgNow, state));
            log(`📊 Статистика отправлена по команде /status (чат ${from}).`);
          } else if (/^\/screenshots?(@\w+)?\b/i.test(text)) {
            log(`📷 Запрошены скриншоты командой /screenshots (чат ${from}).`);
            await sendAllScreenshots(cfgNow);
            log(`📷 Скриншоты отправлены.`);
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
  pollTelegramCommands(); // приём команд /status и /screenshots из чата
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