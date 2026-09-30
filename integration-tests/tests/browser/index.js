const puppeteer = require('puppeteer');
const ms = require('ms');
const consola = require('consola');
const { exit } = require('process');

// Check environment variables
const URLs = (process.env.URLs || 'https://www.bbc.com,https://www.google.com,https://www.theguardian.com/europe,https://adguard.com/').split(',');
const TIME_LIMIT = process.env.TIME_LIMIT || '120s';
const VERBOSE = process.env.VERBOSE === 'true';
const OUTPUT_FILE = process.env.OUTPUT_FILE || 'output.json';
// A failed navigation may be a transient hiccup, so retry it; the run fails when
// the failure count reaches its threshold or the failure ratio exceeds it. The
// retry ratio guards the opposite case: a bug that makes the first attempt fail
// systematically would otherwise be hidden by the retries.
const NAVIGATION_RETRIES = parseInt(process.env.NAVIGATION_RETRIES || '3', 10);
const NAVIGATION_TIMEOUT_MS = parseInt(process.env.NAVIGATION_TIMEOUT_MS || '60000', 10);
const MAX_NAVIGATION_FAILURES = parseInt(process.env.MAX_NAVIGATION_FAILURES || '3', 10);
const MAX_NAVIGATION_FAILURE_RATIO = parseFloat(process.env.MAX_NAVIGATION_FAILURE_RATIO || '0.1');
const MAX_NAVIGATION_RETRY_RATIO = parseFloat(process.env.MAX_NAVIGATION_RETRY_RATIO || '0.25');
// A retry is a weak signal, so the ratio is only judged with enough samples:
// in a short run a single retry would otherwise trip the gate.
const MIN_NAVIGATIONS_FOR_RATIO = parseInt(process.env.MIN_NAVIGATIONS_FOR_RATIO || '10', 10);


// Enable debug-level logging if VERBOSE is enabled
if (VERBOSE) {
  consola.level = 4;
}

consola.info(`Script started with configuration: 
URLs: ${URLs}
TIME_LIMIT: ${TIME_LIMIT}
VERBOSE: ${VERBOSE}
OUTPUT_FILE: ${OUTPUT_FILE}
NAVIGATION_RETRIES: ${NAVIGATION_RETRIES}
NAVIGATION_TIMEOUT_MS: ${NAVIGATION_TIMEOUT_MS}
MAX_NAVIGATION_FAILURES: ${MAX_NAVIGATION_FAILURES}
MAX_NAVIGATION_FAILURE_RATIO: ${MAX_NAVIGATION_FAILURE_RATIO}
MAX_NAVIGATION_RETRY_RATIO: ${MAX_NAVIGATION_RETRY_RATIO}
MIN_NAVIGATIONS_FOR_RATIO: ${MIN_NAVIGATIONS_FOR_RATIO}`);

// Core logic
(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    defaultViewport: null,
    dumpio: true,
    timeout: 30000,
    args: [
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-setuid-sandbox',
      '--no-first-run',
      '--no-sandbox',
      '--no-zygote',
      '--deterministic-fetch',
      '--disable-features=IsolateOrigins',
      '--disable-site-isolation-trials',
  ]
  });
  const stats = {};
  let navigationFailures = 0;
  let navigationRetries = 0;
  let activeReloads = 0;

  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  for (let url of URLs) {
    let page = await browser.newPage();

    // Initialize stats for URL
    stats[url] = {
      reloadsCount: 0,
      navigationRetries: 0,
      navigationFailures: 0,
      requestsCount: 0,
      errorsCount: 0,
      duration: {
        total: 0,
        avg: 0
      }
    };

    page.on('request', (request) => {
      consola.debug(`Starting request: ${request.url()}`);
    });

    page.on('requestfinished', (request) => {
      let duration = NaN;
      if (request.response().timing() != null) {
        duration =
          request.response().timing().receiveHeadersEnd -
          request.response().timing().sendStart;
          stats[url].requestsCount += 1;
      stats[url].duration.total += duration;
      stats[url].duration.avg = stats[url].duration.total / stats[url].requestsCount;
      consola.debug(`Finished request: ${request.url()} - Duration: ${duration}ms`);
      }
    });

    page.on('requestfailed', (request) => {
      const failureInfo = request.failure();
      if (failureInfo) {
        consola.warn(`Request failed: ${request.url()} - Error: ${failureInfo.errorText}`);
      } else {
        consola.warn(`Request failed: ${request.url()} - No error text available`);
      }
      stats[url].errorsCount += 1;
    });

    // Periodically reload the page with a random delay

    const gotoWithRetry = async (targetUrl) => {
      let lastError;
      for (let attempt = 1; attempt <= NAVIGATION_RETRIES; attempt++) {
        try {
          await page.goto(targetUrl, { timeout: NAVIGATION_TIMEOUT_MS });
          return attempt;
        } catch (error) {
          lastError = error;
          if (attempt < NAVIGATION_RETRIES) {
            const backoffMs = Math.min(2000, 500 * 2 ** (attempt - 1));
            consola.warn(`Navigation to ${targetUrl} failed (attempt ${attempt}/${NAVIGATION_RETRIES}): ${error.message}. Retrying in ${backoffMs}ms`);
            await sleep(backoffMs);
          }
        }
      }
      throw lastError;
    };

    const reloadPage = async () => {
      try {
        activeReloads++;
        const attemptsUsed = await gotoWithRetry(url);
        if (attemptsUsed > 1) {
          navigationRetries++;
          stats[url].navigationRetries++;
        }
      } catch (error) {
        navigationFailures++;
        stats[url].navigationFailures++;
        consola.error(`Error while reloading ${url} after ${NAVIGATION_RETRIES} attempts: ${error.message}`);
        consola.error(error.stack);
      } finally {
        activeReloads--;
      }
      stats[url].reloadsCount += 1;
      consola.info(`Reloaded tab for: ${url}`);
      setTimeout(reloadPage, Math.floor(Math.random() * (300000 - 5000) + 5000));
    };

    reloadPage();
    await sleep(5000);
  }

  // Save statistics after the specified time
  setTimeout(async () => {
    while (activeReloads > 0) {
      await sleep(100);
    }

    const totalNavigations = Object.values(stats).reduce((sum, urlStats) => sum + urlStats.reloadsCount, 0);
    const failureRatio = totalNavigations > 0 ? navigationFailures / totalNavigations : 0;
    const retryRatio = totalNavigations > 0 ? navigationRetries / totalNavigations : 0;
    const retryRatioJudged = totalNavigations >= MIN_NAVIGATIONS_FOR_RATIO;
    const thresholdsExceeded = navigationFailures >= MAX_NAVIGATION_FAILURES ||
      failureRatio > MAX_NAVIGATION_FAILURE_RATIO ||
      (retryRatioJudged && retryRatio > MAX_NAVIGATION_RETRY_RATIO);

    await browser.close();
    require('fs').writeFileSync(OUTPUT_FILE, JSON.stringify({
      configuration: {
        URLs, TIME_LIMIT, VERBOSE, OUTPUT_FILE,
        NAVIGATION_RETRIES, NAVIGATION_TIMEOUT_MS,
        MAX_NAVIGATION_FAILURES, MAX_NAVIGATION_FAILURE_RATIO, MAX_NAVIGATION_RETRY_RATIO,
        MIN_NAVIGATIONS_FOR_RATIO
      },
      summary: {
        totalNavigations,
        navigationFailures,
        navigationRetries,
        failureRatio,
        retryRatio,
        retryRatioJudged
      },
      statistics: stats
    }, null, 2));
    consola.info(`Script finished. Output written to: ${OUTPUT_FILE}`);
    consola.info(`Navigation summary: ${navigationFailures}/${totalNavigations} failed (ratio ${failureRatio.toFixed(4)}), ${navigationRetries}/${totalNavigations} needed a retry (ratio ${retryRatio.toFixed(4)}); thresholds: count >= ${MAX_NAVIGATION_FAILURES}, failure ratio > ${MAX_NAVIGATION_FAILURE_RATIO}, retry ratio > ${MAX_NAVIGATION_RETRY_RATIO}`);

    if (retryRatioJudged && retryRatio > MAX_NAVIGATION_RETRY_RATIO) {
      consola.error(`Too many navigations needed a retry: ${navigationRetries}/${totalNavigations} (ratio ${retryRatio.toFixed(4)}), the first attempt fails systematically`);
    }
    if (thresholdsExceeded) {
      consola.error('Navigation failure thresholds exceeded');
      exit(1);
    } else {
      exit(0);
    }
  }, ms(TIME_LIMIT));

})();
