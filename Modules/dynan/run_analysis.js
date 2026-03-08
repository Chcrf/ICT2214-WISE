#!/usr/bin/env node

const { chromium } = require('playwright');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Load the updated instrumenter
let instrumentWasm = null;
try {
  instrumentWasm = require('./instrument').instrumentWasm;
} catch (e) {
  console.warn('⚠️  instrument.js not found or invalid.');
}
let BROWSER_LOADER = '';
try {
  BROWSER_LOADER = fs.readFileSync(path.join(__dirname, 'analysis.js'), 'utf8');
} catch (e) {
  console.warn('⚠️  analysis.js not found.');
}

const CONFIG = {
  targetUrl: process.env.TARGET_URL || process.argv[2],
  outputDir: process.env.OUTPUT_DIR || path.join(__dirname, 'output'),
  timeout: Number(process.env.ANALYSIS_TIMEOUT_MS || 60000),
  observationTime: Number(process.env.ANALYSIS_OBSERVATION_MS || 60000)
};

if (!CONFIG.targetUrl) {
  console.error('❌ Error: Please provide a TARGET_URL.');
  process.exit(1);
}

fs.mkdirSync(CONFIG.outputDir, { recursive: true });

const reportData = {
  wasm: { patches: [] },
  runs: [],
  networkRuns: []
};

const isWasmMagic = (buffer) => (
  buffer
  && buffer.length >= 4
  && buffer[0] === 0x00
  && buffer[1] === 0x61
  && buffer[2] === 0x73
  && buffer[3] === 0x6d
);

const hashBuffer = (buffer) => (
  crypto.createHash('sha256').update(buffer).digest('hex')
);

/* ------------------ MAIN ANALYSIS LOOP ------------------ */

(async () => {
  try {
    console.log(`Starting analysis: ${CONFIG.targetUrl}`);
    const headless = process.env.HEADLESS !== 'false';

    const extractWasmFromUrl = async (targetUrl, outputDir) => {
      const savedFiles = [];
      const browser = await chromium.launch({ headless: true });
      const context = await browser.newContext({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      });
      const page = await context.newPage();

      page.on('response', async (response) => {
        try {
          const url = response.url();
          if (response.status() === 200) {
            const wasmData = await response.body();
            const isWasmMagic = wasmData.length >= 4
              && wasmData[0] === 0x00
              && wasmData[1] === 0x61
              && wasmData[2] === 0x73
              && wasmData[3] === 0x6d;

            if (!isWasmMagic) {
              return;
            }

            const filename = path.basename(url.split('?')[0]) || 'module.wasm';
            let savePath = path.join(outputDir, filename);

            if (fs.existsSync(savePath)) {
              const uniqueId = Date.now();
              savePath = path.join(outputDir, `${uniqueId}_${filename}`);
            }

            console.log(`[*] Extracting WASM: ${url}`);
            fs.writeFileSync(savePath, wasmData);
            savedFiles.push(savePath);

            console.log(`[*] Saved to: ${savePath} (${wasmData.length} bytes)`);
          }
        } catch (err) {
          console.error(`[X] Response handling error: ${err.message}`);
        }
      });

      console.log(`[!] Navigating to ${targetUrl}...`);
      try {
        await page.goto(targetUrl, { waitUntil: 'networkidle', timeout: CONFIG.timeout });
        console.log('[!] Page loaded. Waiting for delayed WASM executions...');
        await page.waitForTimeout(5000);
      } catch (err) {
        console.error(`[X] Navigation Error: ${err.message}`);
      } finally {
        await browser.close();
        console.log(`[!] Extraction done. ${savedFiles.length} WASM file(s) saved.`);
      }

      return savedFiles;
    };

    const extractedWasmFiles = await extractWasmFromUrl(CONFIG.targetUrl, CONFIG.outputDir);
    console.log(`[WASM Extractor] Extracted ${extractedWasmFiles.length} WASM file(s).`);

    // Browser 1: retrieve original WASM and generate patched wasm + wasabi.js
    // ──────────────────────────────────────────────────────────────
    const instrumentedWasmCache = new Map();
    if (instrumentWasm) {
      const browser1 = await chromium.launch({
        headless,
        args: ['--no-sandbox', '--disable-web-security', '--headless=new']
      });
      const context1 = await browser1.newContext();
      const page1 = await context1.newPage();

      await page1.route('**/*', async route => {
        const url = route.request().url();
        try {
          const response = await route.fetch();
          const originalBuffer = await response.body();
          if (response.status() === 200 && isWasmMagic(originalBuffer)) {
            const hash = hashBuffer(originalBuffer);
            if (!instrumentedWasmCache.has(hash)) {
              const entry = {
                originalBuffer,
                status: response.status(),
                headers: response.headers(),
                originalSize: originalBuffer.length,
                url,
                hash
              };
              instrumentedWasmCache.set(hash, entry);
            }
          }
          await route.fulfill({
            status: response.status(),
            headers: {
              ...response.headers(),
              'Content-Length': originalBuffer.length.toString(),
            },
            body: originalBuffer
          });
        } catch (err) {
          console.error(`⚠️ [Browser1] Failed to retrieve/patch ${url}:`, err.message);
          await route.continue();
        }
      });

      try {
        await page1.goto(CONFIG.targetUrl, {
          waitUntil: 'domcontentloaded',
          timeout: CONFIG.timeout
        });
        await page1.waitForTimeout(2000);
      } catch (err) {
        console.error('⚠️ [Browser1] Navigation warning:', err.message);
      }

      await browser1.close();
      console.log(`[Browser1] Prepared ${instrumentedWasmCache.size} wasm module(s).`);

      for (const [, entry] of instrumentedWasmCache.entries()) {
        try {
          const { binary, glue } = instrumentWasm(entry.originalBuffer);
          entry.binary = binary;
          entry.glue = glue;
          entry.patchedSize = binary.length;

          reportData.wasm.patches.push({
            url: entry.url,
            hash: entry.hash,
            originalSize: entry.originalSize,
            patchedSize: entry.patchedSize,
            timestamp: Date.now()
          });
        } catch (err) {
          console.error(`⚠️ Failed to patch ${entry.url || 'unknown URL'}:`, err.message);
        }
      }
    }

    const serializeInBrowser = () => {
      const raw = (self.Wasabi && self.Wasabi.analysisResult !== undefined)
        ? self.Wasabi.analysisResult
        : null;

      const seen = new WeakSet();
      const serialize = (value) => {
        if (value === null || value === undefined) return value;
        const t = typeof value;
        if (t === 'bigint') return value.toString();
        if (t === 'number' || t === 'string' || t === 'boolean') return value;
        if (t === 'function') return '[Function]';
        if (value instanceof Set) return Array.from(value, serialize);
        if (value instanceof Map) {
          return Array.from(value.entries()).map(([k, v]) => [serialize(k), serialize(v)]);
        }
        if (Array.isArray(value)) return value.map(serialize);
        if (t === 'object') {
          if (seen.has(value)) return '[Circular]';
          seen.add(value);
          const out = {};
          for (const [k, v] of Object.entries(value)) {
            out[k] = serialize(v);
          }
          return out;
        }
        return String(value);
      };

      return serialize(raw);
    };

    const patchTargets = Array.from(instrumentedWasmCache.entries())
      .filter(([, entry]) => entry.binary && entry.glue);

    if (patchTargets.length === 0) {
      console.warn('⚠️ No patched WASM modules available for Browser 2+ runs.');
    }

    // Browser 2 -> first wasm set, Browser 3 -> second wasm set, ...
    for (let runIdx = 0; runIdx < patchTargets.length; runIdx++) {
      const [targetHash, targetEntry] = patchTargets[runIdx];
      const targetUrl = targetEntry.url || '';
      const wasmFileName = targetUrl
        ? (decodeURIComponent(path.basename(new URL(targetUrl).pathname)) || `wasm_${runIdx + 1}.wasm`)
        : `wasm_${runIdx + 1}.wasm`;
      const browserN = await chromium.launch({
        headless,
        args: ['--no-sandbox', '--disable-web-security']
      });

      const contextN = await browserN.newContext();
      const pageN = await contextN.newPage();
      const runLabel = `Browser${runIdx + 2}`;

      const runData = {
        runIndex: runIdx + 1,
        wasmFileName,
        browser: runLabel,
        targetWasmUrl: targetUrl,
        wasm: { logs: [], analysisResult: null },
        console: []
      };

      const runNetwork = {
        runIndex: runIdx + 1,
        wasmFileName,
        browser: runLabel,
        targetWasmUrl: targetUrl,
        requests: [],
        responses: [],
        websockets: []
      };

      await contextN.tracing.start({ screenshots: true, snapshots: true });

      pageN.on('console', msg => {
        if (msg.type() === 'debug') return;
        runData.console.push({
          type: msg.type(),
          text: msg.text(),
          timestamp: Date.now()
        });
      });

      const clientN = await contextN.newCDPSession(pageN);
      await clientN.send('Network.enable');

      clientN.on('Network.requestWillBeSent', ({ requestId, request, timestamp }) => {
        runNetwork.requests.push({
          id: requestId,
          url: request.url,
          method: request.method,
          timestamp
        });
      });

      clientN.on('Network.responseReceived', ({ requestId, response, timestamp }) => {
        runNetwork.responses.push({
          id: requestId,
          url: response.url,
          status: response.status,
          mimeType: response.mimeType,
          timestamp
        });
      });

      clientN.on('Network.webSocketCreated', ({ requestId, url }) => {
        runNetwork.websockets.push({
          id: requestId,
          url,
          event: 'created',
          timestamp: Date.now()
        });
      });

      clientN.on('Network.webSocketFrameSent', ({ requestId, timestamp, response }) => {
        runNetwork.websockets.push({
          id: requestId,
          event: 'frameSent',
          timestamp,
          opcode: response?.opcode,
          payloadData: response?.payloadData
        });
      });

      clientN.on('Network.webSocketFrameReceived', ({ requestId, timestamp, response }) => {
        runNetwork.websockets.push({
          id: requestId,
          event: 'frameReceived',
          timestamp,
          opcode: response?.opcode,
          payloadData: response?.payloadData
        });
      });

      await pageN.addInitScript(({ runtimeJs, loaderJs }) => {
        try {
          const WasabiObj = (0, eval)('(function(){\n' + runtimeJs + '\nreturn (typeof Wasabi !== "undefined") ? Wasabi : self.Wasabi;\n})()');
          if (WasabiObj) self.Wasabi = WasabiObj;
        } catch (e) {
          console.warn('Failed to inject generated wasabi.js:', e && e.message ? e.message : e);
        }

        if (loaderJs) {
          try {
            (0, eval)(loaderJs);
          } catch (e) {
            console.warn('Failed to inject analysis.js:', e && e.message ? e.message : e);
          }
        }
      }, {
        runtimeJs: targetEntry.glue,
        loaderJs: BROWSER_LOADER,
      });

      await pageN.route('**/*', async route => {
        const url = route.request().url();
        try {
          const responseMeta = await route.fetch();
          const responseBody = await responseMeta.body();
          if (responseMeta.status() === 200 && isWasmMagic(responseBody)) {
            const hash = hashBuffer(responseBody);
            if (hash === targetHash) {
              await route.fulfill({
                status: responseMeta.status(),
                body: targetEntry.binary,
                headers: {
                  ...responseMeta.headers(),
                  'Content-Length': targetEntry.binary.length.toString(),
                  'Content-Type': 'application/wasm'
                }
              });
              return;
            }
          }

          await route.fulfill({
            status: responseMeta.status(),
            body: responseBody,
            headers: {
              ...responseMeta.headers(),
              'Content-Length': responseBody.length.toString(),
            }
          });
        } catch (err) {
          console.error(`⚠️ [${runLabel}] Failed to fulfill patched wasm ${url}:`, err.message);
          await route.continue();
        }
      });

      try {
        await pageN.goto(CONFIG.targetUrl, {
          waitUntil: 'domcontentloaded',
          timeout: CONFIG.timeout
        });
        await pageN.waitForTimeout(1000);
        await pageN.waitForTimeout(CONFIG.observationTime);
      } catch (err) {
        console.error(`⚠️ [${runLabel}] Navigation warning:`, err.message);
      }

      try {
        runData.wasm.analysisResult = await pageN.evaluate(serializeInBrowser);
      } catch (err) {
        console.error(`⚠️ [${runLabel}] Failed to extract Wasabi.analysisResult:`, err.message);
      }

      try {
        runData.wasm.logs = await pageN.evaluate(() => self.__WASM_LOGS || []);
      } catch (err) {
        console.error(`⚠️ [${runLabel}] Failed to collect WASM logs:`, err.message);
      }

      const tracePath = path.join(CONFIG.outputDir, `trace_run_${runIdx + 1}.zip`);
      await contextN.tracing.stop({ path: tracePath });

      reportData.runs.push(runData);
      reportData.networkRuns.push(runNetwork);

      await browserN.close();
    }

    // Save reports

    const networkReportPath = path.join(CONFIG.outputDir, 'network_report.json');
    fs.writeFileSync(networkReportPath, JSON.stringify(reportData.networkRuns, null, 2));

    const analysisOnlyReport = {
      wasm: reportData.wasm,
      runs: reportData.runs
    };

    const reportPath = path.join(CONFIG.outputDir, 'analysis_report.json');
    fs.writeFileSync(reportPath, JSON.stringify(analysisOnlyReport, null, 2));
    console.log(`Analysis complete. Reports: ${reportPath}, ${networkReportPath}`);

  } catch (error) {
    console.error('❌ Fatal error during analysis:', error);
    process.exit(1);
  }
})();
