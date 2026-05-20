// Cert-plan orchestrator: drives an entire OpenID conformance RP test plan
// end-to-end against https://www.certification.openid.net via its REST API.
//
// Workflow per module:
//   1. POST /api/runner?test=<moduleName>&plan=<planId>     → create test (alias rotates to it)
//   2. Poll GET /api/runner/{id} until status = "WAITING"
//   3. Spawn `node dist/index.js <cli-cmd>` → captures stdout/stderr to client-logs/<moduleName>.log
//   4. Poll GET /api/runner/{id} until status ∈ {FINISHED, INTERRUPTED}
//   5. Move on.
// At the end: zip client-logs/ → optionally POST /api/plan/{id}/certificationpackage with the zip.
//
// Usage:
//   node dist/orchestrate-cert.js --plan-id <id> --token <api-token> [--only <name>] [--upload]
// Or via env:
//   SUITE_TOKEN=<token> node dist/orchestrate-cert.js --plan-id <id> [--upload]

import axios, { AxiosInstance } from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import * as child_process from 'child_process';
import FormData from 'form-data';
import * as dotenv from 'dotenv';

dotenv.config();

const SUITE_BASE = process.env.SUITE_BASE || 'https://www.certification.openid.net';
const LOG_DIR = path.resolve(process.cwd(), 'client-logs');
const ZIP_NAME = path.resolve(process.cwd(), 'client-logs.zip');

// --- args -----------------------------------------------------------------
const args = process.argv.slice(2);
let planId = process.env.SUITE_PLAN_ID || '';
let token = process.env.SUITE_TOKEN || '';
let only = '';
let uploadPackage = false;
let dryRun = false;

for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--plan-id') planId = args[++i];
    else if (a === '--token') token = args[++i];
    else if (a === '--only') only = args[++i];
    else if (a === '--upload') uploadPackage = true;
    else if (a === '--dry-run') dryRun = true;
    else if (a === '-h' || a === '--help') { usage(); process.exit(0); }
}

function usage() {
    console.log('Usage:');
    console.log('  node dist/orchestrate-cert.js --plan-id <id> --token <api-token> [--only <name>] [--upload] [--dry-run]');
    console.log('');
    console.log('Env:');
    console.log('  SUITE_TOKEN   alternative to --token');
    console.log('  SUITE_BASE    override suite base URL (default: https://www.certification.openid.net)');
}

if (!planId || !token) { usage(); process.exit(1); }

// --- mapping: OpenID module name → local CLI subcommand ------------------
// Keep this aligned with src/index.ts processArgs() and run-conformance-logs.sh TESTS array.
const MODULE_TO_CLI: Record<string, string> = {
    'fapi1-advanced-final-client-test': 'happy-path',
    'fapi1-advanced-final-client-test-invalid-iss': 'invalid-issuer',
    'fapi1-advanced-final-client-test-invalid-missing-iss': 'invalid-missing-iss',
    'fapi1-advanced-final-client-test-discovery-issuer-mismatch': 'discovery-issuer-mismatch',
    'fapi1-advanced-final-client-test-invalid-aud': 'invalid-audience',
    'fapi1-advanced-final-client-test-invalid-missing-aud': 'invalid-missing-aud',
    'fapi1-advanced-final-client-test-invalid-secondary-aud': 'invalid-secondary-aud',
    'fapi1-advanced-final-client-test-invalid-signature': 'invalid-signature',
    'fapi1-advanced-final-client-test-invalid-null-alg': 'invalid-null-alg',
    'fapi1-advanced-final-client-test-invalid-alternate-alg': 'invalid-alternate-alg',
    'fapi1-advanced-final-client-test-invalid-expired-exp': 'invalid-expired-exp',
    'fapi1-advanced-final-client-test-invalid-missing-exp': 'invalid-missing-exp',
    'fapi1-advanced-final-client-test-iat-is-week-in-past': 'iat-is-week-in-past',
    'fapi1-advanced-final-client-test-invalid-shash': 'invalid-shash',
    'fapi1-advanced-final-client-test-invalid-missing-shash': 'invalid-missing-shash',
    'fapi1-advanced-final-client-test-invalid-chash': 'invalid-chash',
    'fapi1-advanced-final-client-test-invalid-nonce': 'invalid-nonce',
    'fapi1-advanced-final-client-test-invalid-missing-nonce': 'invalid-missing-nonce',
    'fapi1-advanced-final-client-test-missing-athash': 'missing-at-hash',
    'fapi1-advanced-final-client-test-valid-aud-as-array': 'aud-as-array',
    'fapi1-advanced-final-client-test-no-scope-in-token-endpoint-response': 'no-scope',
    'fapi1-advanced-final-client-test-token-response-missing-fields': 'missing-fields',
    'fapi1-advanced-final-client-test-encrypted-idtoken': 'encrypted-idtoken',
    'fapi1-advanced-final-client-test-encrypted-idtoken-usingrsa15': 'encrypted-rsa15',
    'fapi1-advanced-final-client-refresh-token-test': 'refresh-token'
};

// --- API client -----------------------------------------------------------
// IMPORTANT: do NOT put Content-Type in the global defaults — when we POST
// without a body (creating a test from a plan), any Content-Type makes the
// server think we're sending a config and respond 400.
const api: AxiosInstance = axios.create({
    baseURL: SUITE_BASE,
    headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json'
    },
    validateStatus: () => true
});

// Shorten huge Java stack traces in error messages so they're readable.
function compactErr(data: any): string {
    if (data == null || data === '') return '(empty response body)';
    let s: string;
    if (typeof data === 'string') s = data;
    else {
        try {
            const copy = JSON.parse(JSON.stringify(data));
            if (copy && typeof copy === 'object' && typeof copy.trace === 'string') {
                copy.trace = copy.trace.split('\n').slice(0, 2).join(' | ') + ' …(truncated)';
            }
            s = JSON.stringify(copy);
        } catch {
            s = String(data);
        }
    }
    return s.length > 800 ? s.slice(0, 800) + '…' : s;
}

async function getPlan(): Promise<any> {
    const r = await api.get(`/api/plan/${encodeURIComponent(planId)}`);
    if (r.status !== 200) throw new Error(`GET /api/plan/${planId} → ${r.status} ${compactErr(r.data)}`);
    return r.data;
}

async function createTest(moduleName: string, variant?: any): Promise<string> {
    const q: string[] = [`test=${encodeURIComponent(moduleName)}`, `plan=${encodeURIComponent(planId)}`];
    if (variant) q.push(`variant=${encodeURIComponent(typeof variant === 'string' ? variant : JSON.stringify(variant))}`);
    const url = `${SUITE_BASE}/api/runner?${q.join('&')}`;
    // Use native fetch — it sends no body and no Content-Type for a POST with no
    // body, which matches the OpenID Foundation's own run-test-plan.py reference.
    // Axios would default Content-Type to application/x-www-form-urlencoded here,
    // which the suite rejects with 415.
    const resp = await fetch(url, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/json'
        }
    });
    const text = await resp.text();
    if (resp.status !== 201) {
        throw new Error(`POST /api/runner → ${resp.status} ${compactErr(text || '(empty)')}`);
    }
    let body: any;
    try { body = JSON.parse(text); } catch { body = text; }
    if (!body?.id) throw new Error(`POST /api/runner returned no id: ${compactErr(text)}`);
    return body.id;
}

async function getTestInfo(testId: string): Promise<any> {
    const r = await api.get(`/api/info/${encodeURIComponent(testId)}`);
    if (r.status === 200) return r.data;
    if (r.status === 404) return { status: 'NOT_FOUND' };
    throw new Error(`GET /api/info/${testId} → ${r.status} ${compactErr(r.data)}`);
}

async function pollUntil(testId: string, want: string[], timeoutMs: number): Promise<any> {
    const deadline = Date.now() + timeoutMs;
    let firstSeen = true;
    let lastStatus = '';
    let errorCount = 0;
    while (Date.now() < deadline) {
        let s: any = null;
        try {
            s = await getTestInfo(testId);
        } catch (e: any) {
            errorCount++;
            if (errorCount <= 3) console.log(`   [poll] error: ${e?.message || e}`);
            await sleep(1500);
            continue;
        }
        const status = s?.status || s?.testStatus || s?.state || '';
        const statusUpper = String(status).toUpperCase();
        if (firstSeen) {
            const keys = s && typeof s === 'object' ? Object.keys(s).slice(0, 12).join(', ') : '(non-object)';
            console.log(`   [poll] first response keys: ${keys}`);
            firstSeen = false;
        }
        if (statusUpper !== lastStatus) {
            console.log(`   [poll] status: ${statusUpper || '(no status field)'}`);
            lastStatus = statusUpper;
        }
        if (statusUpper && want.includes(statusUpper)) return s;
        await sleep(1500);
    }
    throw new Error(`Timed out waiting for test ${testId} to reach ${want.join('|')} (last status: ${lastStatus || 'unknown'})`);
}

async function cancelRunningTests(): Promise<void> {
    try {
        const r = await api.get('/api/runner/running');
        if (r.status !== 200 || !Array.isArray(r.data)) return;
        for (const id of r.data) {
            try {
                console.log(`Cancelling stale running test: ${id}`);
                await api.delete(`/api/runner/${encodeURIComponent(id)}`);
            } catch {}
        }
    } catch {}
}

function sleep(ms: number): Promise<void> { return new Promise((res) => setTimeout(res, ms)); }

// --- spawn local CLI; tee output to log file -----------------------------
function runLocalCli(cliCmd: string, logPath: string): Promise<{ exitCode: number }> {
    return new Promise((resolve) => {
        const discoveryUrl = process.env.SUITE_DISCOVERY_URL || '';
        const resourceEndpoint = process.env.SUITE_RESOURCE_ENDPOINT || '';
        // Many test subcommands require discoveryUrl + resourceEndpoint as positional
        // args. Always pass them — the ones that don't need them just ignore extra args.
        const spawnArgs = ['dist/index.js', cliCmd];
        if (discoveryUrl && resourceEndpoint) {
            spawnArgs.push(discoveryUrl, resourceEndpoint);
        }
        const stream = fs.createWriteStream(logPath);
        stream.write(`============================================================\n`);
        stream.write(` OpenID RP Certification — client-side evidence log\n`);
        stream.write(` CLI cmd   : node ${spawnArgs.join(' ')}\n`);
        stream.write(` Started   : ${new Date().toISOString()}\n`);
        stream.write(`============================================================\n\n`);

        const child = child_process.spawn('node', spawnArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
        child.stdout.on('data', (b) => stream.write(b));
        child.stderr.on('data', (b) => stream.write(b));
        child.on('close', (code) => {
            stream.write(`\n============================================================\n`);
            stream.write(` Exit code : ${code}\n`);
            stream.write(` Finished  : ${new Date().toISOString()}\n`);
            if (code !== 0) {
                stream.write(` NOTE: non-zero exit. For NEGATIVE tests this is the expected\n`);
                stream.write(`       outcome — the client refused the bad response.\n`);
            }
            stream.write(`============================================================\n`);
            stream.end();
            resolve({ exitCode: code ?? -1 });
        });
    });
}

// --- main -----------------------------------------------------------------
async function run() {
    fs.mkdirSync(LOG_DIR, { recursive: true });

    console.log('Cancelling any stale running tests under your account...');
    await cancelRunningTests();

    console.log(`Fetching plan ${planId}...`);
    const plan = await getPlan();

    // Plan shape: { id, planName, description, modules: [{ testModule, variant }, ...], ... }
    const modules: Array<{ testModule: string; variant?: any; instances?: any[] }> = plan.modules || plan.testModules || [];
    if (!modules.length) {
        console.error('Plan returned no modules. Raw response:');
        console.error(JSON.stringify(plan, null, 2).slice(0, 2000));
        process.exit(1);
    }
    console.log(`Plan "${plan.planName || '?'}" has ${modules.length} modules.`);

    const results: Array<{ moduleName: string; status: string; testId?: string; localExit?: number }> = [];

    for (const mod of modules) {
        const moduleName = mod.testModule;
        const cli = MODULE_TO_CLI[moduleName];
        if (!cli) {
            console.warn(`\n[skip] No local CLI mapping for module: ${moduleName}`);
            results.push({ moduleName, status: 'SKIPPED_NO_CLI_MAPPING' });
            continue;
        }
        if (only && cli !== only && moduleName !== only) {
            continue;
        }

        console.log(`\n=========================================================`);
        console.log(` Module : ${moduleName}`);
        console.log(` CLI    : ${cli}`);
        console.log(`=========================================================`);

        const logPath = path.join(LOG_DIR, `${moduleName}.log`);

        if (dryRun) {
            console.log(`[dry-run] would create test, run "node dist/index.js ${cli}", write log to ${logPath}`);
            results.push({ moduleName, status: 'DRY_RUN' });
            continue;
        }

        let testId = '';
        let exitCode: number | undefined = undefined;
        let finalStatus = 'ERROR';
        let finalResult = '?';
        try {
            testId = await createTest(moduleName, mod.variant);
            console.log(`Created suite test instance: ${testId}`);

            console.log('Waiting for WAITING state...');
            await pollUntil(testId, ['WAITING'], 60_000);
            console.log('Suite is WAITING — running local CLI.');

            const cliResult = await runLocalCli(cli, logPath);
            exitCode = cliResult.exitCode;
            console.log(`Local CLI exit: ${exitCode}; log written: ${logPath}`);

            console.log('Waiting for FINISHED/INTERRUPTED...');
            try {
                const final = await pollUntil(testId, ['FINISHED', 'INTERRUPTED'], 90_000);
                finalStatus = String(final.status);
                finalResult = String(final.result ?? '?');
                console.log(`Suite final state: ${finalStatus} result: ${finalResult}`);
            } catch (waitErr: any) {
                console.warn(`Wait-for-finish timed out (${waitErr?.message}). Will cancel test.`);
            }
        } catch (err: any) {
            console.error(`Module ${moduleName} failed:`, err?.message || err);
        } finally {
            if (testId) {
                try { await api.delete(`/api/runner/${encodeURIComponent(testId)}`); } catch {}
            }
            results.push({ moduleName, status: finalStatus, testId, localExit: exitCode });
        }
    }

    // Summary
    console.log(`\n=========================================================`);
    console.log(' SUMMARY');
    console.log(`=========================================================`);
    for (const r of results) {
        console.log(`  ${r.moduleName.padEnd(70)} → ${r.status}${r.localExit !== undefined ? ` (local exit ${r.localExit})` : ''}`);
    }

    // Zip — but only if we actually produced any logs.
    const haveLogs = fs.existsSync(LOG_DIR) && fs.readdirSync(LOG_DIR).some((f) => f.endsWith('.log'));
    if (!haveLogs) {
        console.log('\nNo log files were produced. Skipping zip. Fix errors above and rerun.');
        process.exit(1);
    }
    console.log(`\nZipping ${LOG_DIR} → ${ZIP_NAME}`);
    if (fs.existsSync(ZIP_NAME)) fs.unlinkSync(ZIP_NAME);
    child_process.execSync(`cd "${LOG_DIR}" && zip -q "${ZIP_NAME}" ./*.log`);
    console.log(`Zip created: ${ZIP_NAME}`);

    // Upload as certification package
    if (uploadPackage) {
        console.log('\nUploading certification package to the suite...');
        const fd = new FormData();
        fd.append('clientSideData', fs.createReadStream(ZIP_NAME), { filename: 'client-logs.zip', contentType: 'application/zip' });
        const r = await axios.post(`${SUITE_BASE}/api/plan/${encodeURIComponent(planId)}/certificationpackage`, fd, {
            headers: { ...fd.getHeaders(), Authorization: `Bearer ${token}` },
            responseType: 'arraybuffer',
            validateStatus: () => true,
            maxBodyLength: Infinity,
            maxContentLength: Infinity
        });
        if (r.status === 200) {
            const outZip = path.resolve(process.cwd(), 'certification-package.zip');
            fs.writeFileSync(outZip, Buffer.from(r.data));
            console.log(`Certification package saved: ${outZip}`);
            console.log('The plan is now published and immutable on the suite.');
        } else {
            console.error(`Upload failed: ${r.status}`);
            try { console.error(Buffer.from(r.data).toString('utf8').slice(0, 1000)); } catch {}
            process.exit(1);
        }
    }
}

run().catch((e) => { console.error('FATAL:', e?.message || e); process.exit(1); });
