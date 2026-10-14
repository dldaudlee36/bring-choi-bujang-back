import test from 'node:test';
import assert from 'node:assert/strict';
import { operationsReport } from '../src/operations-report.mjs';

const config = { publicAppUrl: 'https://example.invalid', restoreRoute: '/api/restore/:noteId' };

function responseFor(url) {
  if (url.pathname === '/') return new Response('<form id="login-form"></form>', { status: 200 });
  if (url.pathname === '/data.json') return Response.json({ notes: [] });
  if (url.pathname === '/api/device/status') return Response.json({ approved: false });
  return Response.json({ error: 'login_required' }, { status: 401 });
}

test('report counts only observed results and keeps 41 engine attacks separate', async () => {
  const requests = [];
  const report = await operationsReport({
    config,
    commit: 'a'.repeat(40),
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return responseFor(url);
    },
  });
  assert.equal(requests.length, 9);
  assert.equal(report.summary.liveExecuted, 9);
  assert.equal(report.summary.syntheticExecuted, 7);
  assert.equal(report.summary.matched, 16);
  assert.equal(report.summary.mismatch, 0);
  assert.equal(report.summary.notRun, 5);
  assert.equal(report.assault.executed, 0);
  assert.equal(report.assault.notRun, 41);
  assert.equal(report.revocation.status, 'not_run');
  assert.equal(report.recovery.status, 'not_run');
  assert(report.cases.some(x => x.type === 'normal' && x.result === 'matched'));
  assert(report.cases.some(x => x.type === 'forbidden' && x.result === 'matched'));
  for (const row of report.cases.filter(x => x.result !== 'not_run')) {
    assert.match(row.requestId, /^[0-9a-f-]{36}$/u);
    assert(Number.isFinite(Date.parse(row.checkedAt)));
  }
});

test('network errors are not_run and response bodies never enter the report', async () => {
  const report = await operationsReport({
    config,
    commit: null,
    fetchImpl: async url => {
      if (url.pathname === '/') throw new Error('sensitive upstream error');
      if (url.pathname === '/api/notices') return Response.json({ body: 'private fixture content', access_token: 'private_token' });
      return responseFor(url);
    },
  });
  assert.equal(report.cases.find(x => x.id === 'public_page').result, 'not_run');
  assert.equal(report.cases.find(x => x.id === 'unauth_notice').result, 'mismatch');
  const text = JSON.stringify(report);
  for (const secret of ['private fixture content', 'private_token', 'sensitive upstream error']) {
    assert(!text.includes(secret));
  }
  assert(!text.includes('synthetic_burst'));
});
