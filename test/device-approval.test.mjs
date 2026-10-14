import test from 'node:test';
import assert from 'node:assert/strict';
import { createDeviceHandler } from '../src/device-approval.mjs';
import { createDeviceGate } from '../public/device-gate.mjs';

async function invoke(options, request) {
  const response = {
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.code = code; return this; },
    json(value) { this.body = value; return this; },
  };
  await createDeviceHandler(options)(request, response);
  return response;
}

test('client approval flags and forged headers cannot register a device', async () => {
  const response = await invoke({}, {
    method: 'GET',
    headers: { 'x-device-approved': 'true' },
    body: { approved: true, installed: true, role: 'instructor' },
  });
  assert.equal(response.code, 200);
  assert.equal(response.body.approved, false);
  assert.equal(response.headers['Cache-Control'], 'no-store');
});

test('approval request is explicitly unavailable rather than falsely accepted', async () => {
  const response = await invoke({ requestApproval: true }, { method: 'POST', headers: {} });
  assert.equal(response.code, 501);
  assert.equal(response.body.accepted, false);
  assert.equal(response.body.approved, false);
});

test('unapproved or malformed server result never opens materials; approved result does', async () => {
  let result = { status: 200, body: { approved: false } };
  let reads = 0;
  const gate = createDeviceGate({
    fetchStatus: async () => result,
    clearMaterials() {},
    openMaterials: async () => reads++,
  });
  assert.equal(await gate.check(), false);
  result.body.approved = 'true';
  assert.equal(await gate.check(), false);
  result = { status: 403, body: { approved: true } };
  assert.equal(await gate.check(), false);
  assert.equal(reads, 0);
  result = { status: 200, body: { approved: true } };
  assert.equal(await gate.check(), true);
  assert.equal(reads, 1);
  gate.reset();
  assert.equal(gate.approved, false);
});

test('logout or offline reset invalidates a late approval response', async () => {
  let resolve;
  let reads = 0;
  const gate = createDeviceGate({
    fetchStatus: () => new Promise(r => { resolve = r; }),
    clearMaterials() {},
    openMaterials: async () => reads++,
  });
  const check = gate.check();
  gate.reset();
  resolve({ status: 200, body: { approved: true } });
  assert.equal(await check, false);
  assert.equal(reads, 0);
});
