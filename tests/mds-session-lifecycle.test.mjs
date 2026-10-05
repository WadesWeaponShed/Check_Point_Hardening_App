import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../server.js', import.meta.url), 'utf8');
const start = source.indexOf('async function scanMoraHardening(session)');
const end = source.indexOf('async function evaluateSingleHardeningCheck', start);
function fixture(failure) {
  const events = [];
  const session = {id: 'root', baseUrl: 'https://mds', moraAuth: {user: 'scanner', password: 'secret'},
    moraDomains: ['A', 'B'].map(name => ({name, uid: name, session: null}))};
  const context = vm.createContext({Date, Map, Math, Object, Array, Number,
    assertNotCancelled() {}, operationContext: {getStore() {}, run: (_, fn) => fn()},
    log() {}, HARDENING_GUIDE_URL: 'guide', mergeScanSummaries: () => ({}),
    cpRequest: async (target, command, body) => {
      events.push(`${command}:${body.domain || target.sid}`);
      if (command === 'login') return {sid: body.domain};
      return {};
    },
    scanHardening: async target => {
      events.push(`scan:${target.domain}`);
      assert.equal(session.moraDomains.filter(d => d.session).length, 1);
      if (target.domain === 'A' && failure) throw failure;
      return {summary: {}, commandLog: [], commandResults: {}};
    }
  });
  vm.runInContext(source.slice(start, end), context);
  return {session, events, run: () => context.scanMoraHardening(session)};
}
test('CMA sessions are opened just in time and closed before the next login, including repeat scans', async () => {
  const f = fixture();
  await f.run();
  assert.deepEqual(f.events, ['login:A', 'scan:A', 'logout:A', 'login:B', 'scan:B', 'logout:B']);
  assert(f.session.moraDomains.every(d => d.session === null));
  await f.run();
  assert.equal(f.events.filter(e => e === 'login:A').length, 2);
});
test('failed CMA is logged out and subsequent CMA still scans', async () => {
  const f = fixture(Error('expired'));
  const result = await f.run();
  assert.equal(result.domains[0].error, 'expired');
  assert.deepEqual(f.events, ['login:A', 'scan:A', 'logout:A', 'login:B', 'scan:B', 'logout:B']);
});
test('cancellation logs out current CMA without opening another', async () => {
  const f = fixture(Object.assign(Error('cancelled'), {code: 'SCAN_CANCELLED'}));
  await assert.rejects(f.run(), /cancelled/);
  assert.deepEqual(f.events, ['login:A', 'scan:A', 'logout:A']);
  assert.equal(f.session.moraDomains[0].session, null);
});
