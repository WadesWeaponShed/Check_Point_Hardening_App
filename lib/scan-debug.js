import {appendFileSync, mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';

export function redactDebug(value) {
  if (Array.isArray(value)) return value.map(redactDebug);
  if (typeof value === 'string') return value.replace(/(session id\s*)\[[^\]]+\]/gi, '$1[redacted]');
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key,
    /^(password|api-key|apikey|sid|sessionid|session-id|x-chkp-sid|authorization|token)$/i.test(key)
      ? '[redacted]' : redactDebug(item)]));
}
export function createScanDebug(metadata = {}) {
  const journal = {scanId: randomUUID(), startedAt: new Date().toISOString(), ...metadata,
    commandLog: [], totalEntries: 0, writeError: ''};
  try {
    journal.file = join(mkdtempSync(join(tmpdir(), 'cp-scan-debug-')), 'scan.jsonl');
  } catch (error) { journal.writeError = error.message; }
  return journal;
}
export function appendScanDebug(journal, entry) {
  if (!journal) return;
  const event = redactDebug({timestamp: new Date().toISOString(), ...entry});
  journal.totalEntries = (journal.totalEntries || 0) + 1;
  journal.commandLog.push(event);
  if (journal.file) {
    try {
      appendFileSync(journal.file, JSON.stringify(event) + '\n', {mode: 0o600});
    }
    catch (error) { journal.writeError = error.message; }
  }
}
export function scanDebugSnapshot(journal, offset = 0) {
  if (!journal) return null;
  return {scanId: journal.scanId, startedAt: journal.startedAt, baseUrl: journal.baseUrl,
    user: journal.user, writeError: journal.writeError || undefined,
    commandLog: journal.commandLog.slice(Math.max(0, offset - ((journal.totalEntries || journal.commandLog.length) - journal.commandLog.length))), nextOffset: journal.totalEntries || journal.commandLog.length};
}

export function removeScanDebug(journal) {
  if (journal?.file) rmSync(join(journal.file, '..'), {recursive:true, force:true});
}
