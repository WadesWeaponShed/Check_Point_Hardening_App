export function currentSid(root, sid) {
  const seen = new Set();
  while (root?.sidReplacements?.has(sid) && !seen.has(sid)) {seen.add(sid); sid = root.sidReplacements.get(sid);}
  return sid;
}
export async function recoverRead({root, session, command, body, request, expired, renew, checkCancelled}) {
  const sid = currentSid(root, session.sid);
  try {return await request({...session, sid}, command, body);}
  catch (error) {
    if (!root?.scanAuth || !(command.startsWith('show-') || command === 'where-used') || !expired(error)) throw error;
    checkCancelled();
    root.sidReplacements ||= new Map();
    root.sidRenewals ||= new Map();
    if (!root.sidRenewals.has(sid)) {
      const pending = Promise.resolve().then(() => renew(sid,error)).then(next => {
        root.sidReplacements.set(sid,next); return next;
      });
      root.sidRenewals.set(sid,pending);
      pending.catch(() => root.sidRenewals.delete(sid));
    }
    const next = await root.sidRenewals.get(sid);
    checkCancelled();
    // One replay per read. Scripts and mutations are never resubmitted.
    return request({...session,sid:currentSid(root,next)},command,body);
  }
}
