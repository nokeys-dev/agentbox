import { refCodePointEscape } from './git-protocol.js';

const SLACK_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;' };

// Escapes Slack mrkdwn special characters in agent-controlled text (PR titles, branch names,
// runtime identity fields, refs, action names, repository names) so a malicious agent cannot
// forge `<!channel>`/`<@U...>` mentions or other mrkdwn markup by putting them in a title, ref,
// or identity string it controls. Values that are never agent-controlled (the approval ID, and
// the operator-configured approvalUrl) are left unescaped.
function escapeSlack(value) {
  return String(value ?? '').replace(/[&<>]/g, (char) => SLACK_ESCAPES[char]);
}

// Escapes, then collapses embedded newlines so a multi-line title cannot inject extra fake lines
// into the single-line Slack message text.
function singleLine(value) {
  return escapeSlack(value).replace(/[\r\n]+/g, ' ');
}

// Fire-and-forget Slack-compatible webhook notifier. Never throws (beyond the constructor's
// upfront https check) and never blocks its caller: the POST runs detached and failures are only
// logged. It never includes the PR body: that field is free text an agent fully controls and can
// use to carry prompt injection or exfiltrate data into a chat channel.
export function createNotifier({ url, fetchImpl = fetch, logger, approvalUrl }) {
  if (!url) return () => {};
  if (new URL(url).protocol !== 'https:') throw new Error('Approval webhook URL must use https');
  return (item) => {
    const context = item.context ?? {};
    // See the approval UI's identical use (enterprise/src/approval-web.js) of refCodePointEscape: a non-ASCII ref is shown with
    // its exact code points alongside the literal text so a reviewer never has to trust Slack's
    // rendering to distinguish a spoofing character from an ordinary one.
    const changes = (context.changes ?? []).map((change) => {
      const codepoints = refCodePointEscape(change.ref);
      return `• ${escapeSlack(change.ref)}${codepoints ? ` (${escapeSlack(codepoints)})` : ''} ${change.oldOid?.slice(0, 12)} → ${change.newOid?.slice(0, 12)}`;
    });
    const pr = context.payload ? [`• PR ${escapeSlack(context.payload.head)} → ${escapeSlack(context.payload.base)}: ${singleLine(context.payload.title).slice(0, 120)}`] : [];
    if (context.action === 'github.pr.merge') {
      pr.push(`• Merge PR #${escapeSlack(context.number)} into ${escapeSlack(context.base)} (${escapeSlack(context.mergeMethod)}): ${singleLine(context.title).slice(0, 120)}`,
        `• Head ${escapeSlack(String(context.sha ?? '').slice(0, 12))} (${escapeSlack(context.sha)})`);
    }
    // A fork PR's head lives in another repository; show which one so it is never mistaken for a same-repository branch.
    if (typeof context.headRepository === 'string') pr.push(`• PR head repository ${escapeSlack(context.headRepository)}`);
    // Push option values are never stored in the context at all (see server.js) — only a count
    // and a digest — so there is nothing to redact here; send the count only.
    const pushOptionsCount = Number.isInteger(context.pushOptionsCount) ? context.pushOptionsCount : 0;
    const options = pushOptionsCount ? [`• push options: ${pushOptionsCount}`] : [];
    const text = [
      `AgentBox approval needed: ${escapeSlack(context.repository)} (${escapeSlack(context.action ?? 'git.push')})`,
      `Agent ${escapeSlack(context.runtime?.agent)} for ${escapeSlack(context.runtime?.human)}${context.runtime?.task ? ` · task ${singleLine(context.runtime.task)}` : ''}`,
      ...changes, ...pr, ...options,
      `${(item.reviews ?? []).filter((review) => review.decision === 'approve').length}/${item.requiredApprovals ?? 1} approvals · expires ${new Date(item.expiresAt ?? 0).toISOString()}`,
      `ID ${item.id}${approvalUrl ? ` · ${approvalUrl}` : ''}`
    ].join('\n');
    fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text }), redirect: 'error', signal: AbortSignal.timeout(10_000) })
      .then(async (response) => { await response.body?.cancel(); if (!response.ok) logger.warn('approval.notify_failed', { status: response.status, approvalId: item.id }); })
      .catch((error) => logger.warn('approval.notify_failed', { message: error.message, approvalId: item.id }));
  };
}

// Shared call-site guard for every place that fires a notifier after creating a new approval
// (the push path in server.js and the PR-create path in github-api.js): a notifier is
// caller-supplied and must never be allowed to break the approval response by throwing
// synchronously. Failures are logged with the same event name/shape createNotifier itself uses
// for an async failure — never the webhook URL, never any payload/context body.
export function guardNotify(notify, logger) {
  return (item) => {
    try { notify(item); } catch (error) { logger.warn('approval.notify_failed', { message: error.message, approvalId: item.id }); }
  };
}
