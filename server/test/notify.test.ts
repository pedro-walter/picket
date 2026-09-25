import { describe, it, expect, vi, afterEach } from 'vitest';
import { sendEmail } from '../src/notify';
import type { Env } from '../src/index';

const env = { RESEND_API_KEY: 're_test', ALERT_FROM: 'picket@example.com', ALERT_TO: 'a@example.com' } as Env;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('sendEmail', () => {
  it('returns false and skips the request when no API key is configured', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const sent = await sendEmail({ ALERT_FROM: 'a', ALERT_TO: 'b' } as Env, 'subj', 'body');
    expect(sent).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('returns true when Resend accepts the send', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{}', { status: 200 })));
    expect(await sendEmail(env, 'subj', 'body')).toBe(true);
  });

  it('returns false — without throwing — on a non-2xx Resend response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('bad domain', { status: 403 })));
    expect(await sendEmail(env, 'subj', 'body')).toBe(false);
  });

  it('returns false — without throwing — when the request itself fails', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network down')));
    expect(await sendEmail(env, 'subj', 'body')).toBe(false);
  });
});
