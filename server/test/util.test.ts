import { describe, it, expect } from 'vitest';
import { sha256Hex, hmacSha256Hex, timingSafeEqualHex, globToRegExp, fingerprintInput } from '../src/util';

describe('sha256Hex', () => {
  it('matches a known vector', async () => {
    expect(await sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});

describe('hmacSha256Hex', () => {
  it('matches RFC 4231 test case 1', async () => {
    // key = 0x0b*20, data = "Hi There"
    const key = '\x0b'.repeat(20);
    expect(await hmacSha256Hex(key, 'Hi There')).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    );
  });
});

describe('timingSafeEqualHex', () => {
  it('true for equal, false for different or different length', () => {
    expect(timingSafeEqualHex('deadbeef', 'deadbeef')).toBe(true);
    expect(timingSafeEqualHex('deadbeef', 'deadbee0')).toBe(false);
    expect(timingSafeEqualHex('dead', 'deadbeef')).toBe(false);
  });
});

describe('globToRegExp', () => {
  it('anchors and supports * and ?', () => {
    expect(globToRegExp('*|libssl3').test('CVE-2026-14456|libssl3')).toBe(true);
    expect(globToRegExp('*|libssl3').test('CVE-2026-14456|libssl4')).toBe(false);
    expect(globToRegExp('postgres').test('postgres')).toBe(true);
    expect(globToRegExp('postgres').test('postgres:16')).toBe(false);
    expect(globToRegExp('CVE-2026-????').test('CVE-2026-1445')).toBe(true);
  });
  it('treats regex metachars as literal', () => {
    expect(globToRegExp('a.b+c').test('a.b+c')).toBe(true);
    expect(globToRegExp('a.b+c').test('axbxc')).toBe(false);
  });
});

describe('fingerprintInput', () => {
  it('is newline-joined and order-sensitive', () => {
    expect(fingerprintInput('image-cve', 'prod-server', 'postgres', 'CVE-2026-14456|libssl3')).toBe(
      'image-cve\nprod-server\npostgres\nCVE-2026-14456|libssl3',
    );
  });
});
