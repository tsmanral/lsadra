// Run with: npm test (node --test, TypeScript types stripped by Node).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { captureSetupToken, searchWithoutToken, SETUP_TOKEN_KEY, tokenFromSearch } from './setupToken.ts';

const TOKEN = 'a'.repeat(64);

test('a well-formed token is read from the query string', () => {
  assert.equal(tokenFromSearch(`?setup_token=${TOKEN}`), TOKEN);
});

test('missing, short or odd tokens are ignored', () => {
  assert.equal(tokenFromSearch(''), null);
  assert.equal(tokenFromSearch('?setup_token=abc'), null);
  assert.equal(tokenFromSearch(`?setup_token=${'a'.repeat(40)}<script>`), null);
});

test('only the token is removed from the address', () => {
  assert.equal(searchWithoutToken(`?setup_token=${TOKEN}`), '');
  assert.equal(searchWithoutToken(`?x=1&setup_token=${TOKEN}`), '?x=1');
});

const fakeWindow = (search: string) => {
  const stored: Record<string, string> = {};
  const replaced: string[] = [];
  return {
    stored,
    replaced,
    w: {
      location: { search, pathname: '/', hash: '' },
      history: { replaceState: (_d: unknown, _u: string, url: string) => { replaced.push(url); } },
      sessionStorage: { setItem: (k: string, v: string) => { stored[k] = v; } },
    },
  };
};

test('capture stores the token for this window and strips it from the URL', () => {
  const f = fakeWindow(`?setup_token=${TOKEN}`);
  captureSetupToken(f.w);
  assert.equal(f.stored[SETUP_TOKEN_KEY], TOKEN);
  assert.deepEqual(f.replaced, ['/']);
});

test('a malformed token is stripped but not stored', () => {
  const f = fakeWindow('?setup_token=nope');
  captureSetupToken(f.w);
  assert.deepEqual(f.stored, {});
  assert.deepEqual(f.replaced, ['/']);
});

test('nothing happens without a token', () => {
  const f = fakeWindow('?x=1');
  captureSetupToken(f.w);
  assert.deepEqual(f.stored, {});
  assert.deepEqual(f.replaced, []);
});
