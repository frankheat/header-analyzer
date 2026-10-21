'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { HL } = require('./helpers');

const parse = (text) => HL.parser.parseResponse(text);
const headersOf = (text) => Object.fromEntries(HL.parser.headerMap(parse(text).response));

for (const status of ['HTTP/1.0 200 OK', 'HTTP/1.1 301 Moved Permanently', 'HTTP/2 200', 'HTTP/3 204 No Content', 'http/1.1 200 OK']) {
  test(`status line "${status}" is read and skipped`, () => {
    const r = parse(`${status}\r\nX-Frame-Options: DENY\r\n\r\n`);
    assert.deepEqual(headersOf(`${status}\r\nX-Frame-Options: DENY\r\n\r\n`), { 'x-frame-options': ['DENY'] });
    assert.ok(r.response.status);
  });
}

test('headers without a status line still parse', () => {
  assert.deepEqual(headersOf('X-Frame-Options: DENY\r\nServer: nginx\r\n\r\n'),
    { 'x-frame-options': ['DENY'], server: ['nginx'] });
});

test('names are lowercased and OWS is trimmed from values', () => {
  assert.deepEqual(headersOf('HTTP/1.1 200 OK\r\nX-Frame-Options:    DENY \t \r\n\r\n'), { 'x-frame-options': ['DENY'] });
});

test('duplicates are preserved in order', () => {
  assert.deepEqual(headersOf('HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nSet-Cookie: c=3\r\n\r\n')['set-cookie'], ['a=1', 'b=2', 'c=3']);
});

test('a value containing colons is kept whole', () => {
  assert.deepEqual(headersOf('HTTP/1.1 302 Found\r\nLocation: https://example.com:8443/a?b=c\r\n\r\n').location, ['https://example.com:8443/a?b=c']);
});

test('an empty value is preserved as an empty string', () => {
  assert.deepEqual(headersOf('HTTP/1.1 200 OK\r\nReferrer-Policy:\r\n\r\n')['referrer-policy'], ['']);
});

for (const cont of [' more-value', '\tmore-value']) {
  test(`obs-fold continuation ${JSON.stringify(cont)} is joined with SP and noted`, () => {
    const r = parse(`HTTP/1.1 200 OK\r\nX-Long: start\r\n${cont}\r\n\r\n`);
    assert.deepEqual(HL.parser.headerMap(r.response).get('x-long'), ['start more-value']);
    assert.ok(r.response.notes.some((n) => n.includes('obs-fold')));
  });
}

test('obs-fold appends to the last occurrence only', () => {
  assert.deepEqual(headersOf('HTTP/1.1 200 OK\r\nX-Dup: first\r\nX-Dup: second\r\n continued\r\n\r\n')['x-dup'], ['first', 'second continued']);
});

test('the body after the blank line is ignored', () => {
  const h = headersOf('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>X-Frame-Options: DENY</html>\r\n');
  assert.equal(h['x-frame-options'], undefined);
  assert.deepEqual(h['content-type'], ['text/html']);
});

test('a body that contains a status line is not read as a response', () => {
  assert.deepEqual(headersOf('HTTP/1.1 200 OK\r\nA: 1\r\n\r\nsome body\r\nHTTP/1.1 200 OK\r\nB: 2\r\n\r\n'), { a: ['1'] });
});

test('LF-only and mixed line endings are supported', () => {
  assert.deepEqual(headersOf('HTTP/1.1 200 OK\nX-Frame-Options: DENY\r\nA: b\n\n'), { 'x-frame-options': ['DENY'], a: ['b'] });
});

test('a bare CR inside a line is replaced with SP', () => {
  assert.deepEqual(headersOf('HTTP/1.1 200 OK\r\nX-A: one\rtwo\r\n\r\n')['x-a'], ['one two']);
});

test('a UTF-8 BOM and leading blank lines are skipped', () => {
  assert.deepEqual(headersOf('﻿\r\n\r\nHTTP/1.1 200 OK\r\nA: b\r\n\r\n'), { a: ['b'] });
});

test('empty input yields no response', () => {
  assert.equal(parse('').response, null);
  assert.equal(parse('   \n\n ').response, null);
});

test('lines without a colon are ignored and noted', () => {
  const r = parse('HTTP/1.1 200 OK\r\ngarbage line\r\nX-Frame-Options: DENY\r\n\r\n');
  assert.deepEqual(Object.fromEntries(HL.parser.headerMap(r.response)), { 'x-frame-options': ['DENY'] });
  assert.ok(r.response.notes.some((n) => n.includes('not a field line')));
});

test('an invalid field name is discarded, as browsers discard it', () => {
  const r = parse('HTTP/1.1 200 OK\r\nX Frame: DENY\r\nX(Bad): 1\r\n\r\n');
  assert.equal(r.response.fields.length, 0);
  assert.equal(r.response.notes.length, 2);
});

test('whitespace before the colon is read leniently and noted', () => {
  const r = parse('HTTP/1.1 200 OK\r\nX-Frame-Options : DENY\r\n\r\n');
  assert.deepEqual(HL.parser.headerMap(r.response).get('x-frame-options'), ['DENY']);
  assert.ok(r.response.notes.some((n) => n.includes('RFC 9112')));
});

test('HTTP/2 pseudo-headers give the status and are not headers', () => {
  const r = parse(':status: 200\r\ncontent-type: text/html\r\n\r\n');
  assert.equal(r.response.status.code, 200);
  assert.deepEqual(Object.fromEntries(HL.parser.headerMap(r.response)), { 'content-type': ['text/html'] });
});

test('an informational 100 Continue in front of the response is skipped', () => {
  const r = parse('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nA: 1\r\n\r\nbody');
  assert.equal(r.response.status.code, 200);
  assert.deepEqual(Object.fromEntries(HL.parser.headerMap(r.response)), { a: ['1'] });
  assert.ok(r.notes.some((n) => n.includes('100 Continue')));
});

test('only the first response is read: what follows its headers is body', () => {
  const r = parse('HTTP/1.1 301 Moved\r\nLocation: /x\r\n\r\nHTTP/2 200\r\nA: 1\r\n\r\n');
  assert.equal(r.response.status.code, 301);
  assert.deepEqual(Object.fromEntries(HL.parser.headerMap(r.response)), { location: ['/x'] });
});

test('a request in front of the response is skipped (Burp copy)', () => {
  const r = parse('GET / HTTP/1.1\r\nHost: example.com\r\nCookie: a=b\r\n\r\nHTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n');
  assert.equal(r.request, 'GET / HTTP/1.1');
  assert.deepEqual(Object.fromEntries(HL.parser.headerMap(r.response)), { 'x-frame-options': ['DENY'] });
  assert.ok(r.notes.some((n) => n.includes('request')));
});

test('a request with no response is an explanatory error', () => {
  const r = parse('POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=a');
  assert.match(r.error, /request, not a response/);
});

test('input over the size limit is refused, not processed', () => {
  const r = parse('A: b\n'.repeat(HL.parser.MAX_INPUT / 4));
  assert.match(r.error, /larger than/);
});

test('replacement characters from invalid UTF-8 are tolerated', () => {
  assert.ok(headersOf('HTTP/1.1 200 OK\r\nX-Weird: ��\r\n\r\n')['x-weird']);
});

test('the body after the headers is kept as text', () => {
  const p = HL.parser.parseResponse('HTTP/1.1 200 OK\r\nA: b\r\n\r\n{"x":1}\r\nHTTP/1.1 200 OK');
  assert.equal(p.response.body, '{"x":1}\nHTTP/1.1 200 OK');
  assert.equal(HL.parser.parseResponse('HTTP/1.1 200 OK\r\nA: b').response.body, '');
});
