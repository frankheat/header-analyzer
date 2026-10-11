'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { HL } = require('./helpers');

const { splitOutsideQuotes, parseDirectives, parseSfItem, parseSfDictionary } = HL.fields;

test('splitOutsideQuotes ignores separators inside quoted strings and escapes', () => {
  assert.deepEqual(splitOutsideQuotes('a, "b,c", d', ','), ['a', '"b,c"', 'd']);
  assert.deepEqual(splitOutsideQuotes('a, "b\\",c", d', ','), ['a', '"b\\",c"', 'd']);
  assert.deepEqual(splitOutsideQuotes('a,,b,', ','), ['a', 'b']);
  assert.deepEqual(splitOutsideQuotes('a,,b,', ',', true), ['a', '', 'b', '']);
});

test('parseDirectives lowercases names and unquotes arguments', () => {
  const d = parseDirectives('Max-Age="10"; includeSubDomains', ';');
  assert.equal(d.get('max-age'), '10');
  assert.equal(d.get('includesubdomains'), null);
});

// RFC 9651 items
const items = [
  ['same-origin', 'token'], ['"x"', 'string'], ['?1', 'boolean'], ['42', 'integer'],
  ['4.5', 'decimal'], [':aGVsbG8=:', 'bytes'], ['@1659578233', 'date'], ['%"caf%c3%a9"', 'displaystring'],
  ['same-origin; report-to="a;b"', 'token'], ['  same-origin  ', 'token'],
];
for (const [value, type] of items) {
  test(`SF item ${value} parses as ${type}`, () => {
    const r = parseSfItem(value);
    assert.ok(r.ok, r.reason);
    assert.equal(r.item[0].type, type);
  });
}

const badItems = ['same origin', 'a, b', 'x;', 'x; =1', '?2', '1.', '1.2345', '"unterminated', '"bad\\x"', ':!!:', '1234567890123456', '', '%"bad%ZZ"'];
for (const value of badItems) {
  test(`SF item ${JSON.stringify(value)} fails to parse`, () => {
    assert.equal(parseSfItem(value).ok, false);
  });
}

test('SF dictionary: members, inner lists, parameters, booleans', () => {
  const r = parseSfDictionary('a=(self "https://x"), b=*, c;report-to=x, d=()');
  assert.ok(r.ok);
  assert.deepEqual([...r.dict.keys()], ['a', 'b', 'c', 'd']);
  assert.equal(r.dict.get('a')[0].length, 2);
  assert.equal(r.dict.get('c')[0].type, 'boolean');
});

test('SF dictionary: a repeated key keeps the last value', () => {
  const r = parseSfDictionary('a=1, a=2');
  assert.equal(r.dict.get('a')[0].value, 2);
});

for (const [value, reason] of [
  ['Camera=()', 'lowercase'], ['a=(),', 'ends with a comma'], ['a=() b=()', 'not followed by a comma'],
  ['a=(self', 'closing parenthesis'], ['a=("x)', 'closing quote'], ['a=(x,y)', 'not separated by a space'],
]) {
  test(`SF dictionary ${JSON.stringify(value)} fails: ${reason}`, () => {
    const r = parseSfDictionary(value);
    assert.equal(r.ok, false);
    assert.ok(r.reason.includes(reason), r.reason);
  });
}
