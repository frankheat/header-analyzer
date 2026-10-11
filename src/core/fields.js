/*
 * Header Analyzer: reading field values the way a browser reads them.
 *
 * Two families of grammar matter here:
 *   - comma/semicolon lists with quoted-strings (RFC 9110 §5.6), read by
 *     `splitOutsideQuotes` and `parseDirectives`, which is also what Fetch's
 *     "get, decode, and split" does;
 *   - Structured Field Values (RFC 9651, which obsoletes RFC 8941), read by
 *     `parseSfItem` and `parseSfDictionary`, following the RFC's own parsing
 *     algorithms step by step, including the steps that condemn a whole field.
 */
(function (HL) {
  'use strict';

  /** Strip optional whitespace (SP / HTAB, RFC 9110 §5.6.3): nothing else. */
  function trimOWS(s) {
    return s.replace(/^[ \t]+|[ \t]+$/g, '');
  }

  /**
   * Split on `separator`, ignoring separators inside a quoted-string (with
   * quoted-pair escapes, RFC 9110 §5.6.4). Quotes are kept in the parts, as
   * Fetch's "get, decode, and split" keeps them.
   *
   * Empty segments are dropped unless `keepEmpty`: for a list of directives a
   * stray separator means nothing, while for a set of values it is a value.
   */
  function splitOutsideQuotes(value, separator, keepEmpty) {
    const parts = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < value.length; i++) {
      const c = value[i];
      if (inQuotes && c === '\\' && i + 1 < value.length) {
        current += c + value[i + 1];
        i++;
        continue;
      }
      if (c === '"') inQuotes = !inQuotes;
      if (c === separator && !inQuotes) {
        parts.push(current);
        current = '';
      } else {
        current += c;
      }
    }
    parts.push(current);
    const trimmed = parts.map(trimOWS);
    return keepEmpty ? trimmed : trimmed.filter((p) => p !== '');
  }

  function unquote(s) {
    if (s.length >= 2 && s[0] === '"' && s[s.length - 1] === '"') {
      return s.slice(1, -1).replace(/\\(.)/g, '$1');
    }
    return s;
  }

  /**
   * Split a value into a Map of {lowercased directive name: argument or null}.
   * Arguments are unquoted. A later repeat of a name overwrites the earlier one;
   * callers that care about repeats (HSTS) count names separately.
   */
  function parseDirectives(value, separator) {
    const out = new Map();
    for (const token of splitOutsideQuotes(value, separator)) {
      const eq = token.indexOf('=');
      const name = trimOWS(eq === -1 ? token : token.slice(0, eq)).toLowerCase();
      if (!name) continue;
      const arg = eq === -1 ? null : unquote(trimOWS(token.slice(eq + 1)));
      out.set(name, arg);
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Structured Field Values: RFC 9651
  // ---------------------------------------------------------------------------

  const LCALPHA = 'abcdefghijklmnopqrstuvwxyz';
  const UCALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const DIGITS = '0123456789';
  const KEY_START = LCALPHA + '*';
  const KEY_CHARS = KEY_START + DIGITS + '_-.';
  const TOKEN_START = LCALPHA + UCALPHA + '*';
  const TCHAR = LCALPHA + UCALPHA + DIGITS + "!#$%&'*+-.^_`|~";
  const TOKEN_CHARS = TCHAR + ':/';
  const BASE64 = LCALPHA + UCALPHA + DIGITS + '+/=';

  /** The whole field fails to parse; `message` is a reason a report can name. */
  class SfError extends Error {}

  class SfParser {
    constructor(input) {
      this.s = input;
      this.i = 0;
    }

    peek() { return this.i < this.s.length ? this.s[this.i] : ''; }
    take() { const c = this.peek(); this.i++; return c; }
    atEnd() { return this.i >= this.s.length; }
    skip(chars) { while (!this.atEnd() && chars.includes(this.peek())) this.i++; }

    /** §4.2 top level for an Item: SP, item, SP, end. */
    parseTopItem() {
      this.skip(' ');
      const item = this.item();
      this.skip(' ');
      if (!this.atEnd()) {
        if (this.peek() === ',') throw new SfError('it carries more than one value');
        throw new SfError(`unexpected '${this.peek()}' after the value`);
      }
      return item;
    }

    /** §4.2.2. Returns a Map {key: [value, params]}; a repeated key overwrites. */
    parseTopDictionary() {
      const out = new Map();
      this.skip(' ');
      while (!this.atEnd()) {
        const key = this.key();
        let member;
        if (this.peek() === '=') {
          this.take();
          member = this.itemOrInnerList();
        } else {
          member = [{ type: 'boolean', value: true }, this.parameters()];
        }
        out.delete(key);          // keep insertion order of the surviving member
        out.set(key, member);
        this.skip(' \t');
        if (this.atEnd()) return out;
        if (this.take() !== ',') throw new SfError(`'${key}' is not followed by a comma`);
        this.skip(' \t');
        if (this.atEnd()) throw new SfError('it ends with a comma');
      }
      return out;
    }

    /** §4.2.3.3: uppercase cannot start a key. */
    key() {
      const c = this.peek();
      if (!c || !KEY_START.includes(c)) {
        throw new SfError(`'${c || ' '}' cannot start a name (names are lowercase)`);
      }
      let out = '';
      while (!this.atEnd() && KEY_CHARS.includes(this.peek())) out += this.take();
      return out;
    }

    itemOrInnerList() {
      return this.peek() === '(' ? this.innerList() : this.item();
    }

    /** §4.2.1.2 */
    innerList() {
      this.take(); // '('
      const items = [];
      for (;;) {
        this.skip(' ');
        if (this.atEnd()) throw new SfError('a list is missing its closing parenthesis');
        if (this.peek() === ')') {
          this.take();
          return [items, this.parameters()];
        }
        items.push(this.item());
        if (this.atEnd()) throw new SfError('a list is missing its closing parenthesis');
        if (this.peek() !== ' ' && this.peek() !== ')') {
          throw new SfError('a list item is not separated by a space');
        }
      }
    }

    /** §4.2.3 */
    item() {
      return [this.bareItem(), this.parameters()];
    }

    /** §4.2.3.1: typed, so callers can tell a wrong type from a syntax error. */
    bareItem() {
      const c = this.peek();
      if (!c) throw new SfError('a value is missing');
      if (c === '"') return { type: 'string', value: this.string() };
      if (c === ':') return { type: 'bytes', value: this.byteSequence() };
      if (c === '?') return { type: 'boolean', value: this.boolean() };
      if (c === '@') return { type: 'date', value: this.date() };
      if (c === '%') return { type: 'displaystring', value: this.displayString() };
      if (c === '-' || DIGITS.includes(c)) return this.number();
      if (TOKEN_START.includes(c)) return { type: 'token', value: this.token() };
      throw new SfError(`'${c}' cannot start a value`);
    }

    /** §4.2.3.2 */
    parameters() {
      const params = new Map();
      while (this.peek() === ';') {
        this.take();
        this.skip(' ');
        const k = this.key();
        let v = { type: 'boolean', value: true };
        if (this.peek() === '=') {
          this.take();
          v = this.bareItem();
        }
        params.delete(k);
        params.set(k, v);
      }
      return params;
    }

    /** §4.2.4 */
    number() {
      let type = 'integer';
      let out = '';
      if (this.peek() === '-') out += this.take();
      if (!DIGITS.includes(this.peek()) || this.atEnd()) throw new SfError('a number is missing its digits');
      while (!this.atEnd()) {
        const c = this.peek();
        if (DIGITS.includes(c)) {
          out += this.take();
        } else if (type === 'integer' && c === '.') {
          if (out.replace('-', '').length > 12) throw new SfError('a decimal has too many digits');
          out += this.take();
          type = 'decimal';
        } else {
          break;
        }
        const digits = out.replace('-', '').replace('.', '').length;
        if (type === 'integer' && digits > 15) throw new SfError('an integer has too many digits');
        if (type === 'decimal' && digits > 16) throw new SfError('a decimal has too many digits');
      }
      if (type === 'decimal') {
        if (out.endsWith('.')) throw new SfError('a decimal ends with a dot');
        if (out.length - out.indexOf('.') - 1 > 3) throw new SfError('a decimal has too many fractional digits');
      }
      return { type: type, value: Number(out) };
    }

    /** §4.2.5 */
    string() {
      this.take(); // '"'
      let out = '';
      while (!this.atEnd()) {
        const c = this.take();
        if (c === '\\') {
          if (this.atEnd()) throw new SfError('a quoted string ends inside an escape');
          const n = this.take();
          if (n !== '\\' && n !== '"') throw new SfError('a quoted string contains an invalid escape');
          out += n;
        } else if (c === '"') {
          return out;
        } else if (c < ' ' || c > '~') {
          throw new SfError('a quoted string contains an invalid character');
        } else {
          out += c;
        }
      }
      throw new SfError('a quoted string is missing its closing quote');
    }

    /** §4.2.6 */
    token() {
      let out = this.take();
      while (!this.atEnd() && TOKEN_CHARS.includes(this.peek())) out += this.take();
      return out;
    }

    /** §4.2.7 */
    byteSequence() {
      this.take(); // ':'
      let out = '';
      while (!this.atEnd()) {
        const c = this.take();
        if (c === ':') return out;
        if (!BASE64.includes(c)) throw new SfError('a byte sequence contains an invalid character');
        out += c;
      }
      throw new SfError('a byte sequence is missing its closing colon');
    }

    /** §4.2.8 */
    boolean() {
      this.take(); // '?'
      const c = this.take();
      if (c === '1') return true;
      if (c === '0') return false;
      throw new SfError("'?' must be followed by 0 or 1");
    }

    /** §4.2.9 */
    date() {
      this.take(); // '@'
      const n = this.number();
      if (n.type !== 'integer') throw new SfError('a date must be an integer');
      return n.value;
    }

    /** §4.2.10: only its well-formedness matters here. */
    displayString() {
      this.take(); // '%'
      if (this.take() !== '"') throw new SfError("'%' must be followed by a quoted string");
      let out = '';
      while (!this.atEnd()) {
        const c = this.take();
        if (c < ' ' || c > '~') throw new SfError('a display string contains an invalid character');
        if (c === '"') return out;
        if (c === '%') {
          const hex = this.s.slice(this.i, this.i + 2);
          if (!/^[0-9a-f]{2}$/.test(hex)) throw new SfError('a display string has an invalid escape');
          this.i += 2;
          out += '%' + hex;
        } else {
          out += c;
        }
      }
      throw new SfError('a display string is missing its closing quote');
    }
  }

  /** {ok: true, item: [bare, params]} or {ok: false, reason}. */
  function parseSfItem(value) {
    try {
      return { ok: true, item: new SfParser(value).parseTopItem() };
    } catch (e) {
      if (e instanceof SfError) return { ok: false, reason: e.message };
      throw e;
    }
  }

  /** {ok: true, dict: Map} or {ok: false, reason}. */
  function parseSfDictionary(value) {
    try {
      return { ok: true, dict: new SfParser(value).parseTopDictionary() };
    } catch (e) {
      if (e instanceof SfError) return { ok: false, reason: e.message };
      throw e;
    }
  }

  HL.fields = Object.freeze({
    trimOWS,
    splitOutsideQuotes,
    parseDirectives,
    unquote,
    parseSfItem,
    parseSfDictionary,
  });
})(globalThis.HeaderAnalyzer = globalThis.HeaderAnalyzer || {});
