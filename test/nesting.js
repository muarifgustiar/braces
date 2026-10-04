'use strict';

require('mocha');
const assert = require('assert').strict;
const braces = require('..');
const utils = require('../lib/utils');

/**
 * Regression tests for deeply nested patterns.
 *
 * The recursive AST walkers used to lack depth guards, allowing
 * attacker-controlled patterns under the maximum length limit to
 * exhaust the call stack and terminate the process with an uncaught
 * RangeError (CVE-2026-93687).
 */

describe('deeply nested patterns', () => {
  it('should compile deeply nested braces without stack overflow', () => {
    const input = '{'.repeat(5000) + '}'.repeat(5000);
    assert.deepEqual(braces(input), [input]);
  });

  it('should expand deeply nested braces without stack overflow', () => {
    const input = '{'.repeat(5000) + '}'.repeat(5000);
    assert.deepEqual(braces.expand(input), [input]);
  });

  it('should stringify deeply nested braces without stack overflow', () => {
    const input = '{'.repeat(5000) + '}'.repeat(5000);
    assert.equal(braces.stringify(input), input);
  });

  it('should handle deeply nested parentheses without stack overflow', () => {
    const input = '('.repeat(4999) + ')'.repeat(4999);
    assert.deepEqual(braces(input), [input]);
    assert.deepEqual(braces.expand(input), [input]);
    assert.equal(braces.stringify(input), input);
  });

  it('should expand deeply nested sets without stack overflow', () => {
    let input = 'a';
    for (let i = 0; i < 2000; i++) input = '{a,' + input + '}';

    const result = braces.expand(input);
    assert.equal(result.length, 2001);
    assert.ok(result.every(value => value === 'a'));
  });

  it('should expand deeply nested ranges and sets without stack overflow', () => {
    const input = '{1..3,'.repeat(1000) + 'x' + '}'.repeat(1000);

    const result = braces.expand(input);
    assert.ok(result.length > 0);
    assert.ok(result.every(value => typeof value === 'string'));
  });

  it('should compile deeply nested mixed patterns without stack overflow', () => {
    const depth = 2000;
    const input = '{a,b'.repeat(depth) + '}'.repeat(depth);

    let expected = '(a|b)';
    for (let i = 1; i < depth; i++) {
      expected = '(' + 'a' + '|b' + expected + ')';
    }
    assert.deepEqual(braces(input), [expected]);

    const result = braces.expand(input);
    assert.equal(result.length, depth + 1);
    assert.equal(result[0], 'a');
    assert.equal(result[result.length - 1], 'b'.repeat(depth));
  });

  it('should handle deeply nested unbalanced braces without stack overflow', () => {
    const input = '{a{b'.repeat(1000);
    assert.deepEqual(braces(input), [input]);
    assert.deepEqual(braces.expand(input), [input]);
    assert.equal(braces.stringify(input), input);
  });

  it('should expand nested sets the same as shallow ones', () => {
    let input = 'a';
    for (let i = 0; i < 3; i++) input = '{a,' + input + '}';
    assert.deepEqual(braces.expand(input), ['a', 'a', 'a', 'a']);
  });

  it('should expand nested ranges the same as shallow ones', () => {
    const input = '{1..3,{1..3,{1..3,x}}}';
    assert.deepEqual(braces.expand(input), ['1..3', '1..3', '1..3', 'x']);
  });

  it('should expand mixed nested sets the same as shallow ones', () => {
    assert.deepEqual(braces.expand('{a,{b,{c,d}}}'), ['a', 'b', 'c', 'd']);
  });

  it('should flatten deeply nested arrays without stack overflow', () => {
    let input = ['x'];
    for (let i = 0; i < 100000; i++) input = [input];

    assert.deepEqual(utils.flatten(input), ['x']);
  });
});
