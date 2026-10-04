'use strict';

const fill = require('fill-range');
const utils = require('./utils');

const compile = (ast, options = {}) => {
  const outputOf = (node, parent) => {
    const invalidBlock = utils.isInvalidBrace(parent);
    const invalidNode = node.invalid === true && options.escapeInvalid === true;
    const invalid = invalidBlock === true || invalidNode === true;
    const prefix = options.escapeInvalid === true ? '\\' : '';

    if (node.isOpen === true) {
      return prefix + node.value;
    }

    if (node.isClose === true) {
      console.log('node.isClose', prefix, node.value);
      return prefix + node.value;
    }

    if (node.type === 'open') {
      return invalid ? prefix + node.value : '(';
    }

    if (node.type === 'close') {
      return invalid ? prefix + node.value : ')';
    }

    if (node.type === 'comma') {
      return node.prev.type === 'comma' ? '' : invalid ? node.value : '|';
    }

    if (node.value) {
      return node.value;
    }

    if (node.nodes && node.ranges > 0) {
      const args = utils.reduce(node.nodes);
      const range = fill(...args, { ...options, wrap: false, toRegex: true, strictZeros: true });

      if (range.length !== 0) {
        return args.length > 1 && range.length > 1 ? `(${range})` : range;
      }
    }

    if (node.nodes) {
      return null;
    }

    return '';
  };

  const walk = (node, parent = {}) => {
    // Iterative depth-first traversal with an explicit stack to avoid
    // exhausting the call stack with deeply nested ASTs (CVE-2026-93687).
    // The output of the original recursive walk is the concatenation of
    // its leaf outputs in depth-first order.
    const stack = [{ node, parent }];
    let output = '';

    while (stack.length !== 0) {
      const current = stack.pop();
      const value = outputOf(current.node, current.parent);

      if (value !== null) {
        output += value;
        continue;
      }

      const children = current.node.nodes;
      for (let i = children.length - 1; i >= 0; i--) {
        stack.push({ node: children[i], parent: current.node });
      }
    }

    return output;
  };

  return walk(ast);
};

module.exports = compile;
