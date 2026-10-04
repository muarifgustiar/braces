'use strict';

const utils = require('./utils');

module.exports = (ast, options = {}) => {
  const stringify = (node, parent = {}) => {
    const invalidBlock = options.escapeInvalid && utils.isInvalidBrace(parent);
    const invalidNode = node.invalid === true && options.escapeInvalid === true;
    let output = '';

    if (node.value) {
      if ((invalidBlock || invalidNode) && utils.isOpenOrClose(node)) {
        return '\\' + node.value;
      }
      return node.value;
    }

    if (node.nodes) {
      return null;
    }

    return output;
  };

  // Iterative depth-first traversal with an explicit stack to avoid
  // exhausting the call stack with deeply nested ASTs (CVE-2026-93687).
  // The output of the original recursive stringify is the concatenation
  // of its leaf outputs in depth-first order.
  const stack = [ast];
  let output = '';

  while (stack.length !== 0) {
    const node = stack.pop();
    const value = stringify(node);

    if (value !== null) {
      output += value;
      continue;
    }

    for (let i = node.nodes.length - 1; i >= 0; i--) {
      stack.push(node.nodes[i]);
    }
  }

  return output;
};

