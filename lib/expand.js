'use strict';

const fill = require('fill-range');
const stringify = require('./stringify');
const utils = require('./utils');

const leaves = arr => {
  const result = [];
  const stack = [...arr].reverse();

  while (stack.length !== 0) {
    const ele = stack.pop();

    if (Array.isArray(ele)) {
      for (let i = ele.length - 1; i >= 0; i--) {
        stack.push(ele[i]);
      }
      continue;
    }

    result.push(ele);
  }

  return result;
};

/**
 * Appends the given stash to the given queue and returns the flattened
 * result. Implemented iteratively with an explicit stack to avoid
 * exhausting the call stack with deeply nested arrays (CVE-2026-93687).
 *
 * The output is the Cartesian product of the leaves of `queue` and the
 * leaves of `stash`, in depth-first order, with `enclose` wrapping each
 * leaf of `stash` in literal braces. This is equivalent to the original
 * recursive implementation.
 */

const append = (queue = '', stash = '', enclose = false) => {
  const q = [].concat(queue);
  const s = [].concat(stash);

  if (s.length === 0) {
    return leaves(q);
  }

  if (q.length === 0) {
    return enclose === true ? leaves(s).map(ele => `{${ele}}`) : leaves(s);
  }

  const result = [];
  const qLeaves = leaves(q);
  const sLeaves = leaves(s);

  for (const item of qLeaves) {
    for (const ele of sLeaves) {
      result.push(item + (enclose === true && typeof ele === 'string' ? `{${ele}}` : ele));
    }
  }

  return result;
};

const expand = (ast, options = {}) => {
  const rangeLimit = options.rangeLimit === undefined ? 1000 : options.rangeLimit;

  /**
   * Processes the entry of a node. Returns the state needed to iterate
   * the node's children, or null when the node is a leaf.
   */

  const setup = (node, parent) => {
    node.queue = [];

    let p = parent;
    let q = parent.queue;

    while (p.type !== 'brace' && p.type !== 'root' && p.parent) {
      p = p.parent;
      q = p.queue;
    }

    if (node.invalid || node.dollar) {
      q.push(append(q.pop(), stringify(node, options)));
      return null;
    }

    if (node.type === 'brace' && node.invalid !== true && node.nodes.length === 2) {
      q.push(append(q.pop(), ['{}']));
      return null;
    }

    if (node.nodes && node.ranges > 0) {
      const args = utils.reduce(node.nodes);

      if (utils.exceedsLimit(...args, options.step, rangeLimit)) {
        throw new RangeError('expanded array length exceeds range limit. Use options.rangeLimit to increase or disable the limit.');
      }

      let range = fill(...args, options);
      if (range.length === 0) {
        range = stringify(node, options);
      }

      q.push(append(q.pop(), range));
      node.nodes = [];
      return null;
    }

    const enclose = utils.encloseBrace(node);
    let queue = node.queue;
    let block = node;

    while (block.type !== 'brace' && block.type !== 'root' && block.parent) {
      block = block.parent;
      queue = block.queue;
    }

    return { q, queue, enclose, nodes: node.nodes };
  };

  const walk = node => {
    // Iterative depth-first traversal with an explicit stack to avoid
    // exhausting the call stack with deeply nested ASTs (CVE-2026-93687).
    const stack = [{ node, parent: {}, info: null, i: 0 }];

    while (stack.length !== 0) {
      const frame = stack[stack.length - 1];

      if (frame.info === null) {
        frame.info = setup(frame.node, frame.parent);
        if (frame.info === null) {
          stack.pop();
          continue;
        }
      }

      const { q, queue, enclose, nodes } = frame.info;

      if (frame.i < nodes.length) {
        const i = frame.i++;
        const child = nodes[i];

        if (child.type === 'comma' && frame.node.type === 'brace') {
          if (i === 1) queue.push('');
          queue.push('');
          continue;
        }

        if (child.type === 'close') {
          q.push(append(q.pop(), queue, enclose));
          continue;
        }

        if (child.value && child.type !== 'open') {
          queue.push(append(queue.pop(), child.value));
          continue;
        }

        if (child.nodes) {
          stack.push({ node: child, parent: frame.node, info: null, i: 0 });
        }
        continue;
      }

      stack.pop();
    }

    return node.queue;
  };

  return utils.flatten(walk(ast));
};

module.exports = expand;
