const MAX_NODES = 2048;
const MAX_DEPTH = 32;

function field(value, name, limit = 256) {
  if (typeof value !== 'string' || !value.length || value.length > limit) {
    throw new TypeError('Invalid ' + name);
  }
  return value;
}

function normalize(entries) {
  if (!Array.isArray(entries) || entries.length > MAX_NODES) {
    throw new TypeError('Expected a bounded authorization array');
  }
  let count = 0;
  function call(node, depth) {
    if (++count > MAX_NODES || depth > MAX_DEPTH) {
      throw new RangeError('Authorization tree exceeds review limits');
    }
    if (!node || !Array.isArray(node.args) || node.args.length > 128 ||
        !Array.isArray(node.children) || node.children.length > MAX_NODES) {
      throw new TypeError('Expected an invocation with arguments and children');
    }
    return {
      contract: field(node.contract, 'contract'),
      method: field(node.method, 'method', 32),
      args: node.args.map(arg => ({
        type: field(arg?.type, 'argument type', 64),
        xdr: field(arg?.xdr, 'argument XDR', 16384)
      })),
      children: node.children.map(child => call(child, depth + 1))
    };
  }
  return entries.map(entry => ({
    principal: field(entry?.principal, 'principal'),
    credential: field(entry?.credential, 'credential type'),
    root: call(entry.root, 0)
  }));
}

export function compareAuthorization(before, after) {
  const left = normalize(before);
  const right = normalize(after);
  const changes = [];
  function invocation(a, b, path) {
    if (!a || !b || a.contract !== b.contract || a.method !== b.method) {
      changes.push({ kind: !a ? 'call-added' : !b ? 'call-removed' : 'call-replaced', path, before: a, after: b });
      return;
    }
    for (let i = 0; i < Math.max(a.args.length, b.args.length); i++) {
      if (JSON.stringify(a.args[i]) !== JSON.stringify(b.args[i])) {
        changes.push({ kind: 'argument-changed', path: [...path, 'args', i], before: a.args[i], after: b.args[i] });
      }
    }
    for (let i = 0; i < Math.max(a.children.length, b.children.length); i++) {
      invocation(a.children[i], b.children[i], [...path, 'children', i]);
    }
  }
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const a = left[i], b = right[i];
    if (!a || !b || a.principal !== b.principal || a.credential !== b.credential) {
      changes.push({ kind: !a ? 'authorization-added' : !b ? 'authorization-removed' : 'credential-changed', path: [i], before: a, after: b });
    } else {
      invocation(a.root, b.root, [i, 'root']);
    }
  }
  return changes;
}
