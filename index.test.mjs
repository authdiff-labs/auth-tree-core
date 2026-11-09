import test from 'node:test';
import assert from 'node:assert/strict';
import { CHANGE_KINDS, compareAuthorization, summarizeChanges } from './index.mjs';

const call = (method = 'transfer', args = [], children = []) => ({contract: 'example-contract', method, args, children});
const auth = (root, principal = 'example-account') => [{principal, credential: 'address-v2', root}];

test('reports nested typed argument changes at their invocation path', () => {
  const before = auth(call('pay', [], [call('transfer', [{type:'i128', xdr:'AAAA'}])]));
  const after = auth(call('pay', [], [call('transfer', [{type:'i128', xdr:'AAAB'}])]));
  assert.deepEqual(compareAuthorization(before, after).map(({kind,path}) => ({kind,path})),
    [{kind:'argument-changed', path:[0,'root','children',0,'args',0]}]);
});

test('reports a principal substitution without conflating credentials', () => {
  const [change] = compareAuthorization(auth(call()), auth(call(), 'other-account'));
  assert.equal(change.kind, 'principal-changed');
  assert.equal(change.path[0], 0);
});

test('reports credential substitutions separately from principals', () => {
  const before = [{ principal: 'example-account', credential: 'address-v2', root: call() }];
  const after = [{ principal: 'example-account', credential: 'address', root: call() }];
  assert.equal(compareAuthorization(before, after)[0].kind, 'credential-changed');
});

test('reports added and removed authorizations', () => {
  const one = auth(call());
  assert.equal(compareAuthorization(one, []).at(0).kind, 'authorization-removed');
  assert.equal(compareAuthorization([], one).at(0).kind, 'authorization-added');
});

test('distinguishes added, removed and replaced calls', () => {
  const before = auth(call('review', [], [call('record')]));
  const added = compareAuthorization(before, auth(call('review', [], [call('record'), call('extra')])));
  assert.deepEqual(added.map(({ kind, path }) => ({ kind, path })),
    [{ kind: 'call-added', path: [0, 'root', 'children', 1] }]);
  assert.equal(compareAuthorization(auth(call('review', [], [call('record'), call('extra')])), before)[0].kind, 'call-removed');
  assert.equal(compareAuthorization(before, auth(call('review', [], [call('swap')])))[0].kind, 'call-replaced');
});

test('summarizes changes by kind', () => {
  const changes = compareAuthorization(auth(call('pay', [], [call('debit'), call('credit')])),
    auth(call('pay', [], [call('credit'), call('debit')])));
  const summary = summarizeChanges(changes);
  assert.equal(summary.total, 2);
  assert.equal(summary.counts['call-replaced'], 2);
  for (const kind of CHANGE_KINDS) assert.equal(typeof summary.counts[kind], 'number');
  assert.throws(() => summarizeChanges([{ kind: 'mystery' }]), /Unknown change kind/);
  assert.throws(() => summarizeChanges(null), /array of changes/);
});

test('enforces review limits on crafted trees', () => {
  let deep = call('leaf');
  for (let i = 0; i < 34; i++) deep = call('wrap', [], [deep]);
  assert.throws(() => compareAuthorization(auth(deep), auth(call())), /review limits/);
  const wide = call('record', Array.from({ length: 129 }, () => ({ type: 'i32', xdr: 'AAAA' })));
  assert.throws(() => compareAuthorization(auth(wide), auth(call())), /invocation with arguments/);
});

test('preserves invocation order', () => {
  const before = auth(call('pay', [], [call('debit'), call('credit')]));
  const after = auth(call('pay', [], [call('credit'), call('debit')]));
  assert.equal(compareAuthorization(before, after).length, 2);
  assert.deepEqual(compareAuthorization(before, before), []);
});

test('rejects malformed invocation data', () => {
  assert.throws(() => compareAuthorization([], auth({ ...call(), args: [{}] })), /argument type/);
});

test('decodes exact signed i128 values while retaining the wire encoding', () => {
  const encode = (high, low) => {
    const bytes = Buffer.alloc(20);
    bytes.writeUInt32BE(10);
    bytes.writeBigInt64BE(high, 4);
    bytes.writeBigUInt64BE(low, 12);
    return { type: 'i128', xdr: bytes.toString('base64') };
  };
  const negative = encode(-1n, (1n << 64n) - 1n);
  const large = encode(1n, 3n);
  const [change] = compareAuthorization(auth(call('transfer', [negative])), auth(call('transfer', [large])));
  assert.deepEqual(change.before, { ...negative, decimal: '-1' });
  assert.deepEqual(change.after, { ...large, decimal: '18446744073709551619' });
});

test('leaves malformed i128 strings opaque', () => {
  const [change] = compareAuthorization(auth(call('transfer', [{type:'i128',xdr:'AAAA'}])), auth(call()));
  assert.equal(change.before.decimal, undefined);
});
