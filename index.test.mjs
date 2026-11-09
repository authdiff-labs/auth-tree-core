import test from 'node:test';
import assert from 'node:assert/strict';
import { compareAuthorization } from './index.mjs';

const call = (method = 'transfer', args = [], children = []) => ({contract: 'example-contract', method, args, children});
const auth = (root, principal = 'example-account') => [{principal, credential: 'address-v2', root}];

test('reports nested typed argument changes at their invocation path', () => {
  const before = auth(call('pay', [], [call('transfer', [{type:'i128', xdr:'AAAA'}])]));
  const after = auth(call('pay', [], [call('transfer', [{type:'i128', xdr:'AAAB'}])]));
  assert.deepEqual(compareAuthorization(before, after).map(({kind,path}) => ({kind,path})),
    [{kind:'argument-changed', path:[0,'root','children',0,'args',0]}]);
});

test('reports a principal substitution', () => {
  assert.equal(compareAuthorization(auth(call()), auth(call(), 'other-account'))[0].kind, 'credential-changed');
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
