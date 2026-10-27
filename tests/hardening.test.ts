import {test} from 'node:test';
import assert from 'node:assert/strict';
import {revokeAndClose} from '../src/cleanup.js';
import {sessionAdmission} from '../src/rate-limit.js';
import {createDelegation,MemoryDelegationStore} from '../src/delegation.js';

test('failed remote revocation still closes context and browser and reports failure',async()=>{
 const events:string[]=[];
 await assert.rejects(revokeAndClose({revoke:async()=>{events.push('revoke');throw Error('private upstream detail');},closeContext:async()=>{events.push('context');},closeBrowser:async()=>{events.push('browser');}}),/^Error: SESSION_CLEANUP_FAILED$/);
 assert.deepEqual(events,['revoke','context','browser']);
});
test('context close failure still releases browser',async()=>{
 let closed=false;
 await assert.rejects(revokeAndClose({revoke:async()=>{},closeContext:async()=>{throw Error('failed');},closeBrowser:async()=>{closed=true;}}));
 assert.equal(closed,true);
});
test('successful cleanup completes without failure',async()=>{
 await revokeAndClose({revoke:async()=>{},closeContext:async()=>{},closeBrowser:async()=>{}});
});
test('admission rejects a burst and recovers after the window',()=>{
 const clock=Date.now;let now=1000;Date.now=()=>now;
 try {const admit=sessionAdmission(2,100);assert.equal(admit(),true);assert.equal(admit(),true);assert.equal(admit(),false);now+=100;assert.equal(admit(),true);} finally {Date.now=clock;}
});
test('shared admission denies before proof parsing or grant lookup',async()=>{
 const sdk=createDelegation({origin:'https://app.example.com',store:new MemoryDelegationStore(),getGrant:async()=>{throw Error('must not reach');},admitSession:async()=>false});
 const response=await sdk.handle(new Request('https://app.example.com/agentdoor/session',{method:'POST',headers:{'content-type':'application/json'},body:'invalid'}));
 assert.equal(response.status,429);assert.deepEqual(await response.json(),{error:'SESSION_RATE_LIMITED'});
});
