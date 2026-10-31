import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomUUID} from 'node:crypto';
import {prepareEnrollment,fingerprintPublicKey} from '../src/enrollment.js';
import {createDelegation,MemoryDelegationStore} from '../src/delegation.js';
test('preparation is disabled, unique per key and refuses caller authority',async()=>{
 const pair=generateKeyPairSync('ed25519');const publicKey=pair.publicKey.export({format:'pem',type:'spki'}).toString();
 const input={client:'qa-agent',project:'sample',publicKey,scopes:['workspace:read']};
 const grant=prepareEnrollment(input);const another=prepareEnrollment(input);
 assert.equal(grant.enabled,false);assert.equal(grant.status,'pending');assert.notEqual(grant.userId,another.userId);assert.notEqual(grant.id,another.id);
 assert.equal(grant.fingerprint,fingerprintPublicKey(publicKey));
 assert.throws(()=>prepareEnrollment({...input,enabled:true}));assert.throws(()=>prepareEnrollment({...input,scopes:['admin']}));
 const origin='https://app.example.com';
 // Even accidentally toggling enabled cannot replace a recorded approval.
 const sdk=createDelegation({origin,store:new MemoryDelegationStore(),getGrant:async()=>({...grant,enabled:true})});
 const payload=Buffer.from(JSON.stringify({v:1,audience:origin,grantId:grant.id,nonce:randomUUID(),issuedAt:Date.now()})).toString('base64url');
 const r=await sdk.handle(new Request(origin+'/agentdoor/session',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({payload,signature:sign(null,Buffer.from(payload),pair.privateKey).toString('base64url')})}));
 assert.equal(r.status,403);
});
