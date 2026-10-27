import {randomUUID} from 'node:crypto';
import type {Config} from './config.js';
import {signSessionRequest} from './identity.js';
/** Trusted helper only: never return cookies, proofs or upstream error bodies. */
export async function probe(p:Config['projects'][string]) {
 const expected=p.expected;if(!expected)throw Error("EXPECTED_HANDOFF_REQUIRED");
 let cookie:string|undefined;
 const call=(path:string,method='GET',body?:unknown)=>fetch(p.origin+path,{method,headers:{...(cookie?{cookie}:{}),...(body?{'content-type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{}),redirect:'manual',signal:AbortSignal.timeout(15000)});
 const revoke=async()=>{if(!cookie)return;const r=await call('/agentdoor/revoke','POST');if(r.status!==200)throw Error('REVOCATION_FAILED');if((await call('/agentdoor/identity')).status!==403)throw Error('OLD_SESSION_ACCEPTED');cookie=undefined;};
 const login=async()=>{
  const proof=await signSessionRequest(p.auth.identityFile,p.origin,p.auth.grantId);
  const r=await call('/agentdoor/session','POST',proof);if(r.status!==201)throw Error('LOGIN_FAILED');
  cookie=r.headers.get('set-cookie')?.split(';')[0];if(!cookie)throw Error('SESSION_MISSING');
  const who=await call('/agentdoor/identity');if(who.status!==200)throw Error('IDENTITY_FAILED');const identity=await who.json();
  if(identity.grantId!==p.auth.grantId||identity.userId!==p.accountId||identity.agentId!==expected.agentId||identity.fingerprint!==expected.fingerprint||identity.paidModelCapMicrousd!==0||JSON.stringify([...identity.scopes].sort())!==JSON.stringify([...expected.scopes].sort()))throw Error('HANDOFF_MISMATCH');
 };
 try{
  await login();if((await call(p.dashboardPath)).status!==200)throw Error('WORKSPACE_FAILED');
  const note='Synthetic persistence check '+randomUUID();const saved=await call('/agentdoor/records','POST',{note});if(![200,303].includes(saved.status))throw Error('WRITE_FAILED');
  if((await call('/agentdoor/records','POST',{note,accountId:'user_other'})).status!==403)throw Error('ACCOUNT_BOUNDARY_FAILED');
  await revoke();await login();const rows=await call('/agentdoor/records');if(rows.status!==200||!(await rows.json()).records.some((r:{note:string})=>r.note===note))throw Error('PERSISTENCE_FAILED');
  await revoke();return {authenticated:true,isolatedWrite:true,crossAccountDenied:true,freshSessionPersistence:true,remoteRevocation:true,oldSessionRejected:true};
 }finally{if(cookie)await revoke();}
}
