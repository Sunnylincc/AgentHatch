// Report paths and revision identifiers only, never matched secret values.
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
const git=(...args)=>execFileSync('git',args,{encoding:'utf8',maxBuffer:16*1024*1024});
const failures=new Set();
const safeEmail=(email)=>/^(?:[0-9]+\+)?[A-Za-z0-9_-]+@users\.noreply\.github\.com$/.test(email)||email==='noreply@github.com';
function inspect(text,label){
 const privateKey=new RegExp('-----BEGIN '+ '(?:RSA |EC |OPENSSH )?' + 'PRIVATE KEY-----');
 const providerKey=/(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{25,})/;
 if(privateKey.test(text)||providerKey.test(text))failures.add(label+': credential pattern');
 for(const email of text.match(/[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)||[])
  if(!safeEmail(email)&&!email.endsWith('@example.com')&&!email.endsWith('@example.org'))failures.add(label+': contact address');
}
try {
 const revisions=git('rev-list','--all').trim().split('\n').filter(Boolean);
 for(const revision of revisions){
  const [author,committer,...message]=git('show','-s','--format=%ae%n%ce%n%B',revision).split('\n');
  if(!safeEmail(author)||!safeEmail(committer))failures.add(revision.slice(0,7)+': non-private commit email');
  inspect(message.join('\n'),revision.slice(0,7)+' message');
  for(const file of git('ls-tree','-r','--name-only',revision).split('\n').filter(Boolean))inspect(git('show',revision+':'+file),revision.slice(0,7)+' '+file);
 }
 for(const file of git('ls-files','--cached','--others','--exclude-standard').split('\n').filter(Boolean))inspect(readFileSync(file,'utf8'),'working tree '+file);
 if(failures.size){for(const failure of failures)console.error(failure);process.exitCode=1;}
 else console.log('Privacy check passed: commit metadata, history and working tree. Pattern checks are not a guarantee.');
}catch{console.error('Privacy check could not complete; inspect repository access and file sizes. No matched values were printed.');process.exitCode=1;}
