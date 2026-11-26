import http from 'node:http';
import {randomUUID} from 'node:crypto';
import {readFile,writeFile,mkdir,cp,rm,rename,readdir,lstat,appendFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import Ajv from 'ajv';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {createMcpServer} from '../upstream/packages/core/dist/mcp/server.js';
import {READ_TOOLS,handleReadToolCall} from '../upstream/packages/core/dist/mcp/read-tools.js';
import {WRITE_TOOLS,handleWriteToolCall} from '../upstream/packages/core/dist/mcp/write-tools.js';
import {initWiki} from '../upstream/packages/core/dist/init.js';
import {createIdentityVerifier} from './identity-jws.mjs';

const data=resolve(process.env.WIKI_DATA_DIR||'/data');const root=join(data,'.wiki');
const token=(await readFile(process.env.SERVICE_TOKEN_FILE,'utf8')).trim();
const identityKey=(await readFile(process.env.IDENTITY_SECRET_FILE,'utf8')).trim();
const identityVerifier=createIdentityVerifier({
 serviceToken:token,
 identityKey,
 audience:process.env.IDENTITY_AUDIENCE,
 issuer:process.env.IDENTITY_ISSUER,
});
await mkdir(data,{recursive:true});
async function restore(){await rm(root,{recursive:true,force:true});await cp(join(data,'rollback'),root,{recursive:true});await rm(join(data,'pending'),{force:true});}
try{await lstat(join(data,'pending'));await restore();}catch(e){if(e.code!=='ENOENT')throw e;}
await initWiki(data);process.chdir(root);
const writes=new Set(WRITE_TOOLS.map(t=>t.name));const ajv=new Ajv({strict:false});
const validators=new Map([...READ_TOOLS,...WRITE_TOOLS].map(t=>[t.name,ajv.compile(t.inputSchema)]));
async function noLinks(path){for(const e of await readdir(path,{withFileTypes:true})){if(e.isSymbolicLink())throw Error('UNSAFE_PATH');if(e.isDirectory())await noLinks(join(path,e.name));}}
function paths(args){for(const k of ['path','pagePath','sourcePath']){if(args[k]!==undefined){const v=args[k];if(typeof v!=='string'||v.startsWith('/')||/[\\\x00%]/.test(v)||v.split('/').some(x=>x==='..'||x==='.'))throw Error('UNSAFE_PATH');if(k==='sourcePath'&&!v.startsWith('raw/'))throw Error('SOURCE_MUST_BE_IN_RAW');}}}
let queue=Promise.resolve();let stopping=false;
const app=http.createServer(async(req,res)=>{
 if(req.url==='/health'&&req.method==='GET'){res.writeHead(stopping?503:200,{'content-type':'application/json'});res.end('{"status":"ready"}');return;}
 if(req.url!=='/mcp'){res.writeHead(404);res.end();return;}
 try{identityVerifier.authenticateService(req.headers);}catch{res.writeHead(401);res.end();return;}
 if(req.method!=='POST'){res.writeHead(405);res.end();return;}
 let body;try{let bytes=0;const chunks=[];for await(const chunk of req){bytes+=chunk.length;if(bytes>2_000_000)throw Error();chunks.push(chunk);}body=JSON.parse(Buffer.concat(chunks).toString());if(!body||Array.isArray(body))throw Error();}catch{res.writeHead(400);res.end();return;}
 let identity;try{identity=identityVerifier.resolveIdentity(req.headers,body);}catch{res.writeHead(401);res.end();return;}
 if(!identity&&!['initialize','ping','tools/list','notifications/initialized'].includes(body.method)){res.writeHead(403);res.end();return;}
 let release;const previous=queue;queue=new Promise(r=>release=r);await previous;
 const server=createMcpServer(root);const transport=new StreamableHTTPServerTransport({sessionIdGenerator:undefined,enableJsonResponse:true});
 server.setRequestHandler(CallToolRequestSchema,async request=>{
  const {name,arguments:args={}}=request.params;let pending=false;const id=randomUUID();
  try{
   if(!identity)throw Error('IDENTITY_REQUIRED');if(!validators.get(name)?.(args))throw Error('INVALID_ARGUMENT');paths(args);await noLinks(root);
   if(writes.has(name)){
    await rm(join(data,'rollback'),{recursive:true,force:true});await cp(root,join(data,'rollback'),{recursive:true});
    await writeFile(join(data,'pending'),id);pending=true;
   }
   const text=await (writes.has(name)?handleWriteToolCall:handleReadToolCall)(name,args,root);
   // Upstream may return a structured error instead of throwing.
   let structured;try{structured=JSON.parse(text);}catch{}
   if(structured?.status==='error'||structured?.ingest?.status==='error')throw Error('OPERATION_FAILED');
   await appendFile(join(data,'audit.jsonl'),JSON.stringify({at:new Date().toISOString(),id,tool:name,outcome:'success'})+'\n');
   if(pending){await rm(join(data,'pending'));pending=false;}
   return {content:[{type:'text',text}]};
  }catch(e){if(pending){try{await restore();}catch{stopping=true;process.exitCode=1;throw Error('RECOVERY_REQUIRED');}}
   const code=['INVALID_ARGUMENT','UNSAFE_PATH','SOURCE_MUST_BE_IN_RAW','IDENTITY_REQUIRED'].includes(e.message)?e.message:'WIKI_OPERATION_FAILED';
   return {isError:true,content:[{type:'text',text:code}]};}
 });
 try{if(stopping)throw Error();await noLinks(root);await server.connect(transport);await transport.handleRequest(req,res,body);}catch{if(!res.headersSent){res.writeHead(500);res.end('{"error":"WIKI_UNAVAILABLE"}');}}finally{await server.close().catch(()=>{});release();}
});
app.requestTimeout=30000;app.headersTimeout=15000;
app.listen(Number(process.env.PORT||8060),'0.0.0.0',()=>console.log('{"event":"wiki_started"}'));
process.on('SIGTERM',()=>{stopping=true;app.close(()=>process.exit(0));});
