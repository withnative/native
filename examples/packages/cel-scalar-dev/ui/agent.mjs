// Connection wrapper only: no package, provider, formula or tool instructions.
// Keep the connection file private. Local stdio authority is filesystem-owned.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
const path=process.argv[2];
if(!path)throw new Error("private connection file required");
const state=JSON.parse(await readFile(path,"utf8"));
if(state.stage!=="v2-ready"||!state.packageUI?.agent_binding)throw new Error("retained v2 fixture not ready");
// The unoptimized stdio request path runs on Tokio's current/main thread.
// RUST_MIN_STACK cannot enlarge that existing OS thread. Bound this disposable
// Linux proof process explicitly; never change the caller or retained host.
if(process.platform!=="linux")throw new Error("local development stdio proof requires Linux prlimit (util-linux)");
const binary=fileURLToPath(new URL("../../../../target/debug/mcp-stdio",import.meta.url));
const child=spawn("prlimit",["--stack=67108864:67108864","--",binary,"--kernel-v2","--account",state.packageUI.agent_binding,state.dbPath],{stdio:"inherit"});
child.once("error",error=>{console.error(`local development stdio requires prlimit for its bounded 64 MiB process stack: ${error.message}`);process.exitCode=1;});
child.once("exit",code=>{process.exitCode=code??1;});
for(const signal of ["SIGINT","SIGTERM"])process.once(signal,()=>child.kill(signal));
