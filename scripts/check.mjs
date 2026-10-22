import {readFileSync} from "node:fs";
const required=["api/index.js","public/index.html","public/app.js","public/styles.css","db/schema.sql"];
for(const file of required){try{readFileSync(file,"utf8");console.log("OK",file);}catch{console.error("MISSING",file);process.exitCode=1;}}
if(!process.env.DATABASE_URL)console.log("NOTE DATABASE_URL is not set; live database checks are skipped.");
if(!process.env.SESSION_SECRET)console.log("NOTE SESSION_SECRET is not set; live authentication checks are skipped.");
