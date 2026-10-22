import pg from "pg";
import bcrypt from "bcryptjs";
const {Pool}=pg;
const username=(process.env.ADMIN_USERNAME||"admin").trim().toLowerCase();
const password=process.env.ADMIN_PASSWORD;
const fullName=process.env.ADMIN_FULL_NAME||"JUSeeds Administrator";
if(!process.env.DATABASE_URL){console.error("DATABASE_URL is required.");process.exit(1);}
if(!password||password.length<14){console.error("Set a unique ADMIN_PASSWORD with at least 14 characters.");process.exit(1);}
if(!/^[a-z0-9._-]{3,40}$/.test(username)){console.error("ADMIN_USERNAME must be 3-40 lowercase letters, numbers, dots, underscores or hyphens.");process.exit(1);}
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==="false"?false:{rejectUnauthorized:true},max:1,connectionTimeoutMillis:8000});
try{
 const client=await pool.connect();
 try{
  await client.query("BEGIN");
  await client.query("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE");
  const existing=await client.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
  if(existing.rowCount)throw new Error("An administrator already exists. This script will not overwrite an existing admin.");
  const hash=await bcrypt.hash(password,12);
  const created=await client.query("INSERT INTO users(username,password_hash,full_name,role,active) VALUES($1,$2,$3,'admin',TRUE) RETURNING id",[username,hash,fullName]);
  await client.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id) VALUES($1,'admin.created','user',$2)",[created.rows[0].id,String(created.rows[0].id)]);
  await client.query("COMMIT");
  console.log("Administrator created. Store the password securely; it will not be printed.");
 }catch(e){await client.query("ROLLBACK").catch(()=>{});throw e;}finally{client.release();}
}catch(e){console.error("Administrator setup failed:",e.message);process.exitCode=1;}finally{await pool.end();}
