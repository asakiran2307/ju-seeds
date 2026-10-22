const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

let pool;
function db() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_NOT_CONFIGURED");
  if (!pool) pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSL === "false" ? false : { rejectUnauthorized: true },
    max: 5,
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 8000
  });
  return pool;
}
function json(res, status, body, extra = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  for (const [key, value] of Object.entries(extra)) res.setHeader(key, value);
  res.end(JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", chunk => {
      raw += chunk;
      if (raw.length > 1024 * 1024) {
        reject(new Error("BODY_TOO_LARGE"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { reject(new Error("INVALID_JSON")); }
    });
    req.on("error", reject);
  });
}
function cookies(req) {
  const result = {};
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) result[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return result;
}
function secureCookie(req) {
  return process.env.NODE_ENV === "production" || (req.headers["x-forwarded-proto"] || "").includes("https");
}
function cookieHeader(req, value, maxAge) {
  return "ju_session=" + encodeURIComponent(value) + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + maxAge + (secureCookie(req) ? "; Secure" : "");
}
function safeEqual(a, b) {
  const x = Buffer.from(String(a || ""));
  const y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
async function currentUser(req) {
  const token = cookies(req).ju_session;
  if (!token || !process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) return null;
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const q = await db().query(
    "SELECT u.id,u.username,u.full_name,u.role,u.school_id,u.team_id,u.active FROM app_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.expires_at>NOW() AND u.active=TRUE",
    [tokenHash]
  );
  return q.rows[0] || null;
}
function requireRole(user, roles) {
  return Boolean(user && roles.includes(user.role));
}
async function audit(client, actor, action, entityType, entityId, metadata = {}) {
  await client.query(
    "INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES($1,$2,$3,$4,$5::jsonb)",
    [actor ? actor.id : null, action, entityType, entityId == null ? null : String(entityId), JSON.stringify(metadata)]
  );
}
async function createReference(client) {
  const result = await client.query("INSERT INTO visit_reference_counter DEFAULT VALUES RETURNING id");
  return "JU-" + new Date().getFullYear() + "-" + String(result.rows[0].id).padStart(6, "0");
}
function fail(res, status, code, message) { return json(res, status, { error: code, message }); }

module.exports = async function handler(req, res) {
  const url = new URL(req.url, "https://juseeds.invalid");
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = req.method || "GET";
  try {
    if (method === "GET" && path === "/api/health") {
      return json(res, 200, { ok: true, service: "JUSeeds API", databaseConfigured: Boolean(process.env.DATABASE_URL), sessionConfigured: Boolean(process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 32) });
    }
    if (method === "POST" && path === "/api/auth/login") {
      const body = await readBody(req);
      const username = String(body.username || "").trim().toLowerCase();
      const password = String(body.password || "");
      if (!/^[a-z0-9._-]{3,40}$/.test(username) || !password || password.length > 256) return fail(res, 400, "INVALID_INPUT", "Enter a valid username and password.");
      if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) return fail(res, 503, "AUTH_NOT_CONFIGURED", "Login is not configured yet. Contact the system administrator.");
      const ip = String(req.headers["x-real-ip"] || (req.headers["x-forwarded-for"] || "").split(",")[0] || "unknown").trim().slice(0,80);
      const recent = await db().query("SELECT COUNT(*)::int AS count FROM login_attempts WHERE username=$1 AND ip_address=$2 AND attempted_at>NOW()-INTERVAL '15 minutes'", [username,ip]);
      if (recent.rows[0].count >= 8) return fail(res, 429, "RATE_LIMITED", "Too many sign-in attempts. Wait 15 minutes and try again.");
      await db().query("INSERT INTO login_attempts(username,ip_address) VALUES($1,$2)", [username,ip]);
      const result = await db().query("SELECT id,username,password_hash,active FROM users WHERE username=$1 LIMIT 1", [username]);
      const user = result.rows[0];
      const valid = user && user.active && await bcrypt.compare(password, user.password_hash);
      if (!valid) {
        await new Promise(resolve => setTimeout(resolve, 250));
        return fail(res, 401, "INVALID_CREDENTIALS", "Username or password is incorrect.");
      }
      await db().query("DELETE FROM login_attempts WHERE username=$1 AND ip_address=$2", [username,ip]);
      const token = crypto.randomBytes(32).toString("base64url");
      const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
      await db().query("INSERT INTO app_sessions(id,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '12 hours')", [tokenHash, user.id]);
      return json(res, 200, { ok: true }, { "Set-Cookie": cookieHeader(req, token, 43200) });
    }
    if (method === "POST" && path === "/api/auth/logout") {
      const token = cookies(req).ju_session;
      if (token) await db().query("DELETE FROM app_sessions WHERE id=$1", [crypto.createHash("sha256").update(token).digest("hex")]);
      return json(res, 200, { ok: true }, { "Set-Cookie": cookieHeader(req, "", 0) });
    }
    if (method === "GET" && path === "/api/auth/me") {
      const user = await currentUser(req);
      if (!user) return fail(res, 401, "UNAUTHENTICATED", "Please sign in.");
      return json(res, 200, { user });
    }

    // One-time bootstrap: requires a strong server-side token, and refuses if any admin exists.
    if (method === "POST" && path === "/api/setup/admin") {
      const configured = process.env.ADMIN_BOOTSTRAP_TOKEN;
      if (!configured || configured.length < 32) return fail(res, 404, "NOT_AVAILABLE", "Setup endpoint is not enabled.");
      const body = await readBody(req);
      if (!safeEqual(req.headers["x-bootstrap-token"], configured)) return fail(res, 403, "FORBIDDEN", "Setup token is invalid.");
      const username = String(body.username || "admin").trim().toLowerCase();
      const password = String(body.password || "");
      const fullName = String(body.fullName || "JUSeeds Administrator").trim().slice(0, 120);
      if (!/^[a-z0-9._-]{3,40}$/.test(username) || password.length < 14 || password.length > 256) return fail(res, 400, "INVALID_INPUT", "Username must be 3-40 valid characters and password at least 14 characters.");
      const client = await db().connect();
      try {
        await client.query("BEGIN");
        await client.query("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE");
        const existing = await client.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
        if (existing.rowCount) {
          await client.query("ROLLBACK");
          return fail(res, 409, "ADMIN_EXISTS", "An administrator already exists; setup cannot overwrite it.");
        }
        const hash = await bcrypt.hash(password, 12);
        const created = await client.query("INSERT INTO users(username,password_hash,full_name,role,active) VALUES($1,$2,$3,'admin',TRUE) RETURNING id", [username, hash, fullName]);
        await audit(client, { id: created.rows[0].id }, "admin.bootstrap", "user", created.rows[0].id);
        await client.query("COMMIT");
        return json(res, 201, { ok: true, message: "Administrator created. Remove ADMIN_BOOTSTRAP_TOKEN from Vercel now." });
      } catch (e) {
        await client.query("ROLLBACK").catch(() => {});
        throw e;
      } finally { client.release(); }
    }

    const user = await currentUser(req);
    if (!user) return fail(res, 401, "UNAUTHENTICATED", "Please sign in.");
    if (method === "GET" && path === "/api/dashboard") {
      let scope = "";
      const values = [];
      if (user.role === "school_user") { scope = " WHERE school_id=$1 AND team_id=$2"; values.push(user.school_id, user.team_id); }
      else if (user.role === "in_charge") {
        const assignments = await db().query("SELECT school_id,team_id FROM in_charge_assignments WHERE user_id=$1 AND active=TRUE", [user.id]);
        if (!assignments.rowCount) return json(res, 200, { counts: {}, recent: [] });
        const schoolIds = [...new Set(assignments.rows.map(x => x.school_id))];
        scope = " WHERE school_id = ANY($1::bigint[])";
        values.push(schoolIds);
      }
      const counts = await db().query("SELECT status,COUNT(*)::int AS count FROM visit_plans" + scope + " GROUP BY status", values);
      const recent = await db().query("SELECT v.id,v.reference_number,v.title,v.destination,v.visit_date,v.status,s.name AS school_name,t.name AS team_name FROM visit_plans v JOIN schools s ON s.id=v.school_id JOIN teams t ON t.id=v.team_id" + (scope ? scope.replaceAll("school_id", "v.school_id").replaceAll("team_id", "v.team_id") : "") + " ORDER BY v.updated_at DESC LIMIT 8", values);
      return json(res, 200, { counts: Object.fromEntries(counts.rows.map(x => [x.status, x.count])), recent: recent.rows });
    }
    if (method === "GET" && path === "/api/schools") {
      if (user.role !== "admin") {
        const rows = await db().query("SELECT DISTINCT s.id,s.name,s.code,s.active FROM schools s LEFT JOIN in_charge_assignments a ON a.school_id=s.id AND a.active=TRUE WHERE (s.id=$1 OR a.user_id=$2) AND s.active=TRUE ORDER BY s.name", [user.school_id, user.id]);
        return json(res, 200, { schools: rows.rows });
      }
      const rows = await db().query("SELECT s.id,s.name,s.code,s.description,s.active,COUNT(DISTINCT t.id)::int AS team_count FROM schools s LEFT JOIN teams t ON t.school_id=s.id GROUP BY s.id ORDER BY s.name");
      return json(res, 200, { schools: rows.rows });
    }
    if (method === "POST" && path === "/api/schools") {
      if (!requireRole(user, ["admin"])) return fail(res, 403, "FORBIDDEN", "Administrator access required.");
      const b = await readBody(req); const name = String(b.name || "").trim(); const code = String(b.code || "").trim().toUpperCase();
      if (name.length < 2 || name.length > 120 || !/^[A-Z0-9_-]{2,20}$/.test(code)) return fail(res, 400, "INVALID_INPUT", "Provide a school name and a code (2-20 letters, numbers, _ or -).");
      const r = await db().query("INSERT INTO schools(name,code,description) VALUES($1,$2,$3) RETURNING id,name,code,description,active", [name, code, String(b.description || "").slice(0,1000)]);
      await db().query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id) VALUES($1,'school.created','school',$2)", [user.id, String(r.rows[0].id)]);
      return json(res, 201, { school: r.rows[0] });
    }
    if (method === "GET" && path === "/api/teams") {
      const schoolId = url.searchParams.get("schoolId");
      if (user.role === "school_user" && Number(schoolId) !== Number(user.school_id)) return fail(res, 403, "FORBIDDEN", "You cannot access this school.");
      const result = await db().query("SELECT id,school_id,name,code,active FROM teams WHERE ($1::bigint IS NULL OR school_id=$1) AND active=TRUE ORDER BY name", [schoolId || null]);
      return json(res, 200, { teams: result.rows });
    }
    if (method === "GET" && path === "/api/visits") {
      const values = []; let where = [];
      if (user.role === "school_user") { values.push(user.school_id, user.team_id); where.push("v.school_id=$1 AND v.team_id=$2"); }
      if (user.role === "in_charge") {
        values.push(user.id);
        where.push("EXISTS (SELECT 1 FROM in_charge_assignments a WHERE a.user_id=$1 AND a.active=TRUE AND a.school_id=v.school_id AND (a.team_id IS NULL OR a.team_id=v.team_id))");
      }
      const result = await db().query("SELECT v.id,v.reference_number,v.title,v.destination,v.destination_address,v.visit_date,v.start_time,v.end_time,v.purpose,v.objectives,v.participants,v.requirements,v.notes,v.status,v.school_id,v.team_id,v.created_by,v.created_at,v.updated_at,s.name AS school_name,t.name AS team_name FROM visit_plans v JOIN schools s ON s.id=v.school_id JOIN teams t ON t.id=v.team_id" + (where.length ? " WHERE " + where.join(" AND ") : "") + " ORDER BY v.updated_at DESC LIMIT 250", values);
      return json(res, 200, { visits: result.rows });
    }
    if (method === "POST" && path === "/api/visits") {
      if (!requireRole(user, ["admin", "school_user"])) return fail(res, 403, "FORBIDDEN", "Only school users or administrators can create plans.");
      const b = await readBody(req);
      const schoolId = user.role === "school_user" ? user.school_id : Number(b.schoolId);
      const teamId = user.role === "school_user" ? user.team_id : Number(b.teamId);
      const title = String(b.title || "").trim();
      if (!Number.isInteger(Number(schoolId)) || !Number.isInteger(Number(teamId)) || title.length < 3 || title.length > 180) return fail(res, 400, "INVALID_INPUT", "Choose a school and team and enter a visit title.");
      const scope = await db().query("SELECT 1 FROM teams WHERE id=$1 AND school_id=$2 AND active=TRUE", [teamId, schoolId]);
      if (!scope.rowCount) return fail(res, 400, "INVALID_SCOPE", "The selected team does not belong to that school.");
      const client = await db().connect();
      try {
        await client.query("BEGIN");
        const reference = await createReference(client);
        const result = await client.query("INSERT INTO visit_plans(reference_number,created_by,school_id,team_id,title,destination,destination_address,visit_date,start_time,end_time,purpose,objectives,participants,requirements,notes,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'draft') RETURNING *",
          [reference,user.id,schoolId,teamId,title,String(b.destination||"").slice(0,180),String(b.destinationAddress||"").slice(0,300),b.visitDate||null,b.startTime||null,b.endTime||null,String(b.purpose||"").slice(0,3000),String(b.objectives||"").slice(0,3000),String(b.participants||"").slice(0,3000),String(b.requirements||"").slice(0,3000),String(b.notes||"").slice(0,3000)]);
        await audit(client,user,"visit.created","visit_plan",result.rows[0].id,{reference_number:reference});
        await client.query("COMMIT");
        return json(res,201,{visit:result.rows[0]});
      } catch(e) { await client.query("ROLLBACK").catch(()=>{}); throw e; } finally { client.release(); }
    }
    const visitMatch = path.match(/^\/api\/visits\/(\d+)(?:\/(submit|review|complete|report|accept-report))?$/);
    if (visitMatch) {
      const id = Number(visitMatch[1]); const action = visitMatch[2] || "";
      const visitResult = await db().query("SELECT * FROM visit_plans WHERE id=$1", [id]);
      const visit = visitResult.rows[0];
      if (!visit) return fail(res,404,"NOT_FOUND","Visit plan not found.");
      if (user.role === "school_user" && (Number(visit.school_id)!==Number(user.school_id) || Number(visit.team_id)!==Number(user.team_id) || Number(visit.created_by)!==Number(user.id))) return fail(res,403,"FORBIDDEN","You can only access your own visit plans.");
      if (user.role === "in_charge") {
        const a = await db().query("SELECT 1 FROM in_charge_assignments WHERE user_id=$1 AND school_id=$2 AND (team_id IS NULL OR team_id=$3) AND active=TRUE", [user.id,visit.school_id,visit.team_id]);
        if (!a.rowCount) return fail(res,403,"FORBIDDEN","This visit is outside your assignment.");
      }
      if (method === "GET" && !action) return json(res,200,{visit});
      if (method !== "POST") return fail(res,405,"METHOD_NOT_ALLOWED","Use POST for workflow actions.");
      const b = await readBody(req);
      const client = await db().connect();
      try {
        await client.query("BEGIN");
        let updated;
        if (action === "submit") {
          if (!["school_user","admin"].includes(user.role) || !["draft","rejected"].includes(visit.status)) { await client.query("ROLLBACK"); return fail(res,409,"INVALID_TRANSITION","Only a draft or rejected visit can be submitted."); }
          updated = await client.query("UPDATE visit_plans SET status='pending',submitted_at=NOW(),updated_at=NOW() WHERE id=$1 RETURNING *",[id]);
          await audit(client,user,"visit.submitted","visit_plan",id);
        } else if (action === "review") {
          if (!["admin","in_charge"].includes(user.role) || !["pending"].includes(visit.status)) { await client.query("ROLLBACK"); return fail(res,409,"INVALID_TRANSITION","Only pending visits can be reviewed by an approver."); }
          const decision = b.decision;
          if (!["approved","rejected","correction_requested"].includes(decision)) { await client.query("ROLLBACK"); return fail(res,400,"INVALID_DECISION","Decision must be approved, rejected, or correction_requested."); }
          const next = decision === "approved" ? "approved" : "rejected";
          updated = await client.query("UPDATE visit_plans SET status=$2,updated_at=NOW() WHERE id=$1 RETURNING *",[id,next]);
          await client.query("INSERT INTO visit_reviews(visit_plan_id,reviewer_id,decision,remarks) VALUES($1,$2,$3,$4)",[id,user.id,decision,String(b.remarks||"").slice(0,3000)]);
          await audit(client,user,"visit.reviewed","visit_plan",id,{decision});
        } else if (action === "complete") {
          if (!["school_user","admin"].includes(user.role) || visit.status!=="approved") { await client.query("ROLLBACK"); return fail(res,409,"INVALID_TRANSITION","Only approved visits can be marked completed."); }
          updated = await client.query("UPDATE visit_plans SET status='completed',completed_at=NOW(),updated_at=NOW() WHERE id=$1 RETURNING *",[id]);
          await audit(client,user,"visit.completed","visit_plan",id);
        } else if (action === "report") {
          if (!["school_user","admin"].includes(user.role) || visit.status!=="completed") { await client.query("ROLLBACK"); return fail(res,409,"INVALID_TRANSITION","Complete the visit before submitting its report."); }
          const reportContent = b.report && typeof b.report==="object" ? b.report : {};
          const result = await client.query("INSERT INTO visit_reports(visit_plan_id,submitted_by,report_content,status) VALUES($1,$2,$3::jsonb,'submitted') ON CONFLICT(visit_plan_id) DO UPDATE SET submitted_by=EXCLUDED.submitted_by,report_content=EXCLUDED.report_content,status='submitted',submitted_at=NOW(),updated_at=NOW() RETURNING *",[id,user.id,JSON.stringify(reportContent)]);
          updated = await client.query("UPDATE visit_plans SET status='report_submitted',updated_at=NOW() WHERE id=$1 RETURNING *",[id]);
          await audit(client,user,"visit.report_submitted","visit_report",result.rows[0].id);
        } else if (action === "accept-report") {
          if (!["admin","in_charge"].includes(user.role) || visit.status!=="report_submitted") { await client.query("ROLLBACK"); return fail(res,409,"INVALID_TRANSITION","Only submitted reports can be reviewed."); }
          const decision = b.decision === "correction_requested" ? "correction_requested" : "report_accepted";
          const reportStatus = decision === "report_accepted" ? "accepted" : "correction_requested";
          await client.query("UPDATE visit_reports SET status=$2,reviewed_by=$3,reviewed_at=NOW(),review_remarks=$4,updated_at=NOW() WHERE visit_plan_id=$1",[id,reportStatus,user.id,String(b.remarks||"").slice(0,3000)]);
          updated = await client.query("UPDATE visit_plans SET status=$2,updated_at=NOW() WHERE id=$1 RETURNING *",[id,decision==="report_accepted"?"report_accepted":"completed"]);
          await client.query("INSERT INTO visit_reviews(visit_plan_id,reviewer_id,decision,remarks) VALUES($1,$2,$3,$4)",[id,user.id,decision,String(b.remarks||"").slice(0,3000)]);
          await audit(client,user,"visit.report_reviewed","visit_plan",id,{decision});
        } else {
          await client.query("ROLLBACK");
          return fail(res,404,"NOT_FOUND","Unknown workflow action.");
        }
        await client.query("COMMIT");
        return json(res,200,{visit:updated.rows[0]});
      } catch(e) { await client.query("ROLLBACK").catch(()=>{}); throw e; } finally { client.release(); }
    }
    if (method === "GET" && path === "/api/assignments") {
      if (!requireRole(user, ["admin"])) return fail(res, 403, "FORBIDDEN", "Administrator access required.");
      const result = await db().query("SELECT a.id,a.user_id,a.school_id,a.team_id,a.active,u.username,u.full_name,s.name AS school_name,t.name AS team_name FROM in_charge_assignments a JOIN users u ON u.id=a.user_id JOIN schools s ON s.id=a.school_id LEFT JOIN teams t ON t.id=a.team_id WHERE a.active=TRUE ORDER BY s.name,u.full_name,t.name");
      return json(res, 200, { assignments: result.rows });
    }
    if (method === "POST" && path === "/api/assignments") {
      if (!requireRole(user, ["admin"])) return fail(res, 403, "FORBIDDEN", "Administrator access required.");
      const b = await readBody(req);
      const userId = Number(b.userId), schoolId = Number(b.schoolId), teamId = b.teamId ? Number(b.teamId) : null;
      const target = await db().query("SELECT id,role FROM users WHERE id=$1 AND active=TRUE", [userId]);
      if (!target.rowCount || target.rows[0].role !== "in_charge") return fail(res, 400, "INVALID_USER", "Select an active In-Charge account.");
      if (!Number.isInteger(schoolId)) return fail(res, 400, "INVALID_INPUT", "Select a school.");
      if (teamId) { const team = await db().query("SELECT 1 FROM teams WHERE id=$1 AND school_id=$2 AND active=TRUE", [teamId,schoolId]); if (!team.rowCount) return fail(res,400,"INVALID_SCOPE","Team must belong to the selected school."); }
      const result = await db().query("INSERT INTO in_charge_assignments(user_id,school_id,team_id,assigned_by,active) VALUES($1,$2,$3,$4,TRUE) RETURNING id,user_id,school_id,team_id,active", [userId,schoolId,teamId,user.id]);
      await db().query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES($1,'in_charge.assigned','assignment',$2,$3::jsonb)", [user.id,String(result.rows[0].id),JSON.stringify({userId,schoolId,teamId})]);
      return json(res,201,{assignment:result.rows[0]});
    }
    if (method === "GET" && path === "/api/users") {
      if (!requireRole(user,["admin"])) return fail(res,403,"FORBIDDEN","Administrator access required.");
      const result = await db().query("SELECT id,username,full_name,role,school_id,team_id,active,created_at FROM users ORDER BY created_at DESC LIMIT 500");
      return json(res,200,{users:result.rows});
    }
    if (method === "POST" && path === "/api/users") {
      if (!requireRole(user,["admin"])) return fail(res,403,"FORBIDDEN","Administrator access required.");
      const b=await readBody(req); const username=String(b.username||"").trim().toLowerCase(); const password=String(b.password||""); const fullName=String(b.fullName||"").trim(); const role=String(b.role||"");
      const schoolId=b.schoolId ? Number(b.schoolId) : null; const teamId=b.teamId ? Number(b.teamId) : null;
      if (!/^[a-z0-9._-]{3,40}$/.test(username)||password.length<14||password.length>256||fullName.length<2||fullName.length>120||!["admin","in_charge","school_user"].includes(role)) return fail(res,400,"INVALID_INPUT","Check username, full name, role and password (minimum 14 characters).");
      if (role!=="admin"&&!schoolId) return fail(res,400,"INVALID_INPUT","School is required for this role.");
      if (role==="school_user"&&!teamId) return fail(res,400,"INVALID_INPUT","Team is required for a school user.");
      if (teamId) { const check=await db().query("SELECT 1 FROM teams WHERE id=$1 AND school_id=$2",[teamId,schoolId]); if(!check.rowCount) return fail(res,400,"INVALID_SCOPE","Team must belong to the selected school."); }
      const hash=await bcrypt.hash(password,12);
      const result=await db().query("INSERT INTO users(username,password_hash,full_name,role,school_id,team_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,username,full_name,role,school_id,team_id,active,created_at",[username,hash,fullName,role,schoolId,teamId]);
      await db().query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id) VALUES($1,'user.created','user',$2)",[user.id,String(result.rows[0].id)]);
      return json(res,201,{user:result.rows[0]});
    }
    if (method === "POST" && path === "/api/teams") {
      if (!requireRole(user,["admin"])) return fail(res,403,"FORBIDDEN","Administrator access required.");
      const b=await readBody(req); const schoolId=Number(b.schoolId); const name=String(b.name||"").trim(); const code=String(b.code||"").trim().toUpperCase();
      if(!Number.isInteger(schoolId)||name.length<2||name.length>120||!/^[A-Z0-9_-]{2,20}$/.test(code)) return fail(res,400,"INVALID_INPUT","Provide a school, team name and valid code.");
      const result=await db().query("INSERT INTO teams(school_id,name,code) VALUES($1,$2,$3) RETURNING *",[schoolId,name,code]);
      await db().query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id) VALUES($1,'team.created','team',$2)",[user.id,String(result.rows[0].id)]);
      return json(res,201,{team:result.rows[0]});
    }
    return fail(res,404,"NOT_FOUND","API route not found.");
  } catch (error) {
    const known = {
      DATABASE_NOT_CONFIGURED: [503,"DATABASE_NOT_CONFIGURED","Database connection is not configured."],
      INVALID_JSON: [400,"INVALID_JSON","Request body must be valid JSON."],
      BODY_TOO_LARGE: [413,"BODY_TOO_LARGE","Request body is too large."]
    };
    const e = known[error.message];
    if (e) return fail(res,e[0],e[1],e[2]);
    if (error.code === "23505") return fail(res,409,"DUPLICATE","A record with that unique value already exists.");
    if (error.code === "23503" || error.code === "23514") return fail(res,400,"INVALID_DATA","The submitted data does not satisfy database rules.");
    console.error("JUSeeds API error:", error.code || error.name || "Error");
    return fail(res,503,"SERVICE_UNAVAILABLE","The service is temporarily unavailable. Verify database configuration and schema.");
  }
};