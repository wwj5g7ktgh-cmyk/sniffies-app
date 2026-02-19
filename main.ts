#!/usr/bin/env -S deno run --unstable --allow-all

import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { expandGlob } from "https://deno.land/std@0.208.0/fs/mod.ts";
import { readLineSync } from "https://deno.land/std@0.208.0/io/mod.ts";

// ==============================================================================
// CONFIGURATION & STATE
// ==============================================================================

interface AppConfig {
  port: number;
  host: string;
  databasePath: string;
  isInitialized: boolean;
}

interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  createdAt: number;
}

interface Session {
  token: string;
  userId: string;
  expiresAt: number;
}

// In-memory storage (in production: use a database)
const users = new Map<string, User>();
const sessions = new Map<string, Session>();
const config: AppConfig = {
  port: 8080,
  host: "localhost",
  databasePath: "./.sniffies_db",
  isInitialized: false,
};

// ==============================================================================
// INITIALIZATION & SETUP
// ==============================================================================

async function initializeApp(): Promise<boolean> {
  console.log("\n🔧 SNIFFIES APP - INITIALIZATION WIZARD\n");
  console.log("Welcome to Sniffies. Let's set up your instance.\n");

  // Check if already initialized
  try {
    await Deno.stat(config.databasePath);
    console.log("⚠️  Database already exists. Continue with existing data? (y/n)");
    const response = readLineSync();
    if (response.toLowerCase() !== "y") {
      console.log("Aborting initialization.");
      return false;
    }
  } catch {
    // Database doesn't exist, proceed with new setup
    await Deno.mkdir(config.databasePath, { recursive: true });
    console.log("✅ Database directory created.");
  }

  // Configure port
  console.log(
    `\nConfigure server port (default: ${config.port}): `,
  );
  const portInput = readLineSync();
  if (portInput && !isNaN(parseInt(portInput))) {
    config.port = parseInt(portInput);
  }

  // Configure host
  console.log(
    `Configure server host (default: ${config.host}): `,
  );
  const hostInput = readLineSync();
  if (hostInput) {
    config.host = hostInput;
  }

  // Create admin user
  console.log("\n👤 CREATE ADMINISTRATOR ACCOUNT\n");
  console.log("Admin username: ");
  const adminUsername = readLineSync();

  console.log("Admin email: ");
  const adminEmail = readLineSync();

  console.log("Admin password: ");
  const adminPassword = readLineSync();

  if (!adminUsername || !adminEmail || !adminPassword) {
    console.error("❌ Admin account creation failed: empty fields");
    return false;
  }

  // Create admin user
  const adminUser: User = {
    id: crypto.randomUUID(),
    username: adminUsername,
    email: adminEmail,
    passwordHash: await hashPassword(adminPassword),
    createdAt: Date.now(),
  };

  users.set(adminUser.id, adminUser);
  console.log(`✅ Admin user created: ${adminUsername}`);

  config.isInitialized = true;
  await saveConfig();

  console.log("\n✨ Initialization complete!\n");
  console.log(`📍 Server will start at: http://${config.host}:${config.port}`);
  console.log(
    `🔗 Admin login: Username="${adminUsername}" Email="${adminEmail}"\n`,
  );

  return true;
}

async function saveConfig(): Promise<void> {
  const configPath = `${config.databasePath}/config.json`;
  await Deno.writeTextFile(configPath, JSON.stringify(config, null, 2));
}

async function loadConfig(): Promise<void> {
  try {
    const configPath = `${config.databasePath}/config.json`;
    const content = await Deno.readTextFile(configPath);
    const loaded = JSON.parse(content);
    Object.assign(config, loaded);
  } catch {
    console.log("No existing config found.");
  }
}

// ==============================================================================
// AUTHENTICATION
// ==============================================================================

async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyPassword(
  password: string,
  hash: string,
): Promise<boolean> {
  const passwordHash = await hashPassword(password);
  return passwordHash === hash;
}

function generateToken(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function verifyToken(token: string): User | null {
  const session = sessions.get(token);
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    return null;
  }

  const user = users.get(session.userId);
  return user || null;
}

// ==============================================================================
// ROUTE HANDLERS
// ==============================================================================

async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const pathname = url.pathname;
  const method = req.method;

  // CORS headers
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };

  if (method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Health check
    if (pathname === "/" && method === "GET") {
      return new Response(
        JSON.stringify({ status: "healthy", timestamp: Date.now() }),
        {
          headers: { "Content-Type": "application/json", ...corsHeaders },
        },
      );
    }

    // Signup
    if (pathname === "/api/auth/signup" && method === "POST") {
      const body = await req.json() as {
        username: string;
        email: string;
        password: string;
      };

      if (!body.username || !body.email || !body.password) {
        return new Response(
          JSON.stringify({ error: "Missing required fields" }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        );
      }

      // Check if user exists
      const userExists = Array.from(users.values()).some(
        (u) => u.email === body.email || u.username === body.username,
      );

      if (userExists) {
        return new Response(
          JSON.stringify({ error: "User already exists" }),
          { status: 409, headers: { "Content-Type": "application/json" } },
        );
      }

      // Create user
      const newUser: User = {
        id: crypto.randomUUID(),
        username: body.username,
        email: body.email,
        passwordHash: await hashPassword(body.password),
        createdAt: Date.now(),
      };

      users.set(newUser.id, newUser);

      // Create session
      const token = generateToken();
      const session: Session = {
        token,
        userId: newUser.id,
        expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
      };
      sessions.set(token, session);

      return new Response(
        JSON.stringify({
          message: "User created",
          token,
          user: { id: newUser.id, username: newUser.username },
        }),
        {
          status: 201,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        },
      );
    }

    // Login
    if (pathname === "/api/auth/login" && method === "POST") {
      const body = await req.json() as {
        email: string;
        password: string;
      };

      if (!body.email || !body.password) {
        return new Response(
          JSON.stringify({ error: "Email and password required" }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        );
      }

      const user = Array.from(users.values()).find((u) => u.email === body.email);

      if (!user) {
        return new Response(
          JSON.stringify({ error: "Invalid credentials" }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        );
      }

      const passwordValid = await verifyPassword(
        body.password,
        user.passwordHash,
      );

      if (!passwordValid) {
        return new Response(
          JSON.stringify({ error: "Invalid credentials" }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        );
      }

      // Create session
      const token = generateToken();
      const session: Session = {
        token,
        userId: user.id,
        expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
      };
      sessions.set(token, session);

      return new Response(
        JSON.stringify({
          message: "Login successful",
          token,
          user: { id: user.id, username: user.username },
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        },
      );
    }

    // Get current user
    if (pathname === "/api/user/me" && method === "GET") {
      const authHeader = req.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return new Response(
          JSON.stringify({ error: "Unauthorized" }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        );
      }

      const token = authHeader.slice(7);
      const user = verifyToken(token);

      if (!user) {
        return new Response(
          JSON.stringify({ error: "Invalid or expired token" }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        );
      }

      return new Response(
        JSON.stringify({
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
          },
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        },
      );
    }

    // Logout
    if (pathname === "/api/auth/logout" && method === "POST") {
      const authHeader = req.headers.get("Authorization");
      if (authHeader?.startsWith("Bearer ")) {
        const token = authHeader.slice(7);
        sessions.delete(token);
      }

      return new Response(
        JSON.stringify({ message: "Logged out" }),
        {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        },
      );
    }

    // Not Found
    return new Response(
      JSON.stringify({ error: "Not Found" }),
      { status: 404, headers: { "Content-Type": "application/json" } },
    );
  } catch (error) {
    console.error("Error handling request:", error);
    return new Response(
      JSON.stringify({ error: "Internal Server Error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
}

// ==============================================================================
// SERVER START
// ==============================================================================

async function main() {
  console.log("🍃 Loading Sniffies App...\n");

  // Load existing config
  await loadConfig();

  // Check if initialized
  if (!config.isInitialized) {
    const initialized = await initializeApp();
    if (!initialized) {
      console.error("❌ Initialization failed. Exiting.");
      Deno.exit(1);
    }
  } else {
    console.log("✅ App already initialized. Starting server...\n");
  }

  // Start server
  const handler = (req: Request) => handleRequest(req);

  console.log(`🚀 Sniffies server starting...`);
  console.log(`📍 Listening on http://${config.host}:${config.port}\n`);
  console.log("Available endpoints:");
  console.log("  GET  /                          - Health check");
  console.log("  POST /api/auth/signup            - Register new user");
  console.log("  POST /api/auth/login             - Login user");
  console.log("  GET  /api/user/me                - Get current user");
  console.log("  POST /api/auth/logout            - Logout user\n");

  await serve(handler, { port: config.port, hostname: config.host });
}

main().catch(console.error);
