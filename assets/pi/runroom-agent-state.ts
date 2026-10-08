import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { readFileSync } from "node:fs";
import { Socket } from "node:net";
import { isAbsolute } from "node:path";

type State = "working" | "blocked" | "idle";
type Session = { agent: "pi"; reference: string };
const messageLimit = 4096;
const bodyLimit = 16 * 1024;
const socketTimeoutMs = 1000;

function launchReporting(): { socketPath: string; sessions: boolean } | undefined {
  try {
    const descriptor = JSON.parse(readFileSync("/runtime/launch.json", "utf8"));
    const socketPath = descriptor.activity_socket;
    if (descriptor.version === 1 && typeof socketPath === "string" && socketPath.startsWith("/") && !socketPath.includes("\0")) {
      return { socketPath, sessions: descriptor.session_agent === "pi" };
    }
  } catch {
    // Outside an identity-enabled Runroom sandbox there is nothing to report.
  }
  return undefined;
}

function sessionReference(ctx: ExtensionContext): Session | undefined {
  const file = ctx.sessionManager.getSessionFile();
  const reference = file && isAbsolute(file) ? file : ctx.sessionManager.getSessionId();
  if (!reference || Buffer.byteLength(reference, "utf8") > 4096 || /\p{Cc}/u.test(reference)) return undefined;
  return { agent: "pi", reference };
}

function stateFrame(state: State, message: string | undefined, session: Session | undefined): Buffer {
  const text = Buffer.from(message ?? "", "utf8");
  let length = Math.min(text.length, messageLimit);
  let body: Buffer;
  do {
    while (length < text.length && (text[length] & 0xc0) === 0x80) length -= 1;
    body = Buffer.from(JSON.stringify({
      ...(message === undefined ? {} : { message: text.subarray(0, length).toString("utf8") }),
      ...(session === undefined ? {} : { session }),
    }), "utf8");
    if (body.length <= bodyLimit) break;
    // JSON escaping can expand the message. Never truncate the session reference.
    length = Math.floor(length * 0.75);
  } while (true);
  const frame = Buffer.alloc(8 + body.length);
  frame.write("RRA\0", 0, "ascii");
  frame[4] = 2;
  frame[5] = state === "working" ? 0 : state === "blocked" ? 1 : 2;
  frame.writeUInt16BE(body.length, 6);
  body.copy(frame, 8);
  return frame;
}

function sendFrame(socketPath: string, frame: Buffer): Promise<boolean> {
  const { promise, resolve } = Promise.withResolvers<boolean>();
  const socket = new Socket();
  let done = false;
  const timer = setTimeout(() => finish(false), socketTimeoutMs);
  function finish(acknowledged: boolean): void {
    if (done) return;
    done = true;
    clearTimeout(timer);
    socket.destroy();
    resolve(acknowledged);
  }
  socket.on("connect", () => socket.write(frame));
  socket.on("data", (ack: Buffer) => finish(ack.length === 1 && ack[0] === 0));
  socket.on("error", () => finish(false));
  socket.on("end", () => finish(false));
  socket.on("close", () => finish(false));
  try {
    socket.connect({ path: socketPath });
  } catch {
    finish(false);
  }
  return promise;
}

export default function (pi: ExtensionAPI): void {
  const reporting = launchReporting();
  if (!reporting) return;
  let queue: Promise<void> = Promise.resolve();
  let rootSession = false;
  let agentActive = false;
  let failureMessage: string | undefined;
  let session: Session | undefined;
  const blockers = new Map<string, { count: number; message: string }>();
  let lastState: State | undefined;
  let lastMessage: string | undefined;
  let lastReference: string | undefined;

  function publish(force = false): Promise<void> {
    let state: State = agentActive ? "working" : "idle";
    let message = failureMessage;
    if (!agentActive && failureMessage !== undefined) state = "blocked";
    for (const blocker of blockers.values()) {
      state = "blocked";
      message = blocker.message;
    }
    if (!force && state === lastState && message === lastMessage && session?.reference === lastReference) return queue;
    lastState = state;
    lastMessage = message;
    lastReference = session?.reference;
    const frame = stateFrame(state, message, session);
    // Preserve session replacements and activity transitions in one ordered stream.
    queue = queue.then(() => sendFrame(reporting.socketPath, frame)).then(() => undefined, () => undefined);
    return queue;
  }

  const unsubscribeBlocked = pi.events.on("herdr:blocked", (data) => {
    if (!rootSession || !data || typeof data !== "object") return;
    const event = data as { active?: boolean; label?: unknown };
    if (event.active) {
      blockers.set("ui", { count: 1, message: typeof event.label === "string" ? event.label : "waiting for user input" });
    } else {
      blockers.delete("ui");
    }
    void publish();
  });
  pi.on("session_start", (event, ctx) => {
    // hasUI also admits RPC. Only the actual terminal root owns pane reporting.
    if (ctx.mode !== "tui") return;
    rootSession = true;
    session = reporting.sessions ? sessionReference(ctx) : undefined;
    if (event.reason !== "reload") {
      failureMessage = undefined;
      blockers.clear();
    }
    agentActive = ctx.isIdle() === false;
    return publish(true);
  });
  pi.on("agent_start", (_event, ctx) => {
    if (ctx.mode !== "tui") return;
    session = reporting.sessions ? sessionReference(ctx) : undefined;
    agentActive = true;
    failureMessage = undefined;
    return publish();
  });
  pi.on("ui_prompt_start", (event, ctx) => {
    if (ctx.mode !== "tui") return;
    const key = `prompt:${event.kind}`;
    blockers.set(key, { count: (blockers.get(key)?.count ?? 0) + 1, message: event.title || "waiting for user input" });
    return publish();
  });
  pi.on("ui_prompt_end", (event, ctx) => {
    if (ctx.mode !== "tui") return;
    const key = `prompt:${event.kind}`;
    const blocker = blockers.get(key);
    if (blocker && --blocker.count <= 0) blockers.delete(key);
    return publish();
  });
  pi.on("agent_end", (event, ctx) => {
    if (ctx.mode !== "tui") return;
    failureMessage = undefined;
    for (let index = event.messages.length - 1; index >= 0; index -= 1) {
      const message = event.messages[index];
      if (message.role !== "assistant") continue;
      if (message.stopReason === "error") failureMessage = message.errorMessage || "agent failed";
      break;
    }
    // agent_end may precede automatic retries; settlement owns the terminal state.
  });
  pi.on("agent_settled", (event, ctx) => {
    if (ctx.mode !== "tui") return;
    session = reporting.sessions ? sessionReference(ctx) : undefined;
    agentActive = false;
    blockers.clear();
    if (event.aborted) failureMessage = undefined;
    return publish();
  });
  pi.on("session_shutdown", (_event, ctx) => {
    if (ctx.mode !== "tui") return;
    rootSession = false;
    unsubscribeBlocked();
    return queue;
  });
}
