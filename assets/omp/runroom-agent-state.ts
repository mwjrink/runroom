import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { readFileSync } from "node:fs";
import { Socket } from "node:net";

const messageLimit = 4096;
const socketTimeoutMs = 1000;
type State = "working" | "blocked" | "idle";

function activitySocket(): string | undefined {
  try {
    const descriptor = JSON.parse(readFileSync("/runtime/launch.json", "utf8"));
    const socket = descriptor.activity_socket;
    if (descriptor.version === 1 && typeof socket === "string" && socket.startsWith("/") && !socket.includes("\0")) {
      return socket;
    }
  } catch {
    // Outside an identity-enabled Runroom sandbox there is nothing to report.
  }
  return undefined;
}

function stateFrame(state: State, message: string | undefined): Buffer {
  const text = Buffer.from(message ?? "", "utf8");
  let length = Math.min(text.length, messageLimit);
  if (text.length > length) {
    // A continuation byte at the first excluded position means its entire
    // code point must be excluded, not sent as malformed UTF-8.
    while ((text[length] & 0xc0) === 0x80) length -= 1;
  }
  const frame = Buffer.alloc(8 + length);
  frame.write("RRA\0", 0, "ascii");
  frame[4] = 1;
  frame[5] = state === "working" ? 0 : state === "blocked" ? 1 : 2;
  frame.writeUInt16BE(length, 6);
  text.copy(frame, 8, 0, length);
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
  const socketPath = activitySocket();
  if (!socketPath) return;

  let queue: Promise<void> = Promise.resolve();
  let rootSession = false;
  let agentActive = false;
  let failureMessage: string | undefined;
  const blockers = new Map<string, { count: number; message: string }>();
  let lastState: State | undefined;
  let lastMessage: string | undefined;

  function publish(force = false): Promise<void> {
    let state: State = agentActive ? "working" : "idle";
    let message = failureMessage;
    if (failureMessage !== undefined) state = "blocked";
    for (const blocker of blockers.values()) {
      state = "blocked";
      message = blocker.message;
    }
    if (!force && state === lastState && message === lastMessage) return queue;
    lastState = state;
    lastMessage = message;
    const frame = stateFrame(state, message);
    // Do not coalesce transitions: even a fast start/end must reach the daemon
    // in order. Failed or invalid ACKs settle the queue without retries.
    queue = queue.then(() => sendFrame(socketPath, frame)).then(() => undefined, () => undefined);
    return queue;
  }

  function reset(): void {
    agentActive = false;
    failureMessage = undefined;
    blockers.clear();
  }

  function block(key: string, message: string): Promise<void> {
    const count = (blockers.get(key)?.count ?? 0) + 1;
    blockers.delete(key);
    blockers.set(key, { count, message });
    return publish();
  }

  function unblock(key: string): Promise<void> {
    const blocker = blockers.get(key);
    if (!blocker) return queue;
    blocker.count -= 1;
    if (blocker.count === 0) blockers.delete(key);
    return publish();
  }

  const unsubscribeBlocked = pi.events.on("herdr:blocked", (data) => {
    // The shared UI bus has no ExtensionContext. As in the managed reporter,
    // only accept it after an actual UI session has claimed this extension.
    if (!rootSession || !data || typeof data !== "object") return;
    const event = data as { active?: boolean; label?: unknown };
    if (event.active) {
      void block("ui", typeof event.label === "string" ? event.label : "waiting for user input");
    } else {
      void unblock("ui");
    }
  });

  pi.on("session_start", (_event, ctx) => {
    if (ctx.hasUI !== true) return;
    rootSession = true;
    reset();
    // Reloading extensions during a live run does not emit another agent_start.
    agentActive = ctx.isIdle() === false;
    return publish(true);
  });
  pi.on("session_switch", (_event, ctx) => {
    if (ctx.hasUI !== true) return;
    rootSession = true;
    reset();
    agentActive = ctx.isIdle() === false;
    return publish(true);
  });
  pi.on("agent_start", (_event, ctx) => {
    // Always inspect this event's context, even after root session activation:
    // a nested/non-UI context must never inherit the root pane's authority.
    if (ctx.hasUI !== true) return;
    agentActive = true;
    failureMessage = undefined;
    return publish();
  });
  pi.on("tool_approval_requested", (event, ctx) => {
    if (ctx.hasUI !== true) return;
    return block(`approval:${event.sessionId}:${event.toolCallId}`, event.reason || `${event.toolName} approval`);
  });
  pi.on("tool_approval_resolved", (event, ctx) => {
    if (ctx.hasUI !== true) return;
    return unblock(`approval:${event.sessionId}:${event.toolCallId}`);
  });
  pi.on("tool_execution_start", (event, ctx) => {
    if (ctx.hasUI !== true || event.toolName !== "ask") return;
    const args = event.args as { questions?: unknown } | undefined;
    const questions = Array.isArray(args?.questions) ? args.questions : [];
    const first = questions.find((question) => typeof question?.question === "string" && question.question.length > 0);
    return block(`ask:${event.toolCallId}`, first?.question || "waiting for user input");
  });
  pi.on("tool_execution_end", (event, ctx) => {
    if (ctx.hasUI !== true || event.toolName !== "ask") return;
    return unblock(`ask:${event.toolCallId}`);
  });
  pi.on("agent_end", (event, ctx) => {
    if (ctx.hasUI !== true) return;
    // OMP exposes its actual retry/continuation decision. An intermediate
    // failure is still working, not a user-visible terminal failure or idle.
    if (event.willContinue === true) {
      agentActive = true;
      return publish();
    }
    reset();
    for (let index = event.messages.length - 1; index >= 0; index -= 1) {
      const message = event.messages[index];
      if (message.role !== "assistant") continue;
      if (message.stopReason === "error") failureMessage = message.errorMessage || "agent failed";
      break;
    }
    return publish();
  });
  pi.on("session_shutdown", (_event, ctx) => {
    if (ctx.hasUI !== true) return;
    rootSession = false;
    unsubscribeBlocked();
    return queue;
  });
}
