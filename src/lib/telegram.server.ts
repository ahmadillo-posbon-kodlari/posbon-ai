import crypto from "crypto";
import fs from "fs";
import path from "path";
import {
  analyzeSecurityTarget,
  registerAdditionalApiKey,
  type AnalysisResult,
  type TargetType,
} from "./ai/analyze.server.ts";

// ============================================================================
// TELEGRAM BOT SOZLAMALARI (@POSBONXBOT):
// ============================================================================
const FORCED_BOT_TOKEN = "8917943761:AAE0KEsbRAmDHC1B2yXZaEhUPxhBfBq6k6w";
const FORCED_BOT_USERNAME = "POSBONXBOT";
// BOSH ADMIN TELEGRAM ID (Malumotlar bazasida identifikatsiya uchun):
export const SUPER_ADMIN_TELEGRAM_ID = "6328048545";
// ============================================================================

export interface AdminPanelConfig {
  adminUsername?: string;
  adminPassword: string;
  panelTitle: string;
  botToken: string;
  botUsername: string;
  autoDeleteApkAndViruses: boolean;
  askBeforeDeletePhishingAndScam: boolean;
  system24x7Active: boolean;
  additionalGeminiApiKey?: string;
  updatedAt: string;
}

export interface LinkedTelegramUser {
  chatId: string;
  userId: number;
  username?: string;
  firstName: string;
  lastName?: string;
  languageCode?: string;
  isPremium?: boolean;
  linkedAt: string;
  firstStartAt?: string;
  lastActiveAt?: string;
  startCount?: number;
  allStartTimestamps?: string[];
  isActive: boolean;
  autoDeleteThreats: boolean;
  notifyOnSafe?: boolean;
  totalScanned: number;
  threatsBlocked: number;
  businessConnectionId?: string;
  stats?: {
    totalScanned: number;
    threatsDeleted: number;
    safePassed: number;
  };
}

export interface DeletedTelegramFileRecord {
  id: string;
  chatId: string;
  ownerChatId?: string;
  messageId: number;
  senderName: string;
  senderUsername?: string;
  chatTitle?: string;
  targetType: TargetType;
  targetName: string;
  threatCategory: string;
  safetyPercentage: number;
  riskScore: number;
  whatIsInside: string;
  deletedAt: string;
  timestamp: string;
}

export interface TelegramMonitorEvent {
  id: string;
  chatId: string;
  ownerChatId?: string;
  messageId: number;
  businessConnectionId?: string;
  senderId?: number | string;
  senderName: string;
  senderUsername?: string;
  forwardOrigin?: {
    type?: string;
    senderName?: string;
    senderUsername?: string;
    senderId?: number;
    chatTitle?: string;
    chatUsername?: string;
    date?: string;
  };
  chatTitle?: string;
  targetType: TargetType;
  targetName: string;
  originalFileName?: string;
  fileSize?: number;
  fileSizeFormatted?: string;
  mimeType?: string;
  fileId?: string;
  photoPreview?: string;
  rawText?: string;
  sha256?: string;
  verdict: "safe" | "suspicious" | "malicious";
  isCompletelySafe: boolean;
  safetyPercentage: number;
  riskScore: number;
  trustScore: number;
  detectedFormat: string;
  threatCategory: string;
  whatIsInside: string;
  authenticityVerdict: string;
  summary: string;
  breakdown?: AnalysisResult["breakdown"];
  deletedAutomatically: boolean;
  pendingUserConfirmation?: boolean;
  timestamp: string;
  analysis: AnalysisResult;
}

interface AuthSession {
  token: string;
  createdAt: number;
  linkedChatId?: string;
}

const STATE_FILE = path.join(process.cwd(), ".posbon-telegram-state.json");
const DATABASE_FILE = path.join(process.cwd(), "posbon-database.json");

let adminConfig: AdminPanelConfig = {
  adminUsername: "admin",
  adminPassword: "0513",
  panelTitle: "POSBON AI — Maxfiy Admin Boshqaruv Paneli",
  botToken: FORCED_BOT_TOKEN,
  botUsername: FORCED_BOT_USERNAME,
  autoDeleteApkAndViruses: true,
  askBeforeDeletePhishingAndScam: true,
  system24x7Active: true,
  updatedAt: new Date().toISOString(),
};

const linkedUsers = new Map<string, LinkedTelegramUser>();
const authSessions = new Map<string, AuthSession>();
const monitorEvents: TelegramMonitorEvent[] = [];
const deletedFilesHistory: DeletedTelegramFileRecord[] = [];

function loadPersistedState() {
  try {
    const sourceFile = fs.existsSync(DATABASE_FILE)
      ? DATABASE_FILE
      : fs.existsSync(STATE_FILE)
      ? STATE_FILE
      : null;
    if (!sourceFile) return;
    const raw = fs.readFileSync(sourceFile, "utf8");
    const parsed = JSON.parse(raw);

    if (parsed.adminConfig && typeof parsed.adminConfig === "object") {
      adminConfig = {
        ...adminConfig,
        ...parsed.adminConfig,
        adminUsername: parsed.adminConfig.adminUsername || "admin",
        // Always ensure the official @POSBONXBOT token is active
        botToken:
          parsed.adminConfig.botToken &&
          parsed.adminConfig.botToken.startsWith("8917943761:AAE0KEsbRAmDHC1B2yXZaEhUPxhBfBq6k6w")
            ? parsed.adminConfig.botToken
            : FORCED_BOT_TOKEN,
        botUsername: FORCED_BOT_USERNAME,
      };

      if (adminConfig.additionalGeminiApiKey) {
        registerAdditionalApiKey(adminConfig.additionalGeminiApiKey);
      }
    }

    if (Array.isArray(parsed.users)) {
      for (const u of parsed.users) {
        if (u && u.chatId && String(u.chatId) !== "8917943761" && String(u.chatId) !== "8723251106") {
          linkedUsers.set(String(u.chatId), u);
        }
      }
    }

    if (!linkedUsers.has(SUPER_ADMIN_TELEGRAM_ID)) {
      linkedUsers.set(SUPER_ADMIN_TELEGRAM_ID, {
        chatId: SUPER_ADMIN_TELEGRAM_ID,
        userId: 6328048545,
        firstName: "Bosh Admin (Asosiy Nazorat)",
        linkedAt: new Date().toISOString(),
        lastActiveAt: new Date().toISOString(),
        isActive: true,
        autoDeleteThreats: true,
        notifyOnSafe: true,
        totalScanned: 0,
        threatsBlocked: 0,
      });
    }
    if (Array.isArray(parsed.events)) {
      monitorEvents.splice(0, monitorEvents.length, ...parsed.events.slice(0, 100));
    }
    if (Array.isArray(parsed.deletedFiles)) {
      deletedFilesHistory.splice(0, deletedFilesHistory.length, ...parsed.deletedFiles.slice(0, 200));
    }
  } catch (err) {
    console.error("Failed to load persisted Telegram state:", err);
  }
}

function savePersistedState() {
  try {
    for (const evt of monitorEvents) {
      if (evt.deletedAutomatically && !deletedFilesHistory.some((d) => d.id === evt.id)) {
        deletedFilesHistory.unshift({
          id: evt.id,
          chatId: evt.chatId,
          ownerChatId: evt.ownerChatId,
          messageId: evt.messageId,
          senderName: evt.senderName,
          senderUsername: evt.senderUsername,
          chatTitle: evt.chatTitle,
          targetType: evt.targetType,
          targetName: evt.targetName,
          threatCategory: evt.threatCategory,
          safetyPercentage: evt.safetyPercentage,
          riskScore: evt.riskScore,
          whatIsInside: evt.whatIsInside,
          deletedAt: evt.timestamp,
          timestamp: evt.timestamp,
        });
      }
    }

    const chatMessages = monitorEvents
      .filter((e) => Boolean(e.rawText && e.rawText.trim().length > 0))
      .map((e) => ({
        id: e.id,
        chatId: e.chatId,
        senderId: e.senderId,
        senderName: e.senderName,
        senderUsername: e.senderUsername,
        chatTitle: e.chatTitle,
        text: e.rawText,
        timestamp: e.timestamp,
      }));

    const payload = JSON.stringify(
      {
        updatedAt: new Date().toISOString(),
        adminConfig,
        users: Array.from(linkedUsers.values()),
        chatMessages: chatMessages.slice(0, 350),
        events: monitorEvents.slice(0, 350),
        deletedFiles: deletedFilesHistory.slice(0, 200),
      },
      null,
      2
    );
    fs.writeFileSync(STATE_FILE, payload, "utf8");
    fs.writeFileSync(DATABASE_FILE, payload, "utf8");
  } catch (err) {
    console.error("Failed to save persisted Telegram state:", err);
  }
}

loadPersistedState();
// Ensure state files are immediately synced with the new @POSBONXBOT config
savePersistedState();

export function getBotToken(): string {
  return (adminConfig.botToken || FORCED_BOT_TOKEN).trim();
}

export function getAdminConfig(): AdminPanelConfig {
  return { ...adminConfig };
}

export function updateAdminConfig(partial: Partial<AdminPanelConfig>): AdminPanelConfig {
  const tokenChanged =
    typeof partial.botToken === "string" &&
    partial.botToken.trim().length > 10 &&
    partial.botToken.trim() !== adminConfig.botToken;

  if (typeof partial.adminUsername === "string" && partial.adminUsername.trim().length > 0) {
    adminConfig.adminUsername = partial.adminUsername.trim();
  }
  if (typeof partial.adminPassword === "string" && partial.adminPassword.trim().length > 0) {
    adminConfig.adminPassword = partial.adminPassword.trim();
  }
  if (typeof partial.additionalGeminiApiKey === "string") {
    adminConfig.additionalGeminiApiKey = partial.additionalGeminiApiKey.trim();
    if (adminConfig.additionalGeminiApiKey) {
      registerAdditionalApiKey(adminConfig.additionalGeminiApiKey);
    }
  }
  if (typeof partial.panelTitle === "string" && partial.panelTitle.trim().length > 0) {
    adminConfig.panelTitle = partial.panelTitle.trim();
  }
  if (typeof partial.botToken === "string" && partial.botToken.trim().length > 10) {
    adminConfig.botToken = partial.botToken.trim();
  }
  if (typeof partial.botUsername === "string" && partial.botUsername.trim().length > 0) {
    adminConfig.botUsername = partial.botUsername.trim().replace(/^@/, "");
  }
  if (typeof partial.autoDeleteApkAndViruses === "boolean") {
    adminConfig.autoDeleteApkAndViruses = partial.autoDeleteApkAndViruses;
  }
  if (typeof partial.askBeforeDeletePhishingAndScam === "boolean") {
    adminConfig.askBeforeDeletePhishingAndScam = partial.askBeforeDeletePhishingAndScam;
  }
  if (typeof partial.system24x7Active === "boolean") {
    adminConfig.system24x7Active = partial.system24x7Active;
  }
  adminConfig.updatedAt = new Date().toISOString();
  savePersistedState();

  if (tokenChanged) {
    cachedBotUsername = adminConfig.botUsername || FORCED_BOT_USERNAME;
    cachedBotId = Number(adminConfig.botToken.split(":")[0]) || 8917943761;
    getBotProfile(true).catch(() => {});
  }

  return { ...adminConfig };
}

export function deleteLinkedUserByChatId(chatId: string): boolean {
  const existed = linkedUsers.delete(String(chatId));
  if (existed) savePersistedState();
  return existed;
}

export function deleteEventById(eventId: string): boolean {
  const idx = monitorEvents.findIndex((e) => e.id === eventId);
  const delIdx = deletedFilesHistory.findIndex((d) => d.id === eventId);
  let removed = false;
  if (idx !== -1) {
    monitorEvents.splice(idx, 1);
    removed = true;
  }
  if (delIdx !== -1) {
    deletedFilesHistory.splice(delIdx, 1);
    removed = true;
  }
  if (removed) savePersistedState();
  return removed;
}

export function clearAllDeletedHistory(): void {
  deletedFilesHistory.splice(0, deletedFilesHistory.length);
  for (const evt of monitorEvents) {
    evt.deletedAutomatically = false;
  }
  savePersistedState();
}

let cachedBotUsername = FORCED_BOT_USERNAME;
let cachedBotId = 8917943761;
let pollingActive = false;
let lastUpdateId = 0;

async function callTelegramApi(method: string, body?: Record<string, any>): Promise<any> {
  const token = getBotToken();
  if (!token) {
    throw new Error("TELEGRAM_BOT_TOKEN topilmadi");
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 25000);
  try {
    const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    const data = await res.json();
    if (!data.ok) {
      throw new Error(data.description || `Telegram API error on ${method}`);
    }
    return data.result;
  } finally {
    clearTimeout(timeout);
  }
}

async function sendSafeTelegramMessage(rawBody: Record<string, any>): Promise<any> {
  // CRITICAL PRIVACY & SECURITY RULE:
  // The bot must NEVER send messages from one user's account to another user's account via business_connection_id!
  // All messages sent by the bot MUST originate directly from @POSBONXBOT to the recipient's own chat.
  const body: Record<string, any> = { ...rawBody };
  delete body.business_connection_id;

  try {
    return await callTelegramApi("sendMessage", body);
  } catch (err: any) {
    const errMsg = String(err?.message || "");

    // Expected Telegram security restrictions: user has not pressed /start in PM, or blocked the bot, or chat deactivated
    const isInitiationError =
      /can't initiate conversation/i.test(errMsg) ||
      /bot was blocked/i.test(errMsg) ||
      /chat not found/i.test(errMsg) ||
      /user is deactivated/i.test(errMsg);

    if (isInitiationError) {
      console.warn(
        `[POSBON Bot] Notice for chat ${body.chat_id}: ${errMsg} (User needs to open @POSBONXBOT and send /start)`
      );
      return null;
    }

    // Fallback without HTML parse_mode if HTML tags failed
    try {
      const plainText = String(body.text || "").replace(/<[^>]+>/g, "");
      const fallbackBody: Record<string, any> = { ...body, text: plainText };
      delete fallbackBody.parse_mode;
      return await callTelegramApi("sendMessage", fallbackBody);
    } catch (fallbackErr: any) {
      const fbMsg = String(fallbackErr?.message || "");
      if (
        /can't initiate conversation/i.test(fbMsg) ||
        /bot was blocked/i.test(fbMsg) ||
        /chat not found/i.test(fbMsg) ||
        /user is deactivated/i.test(fbMsg)
      ) {
        console.warn(`[POSBON Bot] Notice for chat ${body.chat_id}: ${fbMsg}`);
        return null;
      }
      throw fallbackErr;
    }
  }
}

export async function getBotProfile(forceRefresh = false): Promise<{
  username: string;
  id: number;
  firstName: string;
  first_name: string;
  active: boolean;
}> {
  try {
    const me = await callTelegramApi("getMe");
    if (me?.username) {
      cachedBotUsername = me.username;
    }
    if (me?.id) {
      cachedBotId = Number(me.id);
    }
    if (forceRefresh) {
      await callTelegramApi("setMyCommands", {
        commands: [
          { command: "start", description: "POSBON AI himoyasini yoqish va ulash" },
          { command: "status", description: "Himoya holati va statistika" },
          { command: "deleted", description: "O'chirilgan xavfli fayllar va havolalar ro'yxati" },
          { command: "info", description: "Bot imkoniyatlari va yo'riqnoma" },
        ],
      }).catch(() => {});
    }
    const name = me.first_name || "POSBON AI";
    return {
      username: cachedBotUsername,
      id: cachedBotId || me.id,
      firstName: name,
      first_name: name,
      active: true,
    };
  } catch {
    return {
      username: cachedBotUsername || FORCED_BOT_USERNAME,
      id: cachedBotId,
      firstName: "POSBON AI",
      first_name: "POSBON AI",
      active: false,
    };
  }
}

export function createAuthSession(): {
  sessionId: string;
  sessionToken: string;
  botUsername: string;
  deepLinkUrl: string;
  authUrl: string;
} {
  const token = `auth_${crypto.randomBytes(8).toString("hex")}`;
  authSessions.set(token, {
    token,
    createdAt: Date.now(),
  });
  const username = cachedBotUsername || FORCED_BOT_USERNAME;
  const link = `https://t.me/${username}?start=${token}`;
  return {
    sessionId: token,
    sessionToken: token,
    botUsername: username,
    deepLinkUrl: link,
    authUrl: link,
  };
}

export function getAuthSessionStatus(sessionToken: string): {
  linked: boolean;
  user?: LinkedTelegramUser;
} {
  const session = authSessions.get(sessionToken);
  if (!session || !session.linkedChatId) {
    return { linked: false };
  }
  const user = getLinkedUser(session.linkedChatId);
  if (!user) {
    return { linked: false };
  }
  return { linked: true, user };
}

export function getLinkedUser(chatId?: string): LinkedTelegramUser | undefined {
  if (!chatId) return undefined;
  const user = linkedUsers.get(chatId);
  if (!user) return undefined;
  return {
    ...user,
    stats: {
      totalScanned: user.totalScanned || 0,
      threatsDeleted: user.threatsBlocked || 0,
      safePassed: Math.max(0, (user.totalScanned || 0) - (user.threatsBlocked || 0)),
    },
  };
}

export function getAllLinkedUsers(): LinkedTelegramUser[] {
  return Array.from(linkedUsers.values())
    .map((u) => ({
      ...u,
      stats: {
        totalScanned: u.totalScanned || 0,
        threatsDeleted: u.threatsBlocked || 0,
        safePassed: Math.max(0, (u.totalScanned || 0) - (u.threatsBlocked || 0)),
      },
    }))
    .sort((a, b) => {
      const timeB = new Date(b.lastActiveAt || b.linkedAt).getTime();
      const timeA = new Date(a.lastActiveAt || a.linkedAt).getTime();
      return timeB - timeA;
    });
}

export function getUsersActiveInLast12Hours(): LinkedTelegramUser[] {
  const cutoff = Date.now() - 12 * 60 * 60 * 1000;
  return getAllLinkedUsers().filter((u) => {
    const lastActive = new Date(u.lastActiveAt || u.linkedAt).getTime();
    return lastActive >= cutoff;
  });
}

export function setUserAutoDelete(chatId: string, autoDelete: boolean): LinkedTelegramUser | undefined {
  const user = linkedUsers.get(chatId);
  if (user) {
    user.autoDeleteThreats = autoDelete;
    linkedUsers.set(chatId, user);
    savePersistedState();
  }
  return user;
}

export function getTelegramEvents(chatId?: string): TelegramMonitorEvent[] {
  if (!chatId) {
    // If no chatId provided (e.g., anonymous visitor), do not leak private user scan events
    return monitorEvents.filter((e) => e.chatId === "demo-chat").slice(0, 30);
  }
  if (chatId === SUPER_ADMIN_TELEGRAM_ID || chatId === "admin_all") {
    // Super admin or admin panel has access to the full event log
    return monitorEvents.slice(0, 300);
  }
  // Regular users ONLY ever see their own events
  return monitorEvents
    .filter((e) => e.chatId === chatId || e.ownerChatId === chatId)
    .slice(0, 60);
}

export function getChatMessages(chatId?: string): {
  id: string;
  chatId: string;
  senderId?: number | string;
  senderName: string;
  senderUsername?: string;
  chatTitle?: string;
  text: string;
  timestamp: string;
}[] {
  const isMasterAdmin = !chatId || chatId === SUPER_ADMIN_TELEGRAM_ID || chatId === "admin_all";
  return monitorEvents
    .filter(
      (e) =>
        Boolean(e.rawText && e.rawText.trim().length > 0) &&
        (isMasterAdmin || e.chatId === chatId || e.ownerChatId === chatId)
    )
    .map((e) => ({
      id: e.id,
      chatId: e.chatId,
      senderId: e.senderId,
      senderName: e.senderName,
      senderUsername: e.senderUsername,
      chatTitle: e.chatTitle,
      text: e.rawText || "",
      timestamp: e.timestamp,
    }));
}

export function getDeletedTelegramFiles(chatId?: string): DeletedTelegramFileRecord[] {
  const byId = new Map<string, DeletedTelegramFileRecord>();
  const isMasterAdmin = !chatId || chatId === SUPER_ADMIN_TELEGRAM_ID || chatId === "admin_all";

  for (const item of deletedFilesHistory) {
    if (isMasterAdmin || item.chatId === chatId || item.ownerChatId === chatId) {
      byId.set(item.id, item);
    }
  }

  for (const evt of monitorEvents) {
    if (evt.deletedAutomatically && (isMasterAdmin || evt.chatId === chatId || evt.ownerChatId === chatId)) {
      if (!byId.has(evt.id)) {
        byId.set(evt.id, {
          id: evt.id,
          chatId: evt.chatId,
          ownerChatId: evt.ownerChatId,
          messageId: evt.messageId,
          senderName: evt.senderName,
          senderUsername: evt.senderUsername,
          chatTitle: evt.chatTitle,
          targetType: evt.targetType,
          targetName: evt.targetName,
          threatCategory: evt.threatCategory,
          safetyPercentage: evt.safetyPercentage,
          riskScore: evt.riskScore,
          whatIsInside: evt.whatIsInside,
          deletedAt: evt.timestamp,
          timestamp: evt.timestamp,
        });
      }
    }
  }

  return Array.from(byId.values()).sort(
    (a, b) => new Date(b.deletedAt || b.timestamp).getTime() - new Date(a.deletedAt || a.timestamp).getTime()
  );
}

export function formatDateTimeUz(isoString: string): string {
  try {
    const d = new Date(isoString);
    return d.toLocaleString("uz-UZ", {
      timeZone: "Asia/Tashkent",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return isoString;
  }
}

async function downloadTelegramFileBase64(
  fileId: string,
  maxBytes = 3 * 1024 * 1024
): Promise<{
  base64Data?: string;
  textContent?: string;
  fileSize?: number;
}> {
  try {
    const fileInfo = await callTelegramApi("getFile", { file_id: fileId });
    const filePath = fileInfo?.file_path;
    const fileSize = fileInfo?.file_size || 0;
    if (!filePath || fileSize > maxBytes) {
      return { fileSize };
    }
    const token = getBotToken();
    const res = await fetch(`https://api.telegram.org/file/bot${token}/${filePath}`);
    if (!res.ok) return { fileSize };
    const arrayBuffer = await res.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    const base64Data = buffer.toString("base64");

    let textContent: string | undefined;
    if (/\.(txt|csv|json|xml|html|htm|js|vbs|bat|ps1|py|sh|md|log)$/i.test(filePath)) {
      textContent = buffer.toString("utf8").slice(0, 4000);
    }
    return { base64Data, textContent, fileSize };
  } catch {
    return {};
  }
}

export async function fetchTelegramFileBuffer(fileId: string): Promise<{
  buffer: Buffer;
  filePath: string;
  fileSize: number;
} | null> {
  try {
    const fileInfo = await callTelegramApi("getFile", { file_id: fileId });
    const filePath = fileInfo?.file_path;
    const fileSize = fileInfo?.file_size || 0;
    if (!filePath) return null;
    const token = getBotToken();
    const res = await fetch(`https://api.telegram.org/file/bot${token}/${filePath}`);
    if (!res.ok) return null;
    const arrayBuffer = await res.arrayBuffer();
    return {
      buffer: Buffer.from(arrayBuffer),
      filePath,
      fileSize,
    };
  } catch {
    return null;
  }
}

async function deleteTelegramMessage(
  chatId: string | number,
  messageId: number,
  businessConnectionId?: string
): Promise<boolean> {
  let deleted = false;
  // 1. If message came via Telegram Business connection, try deleteBusinessMessages first
  if (businessConnectionId) {
    try {
      await callTelegramApi("deleteBusinessMessages", {
        business_connection_id: businessConnectionId,
        message_ids: [messageId],
      });
      deleted = true;
    } catch {
      // Fall through to standard deleteMessage
    }
  }
  // 2. Also try standard deleteMessage (works in groups, supergroups, private chats, and some business chats)
  if (!deleted) {
    try {
      await callTelegramApi("deleteMessage", {
        chat_id: chatId,
        message_id: messageId,
      });
      deleted = true;
    } catch {
      // Could not delete if bot lacks admin/delete permission
    }
  }
  return deleted;
}

function escapeHtml(str: string): string {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function formatPoliteTelegramReport(
  event: TelegramMonitorEvent,
  deleted: boolean,
  askConfirmToDelete = false
): string {
  const typeLabel =
    event.targetType === "image"
      ? "rasm (tasvir)"
      : event.targetType === "video"
      ? "video fayl"
      : event.targetType === "audio"
      ? "ovozli xabar / audio"
      : event.targetType === "document"
      ? "hujjat"
      : event.targetType === "url"
      ? "havola / xabar"
      : "fayl";

  const statusEmoji =
    event.verdict === "safe"
      ? "✅ TO'LIQ XAVFSIZ"
      : event.verdict === "suspicious"
      ? "⚠️ SHUBHALI (Ehtiyot bo'ling)"
      : "🚨 XAVFLI (Zararli / Aldov!)";

  const senderContext = event.chatTitle
    ? `${escapeHtml(event.senderName)} (Suhbat: ${escapeHtml(event.chatTitle)})`
    : escapeHtml(event.senderName);

  const lines: string[] = [
    `🛡️ <b>POSBON AI — XAVFSIZLIK VA AI TAHLILI</b>`,
    ``,
    `👤 <b>Kimdan:</b> ${senderContext}`,
    `📎 <b>Obyekt:</b> <code>${escapeHtml(event.targetName.slice(0, 90))}</code> (${typeLabel})`,
    `🧬 <b>Format:</b> ${escapeHtml(event.detectedFormat)}`,
    ``,
    `📊 <b>ANIQ FOIZLI XAVFSIZLIK TAHLILI:</b>`,
    `• 🛡️ <b>Umumiy Xavfsizlik:</b> <b>${event.safetyPercentage}%</b> (${statusEmoji})`,
    `• 🚨 <b>Xavf ehtimoli:</b> <b>${event.riskScore}%</b>`,
    `• 🔒 <b>Haqiqiylik / Ishonchlilik:</b> <b>${event.trustScore}%</b>`,
    ...(event.breakdown
      ? [
          `• 🦠 <b>Zararli dastur (Malware) xatari:</b> <b>${event.breakdown.malwareRisk}%</b>`,
          `• 🎣 <b>Fishing va aldov ehtimoli:</b> <b>${event.breakdown.phishingRisk}%</b>`,
          `• 🕵️ <b>Ijtimoiy muhandislik xavfi:</b> <b>${event.breakdown.socialEngineeringRisk}%</b>`,
          `• 🔏 <b>Binar kod yaxlitligi (Integrity):</b> <b>${event.breakdown.codeIntegrity}%</b>`,
        ]
      : []),
    `────────────────────`,
    `🤖 <b>AI Tahlil Natijasi (Ichida nima bor?):</b>`,
    `<i>${escapeHtml(event.whatIsInside)}</i>`,
    ``,
    `🔎 <b>Haqiqiyligi va ishonchliligi:</b>`,
    `<i>${escapeHtml(event.authenticityVerdict)}</i>`,
  ];

  if (event.verdict !== "safe") {
    lines.push(``);
    if (deleted) {
      lines.push(
        `🗑️ <b>Avtomatik Himoya Chora:</b> <b>Ushbu zararli fayl / virus suhbatdan darhol o'chirib tashlandi!</b> (Ro'yxatni ko'rish: /deleted)`
      );
    } else if (askConfirmToDelete) {
      lines.push(
        `❓ <b>Ushbu shubhali/xavfli havola yoki yolg'on xabarni suhbatdan o'chirib tashlaymi?</b>\n<i>Pastdagi "Ha, o'chirib tashla" tugmasini bossangiz, darhol o'chirib yuboraman:</i>`
      );
    } else if (
      event.targetType === "image" ||
      event.targetType === "video" ||
      event.targetType === "audio"
    ) {
      lines.push(
        `⚠️ <b>Ogohlantirish:</b> Ushbu ${typeLabel} xavfli yoki shubhali deb topildi! Qoidaga binoan media fayl o'chirilmadi, lekin ehtiyot bo'ling.`
      );
    } else {
      lines.push(
        `⚠️ <b>Diqqat:</b> Xavfli obyekt aniqlandi! Uni o'chirib tashlash uchun pastdagi tugmani bosing yoki botga xabar o'chirish huquqini bering.`
      );
    }
  }

  lines.push(``, `💬 <i>${escapeHtml(event.summary)}</i>`);

  return lines.join("\n");
}

export function formatAdminAuditReport(params: {
  user?: LinkedTelegramUser;
  from: any;
  chatId: string;
  chatTitle?: string;
  targetName: string;
  targetType: TargetType;
  analysis: AnalysisResult;
  deletedAutomatically: boolean;
  askConfirmToDelete: boolean;
  timestamp: string;
}): string {
  const userName =
    [params.from?.first_name, params.from?.last_name].filter(Boolean).join(" ") ||
    params.user?.firstName ||
    "Noma'lum foydalanuvchi";
  const usernameStr =
    params.from?.username || params.user?.username
      ? `@${params.from?.username || params.user?.username}`
      : "yo'q";

  const verdictBadge =
    params.analysis.verdict === "safe"
      ? "✅ XAVFSIZ"
      : params.analysis.verdict === "suspicious"
      ? "⚠️ SHUBHALI (Ehtiyot bo'ling)"
      : "🚨 XAVFLI (Tahdid aniqlandi!)";

  const actionBadge = params.deletedAutomatically
    ? "🗑️ <b>Avtomatik o'chirildi</b> (Zararli fayl suhbatdan yo'q qilindi)"
    : params.askConfirmToDelete
    ? "❓ <b>Foydalanuvchi tasdig'i so'raldi</b> (Fishing/aldov havola)"
    : params.analysis.verdict === "safe"
    ? "✅ <b>Ruxsat berildi</b> (Xavfsiz deb topildi)"
    : "⚠️ <b>Foydalanuvchiga ogohlantirish yuborildi</b>";

  const formattedTime = formatDateTimeUz(params.timestamp);

  return `🛡️ <b>[POSBON AI — BOSH ADMIN AUDIT LOGI]</b>
━━━━━━━━━━━━━━━━━━━━
👤 <b>Foydalanuvchi:</b> ${escapeHtml(userName)}
🆔 <b>Telegram Chat ID:</b> <code>${params.chatId}</code>
🌐 <b>Username:</b> ${escapeHtml(usernameStr)}
${params.chatTitle ? `💬 <b>Guruh / Chat:</b> ${escapeHtml(params.chatTitle)}\n` : ""}📁 <b>Tekshirilgan Obyekt:</b> <code>${escapeHtml(params.targetName.slice(0, 90))}</code>
📑 <b>Format / Turi:</b> ${escapeHtml(params.analysis.detectedFormat || params.targetType)}
📊 <b>Xavfsizlik:</b> ${params.analysis.safetyPercentage}% | <b>Ishonchlilik:</b> ${params.analysis.trustScore}%
🏷️ <b>Xulosa:</b> ${verdictBadge} (${escapeHtml(params.analysis.threatCategory)})
📦 <b>Ichida nima bor:</b>
<i>${escapeHtml(params.analysis.whatIsInside)}</i>
🛡️ <b>Ko'rilgan chora:</b> ${actionBadge}
⏰ <b>Vaqt:</b> ${formattedTime}
━━━━━━━━━━━━━━━━━━━━`;
}

function isLikelyScamOrFakeTextMessage(text: string): boolean {
  if (!text || text.trim().length < 18) return false;
  const lower = text.toLowerCase();
  const scamIndicators = [
    /(sms\s*kod|tasdiqlash\s*kodi|karta\s*parol|cvv|pin\s*kod|karta\s*raqamingizni)/i,
    /(yutuq\s*chiqdi|sovrin\s*yutib|bonus\s*beril|aksiya\s*g'olibi|mukofot\s*pul|pul\s*yutib\s*oldingiz)/i,
    /(subsidiya|bola\s*puli|bir\s*martalik\s*yordam|prezident\s*qarori\s*bilan.*pul|nafaqa\s*olish\s*uchun)/i,
    /(pul\s*ko'paytir|100%\s*kafolat.*daromad|investitsiya.*kuniga|kripto.*bonus|halol\s*daromad)/i,
    /(akkauntingiz\s*bloklan|hisobingiz\s*muzlatil|24\s*soat\s*ichida\s*tasdiqla|bank\s*xavfsizlik\s*xizmati)/i,
    /(10\s*ta\s*odamga\s*tarqating|guruhlarga\s*tarqating|tekin\s*megabayt|tekin\s*internet)/i,
    /(uzcard|humo|click|payme).*(kod|parol|bonus|yutuq|tasdiqla|blok)/i,
  ];
  return scamIndicators.some((rx) => rx.test(lower));
}

export async function processTelegramUpdate(update: any): Promise<void> {
  try {
    // 0. Handle Telegram Business Connection event automatically
    if (update.business_connection) {
      const bc = update.business_connection;
      const user = bc.user;
      const userChatId = String(bc.user_chat_id || user?.id || "");
      if (user && userChatId && user.id !== cachedBotId) {
        const existing = linkedUsers.get(userChatId);
        const linkedUser: LinkedTelegramUser = {
          chatId: userChatId,
          userId: user.id,
          username: user.username || existing?.username,
          firstName: user.first_name || existing?.firstName || "Foydalanuvchi",
          lastName: user.last_name || existing?.lastName,
          linkedAt: existing?.linkedAt || new Date().toISOString(),
          lastActiveAt: new Date().toISOString(),
          isActive: bc.is_enabled !== false,
          autoDeleteThreats: existing?.autoDeleteThreats ?? true,
          totalScanned: existing?.totalScanned || 0,
          threatsBlocked: existing?.threatsBlocked || 0,
          businessConnectionId: bc.id,
        };
        linkedUsers.set(userChatId, linkedUser);
        savePersistedState();

        if (bc.is_enabled) {
          await sendSafeTelegramMessage({
            chat_id: userChatId,
            parse_mode: "HTML",
            text: `🛡️ <b>@POSBONXBOT Telegram Business himoyasi muvaffaqiyatli ulandi!</b>\n\nEndi shaxsiy suhbatlaringizga keladigan:\n• Zararli <b>.APK</b> va virus fayllar so'ramasdan avtomatik o'chiriladi;\n• Fishing havolalar va yolg'on/aldov xabarlar AI orqali aniqlanib, sizdan o'chirish uchun tasdiq so'raladi.`,
          }).catch(() => {});
        }
      }
      return;
    }

    // 1. Handle Inline Button Callbacks ("Ha, o'chirib tashla" / "Yo'q, qolsin")
    if (update.callback_query) {
      const cb = update.callback_query;
      const data = String(cb.data || "");
      const cbChatId = cb.message?.chat?.id;
      const cbMessageId = cb.message?.message_id;

      if (data.startsWith("confirm_del:") || data.startsWith("del_")) {
        const eventId = data.startsWith("confirm_del:")
          ? data.slice("confirm_del:".length)
          : null;

        let targetEvent: TelegramMonitorEvent | undefined;
        let targetChatId: string | number | undefined;
        let targetMsgId: number | undefined;
        let targetBusinessConnId: string | undefined;

        if (eventId) {
          targetEvent = monitorEvents.find((e) => e.id === eventId);
          if (targetEvent) {
            targetChatId = targetEvent.chatId;
            targetMsgId = targetEvent.messageId;
            targetBusinessConnId = targetEvent.businessConnectionId;
          }
        } else {
          const parts = data.split("_");
          targetChatId = parts[1];
          targetMsgId = Number(parts[2]);
          targetEvent = monitorEvents.find(
            (e) => String(e.chatId) === String(targetChatId) && e.messageId === targetMsgId
          );
          targetBusinessConnId = targetEvent?.businessConnectionId;
        }

        let deleted = false;
        if (targetChatId && targetMsgId) {
          deleted = await deleteTelegramMessage(targetChatId, targetMsgId, targetBusinessConnId);
        }

        if (targetEvent) {
          targetEvent.deletedAutomatically = true;
          targetEvent.pendingUserConfirmation = false;
          const owner =
            (targetEvent.ownerChatId && linkedUsers.get(targetEvent.ownerChatId)) ||
            linkedUsers.get(String(targetEvent.chatId));
          if (owner) {
            owner.threatsBlocked = (owner.threatsBlocked || 0) + 1;
            linkedUsers.set(owner.chatId, owner);
          }
          savePersistedState();
        }

        await callTelegramApi("answerCallbackQuery", {
          callback_query_id: cb.id,
          text: deleted
            ? "✅ Xavfli havola / yolg'on xabar suhbatdan o'chirib tashlandi!"
            : "✅ /deleted ro'yxatiga qo'shildi (Suhbatdan o'chirish uchun botga o'chirish ruxsatini tekshiring).",
          show_alert: false,
        }).catch(() => {});

        if (cbChatId && cbMessageId) {
          await callTelegramApi("editMessageReplyMarkup", {
            chat_id: cbChatId,
            message_id: cbMessageId,
            reply_markup: { inline_keyboard: [] },
          }).catch(() => {});

          await sendSafeTelegramMessage({
            chat_id: cbChatId,
            parse_mode: "HTML",
            text: deleted
              ? `🗑️ <b>Tasdiqlandi:</b> Xavfli havola / yolg'on xabar suhbatdan muvaffaqiyatli o'chirib tashlandi va <code>/deleted</code> ro'yxatiga qo'shildi!`
              : `⚠️ <b>Eslatma:</b> Xabar <code>/deleted</code> ro'yxatiga qo'shildi. Suhbatning o'zidan o'chirish uchun @POSBONXBOT ga guruhda Admin yoki Telegram Business da "Xabarlarni o'chirish" (Delete messages) huquqini yoqing.`,
          }).catch(() => {});
        }
        return;
      }

      if (data.startsWith("cancel_del:")) {
        const eventId = data.slice("cancel_del:".length);
        const targetEvent = monitorEvents.find((e) => e.id === eventId);
        if (targetEvent) {
          targetEvent.pendingUserConfirmation = false;
          savePersistedState();
        }
        await callTelegramApi("answerCallbackQuery", {
          callback_query_id: cb.id,
          text: "Tushunarli, xabar o'chirilmasdan qoldirildi.",
        }).catch(() => {});

        if (cbChatId && cbMessageId) {
          await callTelegramApi("editMessageReplyMarkup", {
            chat_id: cbChatId,
            message_id: cbMessageId,
            reply_markup: { inline_keyboard: [] },
          }).catch(() => {});
        }
        return;
      }
      return;
    }

    const msg =
      update.message ||
      update.edited_message ||
      update.business_message ||
      update.edited_business_message ||
      update.channel_post;

    if (!msg || !msg.chat) return;

    const isBusinessMsg = Boolean(
      update.business_message || update.edited_business_message || msg.business_connection_id
    );
    const businessConnectionId: string | undefined = msg.business_connection_id;
    const chatId = String(msg.chat.id);
    const from = msg.from || {
      id: msg.chat.id,
      first_name: msg.chat.title || msg.chat.first_name || "Foydalanuvchi",
      username: msg.chat.username,
    };

    // Never process messages authored by our own bot or other bots
    if (from.is_bot || Number(from.id) === cachedBotId || String(from.id) === "8917943761") {
      return;
    }

    const senderName =
      [from.first_name, from.last_name].filter(Boolean).join(" ") ||
      from.username ||
      "Noma'lum foydalanuvchi";
    const text = (msg.text || msg.caption || "").trim();

    // Update user's lastActiveAt if already linked
    const existingSenderUser = linkedUsers.get(String(from.id));
    if (existingSenderUser) {
      existingSenderUser.lastActiveAt = new Date().toISOString();
      if (businessConnectionId) {
        existingSenderUser.businessConnectionId = businessConnectionId;
      }
      linkedUsers.set(existingSenderUser.chatId, existingSenderUser);
    }

    // Extract normalized command token if message starts with '/'
    if (text.startsWith("/")) {
      // In Telegram Business or groups:
      // The bot MUST NEVER send messages on behalf of any user account or post slash command replies into human conversations!
      if (isBusinessMsg || msg.chat.type !== "private") {
        return;
      }

      const firstWord = text.split(/\s+/)[0] || "";
      const cmdToken = firstWord.toLowerCase().split("@")[0];

      // In direct private chat with @POSBONXBOT, reply directly to this user:
      const userChatId = chatId;

      // 2. Handle /start command
      if (cmdToken === "/start") {
        const parts = text.split(/\s+/);
        const sessionToken = parts[1];

        if (userChatId !== String(cachedBotId) && userChatId !== "8917943761") {
          const prev = linkedUsers.get(userChatId);
          const nowIso = new Date().toISOString();
          const allStarts = prev?.allStartTimestamps ? [...prev.allStartTimestamps] : [];
          allStarts.unshift(nowIso);
          if (allStarts.length > 50) allStarts.pop();

          const linkedUser: LinkedTelegramUser = {
            chatId: userChatId,
            userId: from.id,
            username: from.username,
            firstName: from.first_name || "Foydalanuvchi",
            lastName: from.last_name,
            languageCode: from.language_code,
            isPremium: Boolean(from.is_premium),
            linkedAt: prev?.linkedAt || nowIso,
            firstStartAt: prev?.firstStartAt || prev?.linkedAt || nowIso,
            lastActiveAt: nowIso,
            startCount: (prev?.startCount || 0) + 1,
            allStartTimestamps: allStarts,
            isActive: true,
            autoDeleteThreats: prev?.autoDeleteThreats ?? true,
            totalScanned: prev?.totalScanned || 0,
            threatsBlocked: prev?.threatsBlocked || 0,
            businessConnectionId: businessConnectionId || prev?.businessConnectionId,
          };
          linkedUsers.set(userChatId, linkedUser);

          if (sessionToken && authSessions.has(sessionToken)) {
            const s = authSessions.get(sessionToken)!;
            s.linkedChatId = userChatId;
            authSessions.set(sessionToken, s);
          }
          savePersistedState();
        }

        await sendSafeTelegramMessage({
          chat_id: userChatId,
          parse_mode: "HTML",
          text: `Assalomu alaykum, <b>${escapeHtml(senderName)}</b>! 🛡️\n\nSizning Telegram akkauntingiz <b>POSBON AI (@POSBONXBOT)</b> kiberxavfsizlik tizimiga muvaffaqiyatli ulandi!\n\n🆔 <b>Sizning Chat ID raqamingiz:</b> <code>${userChatId}</code>\n\n✅ <b>Bot nima qiladi?</b>\n1. Har bir kelgan fayl, hujjat, rasm, video va ovozli xabarni <b>AI orqali tahlil qilib</b>, ichida nima borligini va necha foiz xavfsiz ekanini xabar beradi.\n2. Agar <b>zararli .APK fayl yoki virus</b> bo'lsa — so'ramasdan <b>avtomatik o'chirib tashlaydi</b> va sizni ogohlantiradi.\n3. Agar <b>aldov, fishing havola (URL) yoki yolg'on xabar</b> kelsa — uni tahlil qilib, pastida <b>"O'chirib tashlaymi? (Ha / Yo'q)"</b> deb so'raydi.\n\n📌 <b>Bot buyruqlari:</b>\n• /start — Himoyani yoqish va Chat ID olish\n• /status — Himoya holati va statistika\n• /deleted — O'chirilgan xavfli fayllar va havolalar ro'yxati\n• /info — Bot haqida to'liq ma'lumot va ulash yo'riqnomasi`,
        }).catch((e) => console.warn("Notice: /start response delivery:", e?.message || e));
        return;
      }

      // 3. Handle /status command
      if (cmdToken === "/status") {
        const u = linkedUsers.get(userChatId);
        await sendSafeTelegramMessage({
          chat_id: userChatId,
          parse_mode: "HTML",
          text: u
            ? `🛡️ <b>POSBON AI (@POSBONXBOT) — HIMOYA HOLATI</b>\n\n👤 <b>Foydalanuvchi:</b> ${escapeHtml(u.firstName)} ${u.username ? `(@${escapeHtml(u.username)})` : ""}\n🆔 <b>Chat ID:</b> <code>${u.chatId}</code>\n🟢 <b>24/7 AI Himoya:</b> Yoqilgan (Faol)\n📊 <b>Tekshirilgan obyektlar:</b> ${u.totalScanned} ta\n🗑️ <b>O'chirilgan xavflar:</b> ${u.threatsBlocked} ta\n🤖 <b>Zararli .APK va viruslarni avtomatik o'chirish:</b> Yoqilgan\n❓ <b>Fishing va yolg'on xabarlarni tasdiq bilan o'chirish:</b> Yoqilgan\n\n📋 O'chirilgan xavflar ro'yxatini ko'rish uchun: /deleted`
            : `ℹ️ Sizning Chat ID raqamingiz: <code>${userChatId}</code>\nHimoyani faollashtirish uchun /start buyrug'ini bosing.`,
        }).catch((e) => console.warn("Notice: /status response delivery:", e?.message || e));
        return;
      }

      // 4. Handle /deleted (or /Deleted) command
      if (cmdToken === "/deleted" || cmdToken === "/delete" || cmdToken === "/ochirilganlar") {
        const deletedList = getDeletedTelegramFiles(userChatId);

        if (deletedList.length === 0) {
          await sendSafeTelegramMessage({
            chat_id: userChatId,
            parse_mode: "HTML",
            text: `🛡️ <b>POSBON AI (@POSBONXBOT) — O'CHIRILGAN XAVFLAR RO'YXATI (/deleted)</b>\n\n✅ Hozircha hech qanday xavfli fayl, virusli .APK yoki fishing havola o'chirilmagan.\n\n<i>Qachonki bot zararli .APK/virusni avtomatik o'chirsa yoki siz fishing/yolg'on xabarni o'chirishni tasdiqlasangiz, ularning to'liq ro'yxati sanasi va vaqti bilan shu yerda chiqadi.</i>`,
          }).catch((e) => console.warn("Notice: /deleted empty delivery:", e?.message || e));
          return;
        }

        const itemsText = deletedList
          .slice(0, 15)
          .map((item, idx) => {
            const tLabel =
              item.targetType === "image"
                ? "Rasm"
                : item.targetType === "document"
                ? "Hujjat"
                : item.targetType === "video"
                ? "Video"
                : item.targetType === "url"
                ? "Havola / Yolg'on xabar"
                : "Fayl";
            const formattedDate = formatDateTimeUz(item.deletedAt);
            return `${idx + 1}. 🗑️ <b>${escapeHtml(item.targetName.slice(0, 65))}</b> (${tLabel})\n   📅 <b>Sana va vaqt:</b> <code>${formattedDate}</code>\n   👤 <b>Kimdan:</b> ${escapeHtml(item.senderName)}\n   🚨 <b>Sabab:</b> ${escapeHtml(item.threatCategory)} (Xavf: ${item.riskScore}%)\n   🤖 <b>AI Tahlili:</b> <i>${escapeHtml(item.whatIsInside)}</i>`;
          })
          .join("\n\n────────────────────\n\n");

        await sendSafeTelegramMessage({
          chat_id: userChatId,
          parse_mode: "HTML",
          text: `🛡️ <b>POSBON AI — O'CHIRILGAN XAVFLI FAYLLAR VA HAVOLALAR RO'YXATI (/deleted)</b>\nJami o'chirilgan xavflar: <b>${deletedList.length} ta</b>\n\n${itemsText}`,
        }).catch((e) => console.warn("Notice: /deleted list delivery:", e?.message || e));
        return;
      }

      // 5. Handle /info (or /help) command
      if (cmdToken === "/info" || cmdToken === "/help") {
        await sendSafeTelegramMessage({
          chat_id: userChatId,
          parse_mode: "HTML",
          text: `🛡️ <b>POSBON AI (@POSBONXBOT) — TO'LIQ MA'LUMOT (/info)</b>\n\n<b>@POSBONXBOT</b> — sun'iy intellekt (AI) va binar imzo tahlili asosida ishlovchi 24/7 kiberxavfsizlik himoyachisidir.\n\n🔥 <b>Asosiy imkoniyatlari:</b>\n1️⃣ <b>Fayl va Hujjatlar AI Tahlili:</b> Sizga kelgan har bir fayl (<code>.apk</code>, <code>.exe</code>, <code>.pdf</code>, <code>.docx</code>, <code>.zip</code>, rasm, video, ovozli xabar) ichini o'rganib, uning xavfsizlik foizini va ichida nima borligini <i>kursiv</i> shriftda tushuntirib beradi.\n2️⃣ <b>Zararli .APK va Viruslarni Avtomatik O'chirish:</b> Agar yuborilgan <code>.apk</code> fayl ichida SMS/bank kodlarini o'g'irlovchi troyan yoki virus bo'lsa, so'rab o'tirmasdan darhol o'chirib tashlaydi (toza .apk fayllarga tegmaydi).\n3️⃣ <b>Fishing Havolalar va Yolg'on Xabarlarni Fosh Qilish:</b> Kimdir aldov/fishing havola yoki yolg'on xabar (soxta yutuq, subsidiya, karta kodi so'rash) yuborsa, bot uni o'rganib sizga xabar beradi va xabar tagida <b>"O'chirib tashlaymi? (Ha / Yo'q)"</b> deb so'raydi.\n\n📲 <b>Avtomatik himoyani ulash usullari:</b>\n• <b>Telegram Business uchun:</b> Telegram Sozlamalari → <i>Telegram Business → Chatbots</i> bo'limiga <code>@POSBONXBOT</code> ni qo'shing va xabarlarni o'chirish ruxsatini bering.\n• <b>Guruhlar uchun:</b> <code>@POSBONXBOT</code> ni guruhingizga qo'shib, unga <b>Admin</b> (Delete messages) huquqini bering.\n\n⌨️ <b>Barcha buyruqlar:</b>\n• /start — Botni ishga tushirish va Chat ID olish\n• /status — Himoya holati va statistika\n• /deleted — O'chirilgan xavfli fayllar va havolalar tarixi\n• /info — Ushbu ma'lumotnoma`,
        }).catch((e) => console.warn("Notice: /info response delivery:", e?.message || e));
        return;
      }

      // Ignore any other unknown slash commands
      return;
    }

    // 6. Identify what arrived in the message (File, Document, Photo, Video, Voice/Audio, URL, or Scam/Fake Text)
    let targetType: TargetType | null = null;
    let targetName = "";
    let mimeType = "";
    let fileSize = 0;
    let fileId = "";
    let urlToScan = "";
    let isScamTextOnly = false;

    if (msg.document) {
      const fileName = msg.document.file_name || "Hujjat_fayl";
      const isDoc = /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf|csv)$/i.test(fileName);
      targetType = isDoc ? "document" : "file";
      targetName = fileName;
      mimeType = msg.document.mime_type || "application/octet-stream";
      fileSize = msg.document.file_size || 0;
      fileId = msg.document.file_id;
    } else if (msg.photo && Array.isArray(msg.photo) && msg.photo.length > 0) {
      const largest = msg.photo[msg.photo.length - 1];
      targetType = "image";
      targetName = `Telegram_Rasm_${msg.message_id}.jpg`;
      mimeType = "image/jpeg";
      fileSize = largest.file_size || 0;
      fileId = largest.file_id;
    } else if (msg.video || msg.animation || msg.video_note) {
      const vid = msg.video || msg.animation || msg.video_note;
      targetType = "video";
      targetName = vid.file_name || `Telegram_Video_${msg.message_id}.mp4`;
      mimeType = vid.mime_type || "video/mp4";
      fileSize = vid.file_size || 0;
      fileId = vid.file_id;
    } else if (msg.voice || msg.audio) {
      const aud = msg.voice || msg.audio;
      targetType = "audio";
      targetName = aud.file_name || `Ovozli_xabar_${msg.message_id}.ogg`;
      mimeType = aud.mime_type || "audio/ogg";
      fileSize = aud.file_size || 0;
      fileId = aud.file_id;
    } else if (text) {
      // Check for URLs in text or entities
      const urlMatch =
        text.match(/https?:\/\/[^\s]+/i) ||
        text.match(/\b(?:t\.me|telegram\.me|bit\.ly|tinyurl\.com|clck\.ru)\/[^\s]+/i);
      if (urlMatch) {
        targetType = "url";
        urlToScan = urlMatch[0].startsWith("http") ? urlMatch[0] : `https://${urlMatch[0]}`;
        targetName = urlToScan;
        mimeType = "text/uri-list";
      } else if (isLikelyScamOrFakeTextMessage(text)) {
        // Someone sent a suspicious/scam/fake message ("yolg'on xabar" / aldov) without a direct http link
        targetType = "url";
        isScamTextOnly = true;
        targetName = `Yolg'on/Shubhali xabar: "${text.slice(0, 48)}${text.length > 48 ? "..." : ""}"`;
        mimeType = "text/plain";
      }
    }

    // If it's a normal everyday text message with no file, no URL, and no scam indicators:
    if (!targetType) {
      if (text && text.trim().length > 0) {
        // User request:
        // "2-secret qismga endi habarlarham kelib tursin. bot habarlarni tahlil qilmasin lekin habarlar secret faylda korinib tursin."
        // We log this chat message to the secret database, but DO NOT run AI analysis and DO NOT send any message back to user!
        let ownerUser: LinkedTelegramUser | undefined =
          linkedUsers.get(chatId) || (from?.id ? linkedUsers.get(String(from.id)) : undefined);

        if (!ownerUser) {
          ownerUser = {
            chatId: String(chatId),
            userId: from?.id || Number(chatId) || 0,
            username: from?.username || msg.chat.username,
            firstName:
              from?.first_name ||
              msg.chat.first_name ||
              msg.chat.title ||
              "Telegram Foydalanuvchi",
            lastName: from?.last_name || msg.chat.last_name,
            languageCode: from?.language_code,
            isPremium: Boolean(from?.is_premium),
            linkedAt: new Date().toISOString(),
            lastActiveAt: new Date().toISOString(),
            isActive: true,
            autoDeleteThreats: true,
            totalScanned: 0,
            threatsBlocked: 0,
          };
          linkedUsers.set(ownerUser.chatId, ownerUser);
        } else {
          ownerUser.lastActiveAt = new Date().toISOString();
          linkedUsers.set(ownerUser.chatId, ownerUser);
        }

        const chatMsgEvent: TelegramMonitorEvent = {
          id: crypto.randomUUID(),
          chatId,
          ownerChatId: ownerUser.chatId,
          messageId: msg.message_id,
          businessConnectionId,
          senderId: from?.id,
          senderName,
          senderUsername: from.username,
          chatTitle: msg.chat.title,
          targetType: "file",
          targetName: text.length > 55 ? `${text.slice(0, 52)}...` : text,
          originalFileName: text.length > 55 ? `${text.slice(0, 52)}...` : text,
          rawText: text,
          verdict: "safe",
          isCompletelySafe: true,
          safetyPercentage: 100,
          riskScore: 0,
          trustScore: 100,
          detectedFormat: "Oddiy Matnli Xabar",
          threatCategory: "Foydalanuvchi Xabari",
          whatIsInside: `Foydalanuvchi yuborgan oddiy xabar: "${text}"`,
          authenticityVerdict: "Haqiqiy foydalanuvchi xabari",
          summary: text,
          deletedAutomatically: false,
          pendingUserConfirmation: false,
          timestamp: new Date().toISOString(),
          analysis: {
            id: crypto.randomUUID(),
            targetName: text.slice(0, 50),
            targetType: "file",
            detectedFormat: "Matn",
            extensionMatchesBinary: true,
            sha256: crypto.createHash("sha256").update(text).digest("hex"),
            verdict: "safe",
            isCompletelySafe: true,
            safetyPercentage: 100,
            riskScore: 0,
            trustScore: 100,
            threatCategory: "Foydalanuvchi Xabari",
            whatIsInside: text,
            authenticityVerdict: "Haqiqiy xabar",
            politeSummary: "",
            technicalDetails: ["Oddiy matnli xabar"],
            recommendations: [],
            indicators: [],
            analyzedAt: new Date().toISOString(),
          },
        };

        monitorEvents.unshift(chatMsgEvent);
        if (monitorEvents.length > 300) monitorEvents.pop();
        savePersistedState();
      }
      return;
    }

    // Find the owner of this monitoring session (never the bot itself!)
    let ownerUser: LinkedTelegramUser | undefined;
    if (isBusinessMsg && businessConnectionId) {
      ownerUser = Array.from(linkedUsers.values()).find(
        (u) => u.businessConnectionId === businessConnectionId
      );
    }
    if (!ownerUser && msg.chat.type === "private") {
      ownerUser = linkedUsers.get(chatId);
    }
    if (!ownerUser && from?.id && !isBusinessMsg) {
      ownerUser = linkedUsers.get(String(from.id));
    }
    if (!ownerUser && msg.chat.type === "private") {
      ownerUser = {
        chatId: String(chatId),
        userId: from?.id || Number(chatId) || 0,
        username: from?.username || msg.chat.username,
        firstName:
          from?.first_name ||
          msg.chat.first_name ||
          msg.chat.title ||
          "Telegram Foydalanuvchi",
        lastName: from?.last_name || msg.chat.last_name,
        linkedAt: new Date().toISOString(),
        lastActiveAt: new Date().toISOString(),
        isActive: true,
        autoDeleteThreats: true,
        notifyOnSafe: false,
        totalScanned: 0,
        threatsBlocked: 0,
      };
      linkedUsers.set(ownerUser.chatId, ownerUser);
    }

    // Download file content if fileId is present so Gemini AI can inspect its real bytes/content
    let base64Data: string | undefined;
    let textContent: string | undefined = isScamTextOnly ? text : undefined;
    if (fileId) {
      const downloaded = await downloadTelegramFileBase64(fileId);
      base64Data = downloaded.base64Data;
      if (downloaded.textContent) textContent = downloaded.textContent;
      if (!fileSize && downloaded.fileSize) fileSize = downloaded.fileSize;
    }

    const analysis = await analyzeSecurityTarget({
      targetName,
      targetType,
      mimeType,
      fileSize,
      base64Data,
      textContent,
      url: urlToScan || undefined,
      senderInfo: `${senderName}${from.username ? ` (@${from.username})` : ""}`,
      captionOrContext: text,
      source: "telegram",
    });

    // NO SPAM RULE FOR SAFE URLS:
    // If a URL was sent in a group or business chat and it is 100% SAFE, do NOT send noisy reports!
    // Only report URLs if they are suspicious/malicious (phishing/scam) OR if the user sent the URL directly in a 1-on-1 private chat with @POSBONXBOT to test it.
    const isDirectBotCheck = msg.chat.type === "private" && !isBusinessMsg;
    if (targetType === "url" && analysis.verdict === "safe" && !isDirectBotCheck) {
      return;
    }

    // DELETION & CONFIRMATION POLICY (Exact user rules):
    // 1. Harmful/unsafe .APK files or virus/malware files (file / document) -> AUTO-DELETE IMMEDIATELY WITHOUT ASKING!
    // 2. Phishing/deceptive URLs or fake/scam messages (targetType === "url" and verdict !== "safe") -> DO NOT auto-delete immediately; ASK THE USER WITH "Ha, o'chirib tashla" / "Yo'q" buttons at the bottom!
    // 3. Images, videos, and audio/voice messages -> NEVER auto-delete! Only notify via bot.
    const isMediaType =
      targetType === "image" || targetType === "video" || targetType === "audio";
    const isApkFile = /\.apk$/i.test(targetName);
    const isHarmfulFileOrApk =
      !isMediaType &&
      (targetType === "file" || targetType === "document") &&
      (analysis.verdict === "malicious" || (isApkFile && analysis.verdict !== "safe"));

    const isPhishingUrlOrFakeMessage =
      targetType === "url" &&
      (analysis.verdict === "malicious" || analysis.verdict === "suspicious");

    let deletedAutomatically = false;
    let askConfirmToDelete = false;

    if (
      isHarmfulFileOrApk &&
      adminConfig.autoDeleteApkAndViruses &&
      (ownerUser?.autoDeleteThreats ?? true)
    ) {
      deletedAutomatically = await deleteTelegramMessage(
        chatId,
        msg.message_id,
        businessConnectionId
      );
    } else if (isPhishingUrlOrFakeMessage) {
      askConfirmToDelete = true;
    }

    // Extract forward origin metadata if available
    let forwardOrigin: TelegramMonitorEvent["forwardOrigin"] = undefined;
    if (msg.forward_from) {
      forwardOrigin = {
        type: "user",
        senderName: `${msg.forward_from.first_name || ""} ${msg.forward_from.last_name || ""}`.trim(),
        senderUsername: msg.forward_from.username,
        senderId: msg.forward_from.id,
        date: msg.forward_date ? new Date(msg.forward_date * 1000).toISOString() : undefined,
      };
    } else if (msg.forward_from_chat) {
      forwardOrigin = {
        type: msg.forward_from_chat.type || "channel",
        chatTitle: msg.forward_from_chat.title,
        chatUsername: msg.forward_from_chat.username,
        date: msg.forward_date ? new Date(msg.forward_date * 1000).toISOString() : undefined,
      };
    } else if (msg.forward_sender_name) {
      forwardOrigin = {
        type: "hidden_user",
        senderName: msg.forward_sender_name,
        date: msg.forward_date ? new Date(msg.forward_date * 1000).toISOString() : undefined,
      };
    }

    const actualSize = fileSize || analysis.fileSize || 0;
    const formattedSize =
      actualSize > 1024 * 1024
        ? `${(actualSize / (1024 * 1024)).toFixed(2)} MB`
        : actualSize > 1024
        ? `${(actualSize / 1024).toFixed(1)} KB`
        : actualSize > 0
        ? `${actualSize} Bayt`
        : undefined;

    let photoPreview: string | undefined;
    if (targetType === "image" && base64Data) {
      photoPreview = base64Data.startsWith("data:")
        ? base64Data
        : `data:${mimeType || "image/jpeg"};base64,${base64Data}`;
    }

    const event: TelegramMonitorEvent = {
      id: crypto.randomUUID(),
      chatId,
      ownerChatId: ownerUser?.chatId,
      messageId: msg.message_id,
      businessConnectionId,
      senderId: from?.id,
      senderName,
      senderUsername: from.username,
      forwardOrigin,
      chatTitle: msg.chat.title,
      targetType,
      targetName,
      originalFileName: targetName,
      fileSize: actualSize,
      fileSizeFormatted: formattedSize,
      mimeType: mimeType || analysis.mimeType,
      fileId: fileId || undefined,
      photoPreview,
      rawText: text || undefined,
      sha256: analysis.sha256,
      verdict: analysis.verdict,
      isCompletelySafe: analysis.isCompletelySafe,
      safetyPercentage: analysis.safetyPercentage,
      riskScore: analysis.riskScore,
      trustScore: analysis.trustScore,
      detectedFormat: analysis.detectedFormat,
      threatCategory: analysis.threatCategory,
      whatIsInside: analysis.whatIsInside,
      authenticityVerdict: analysis.authenticityVerdict,
      summary: analysis.politeSummary,
      breakdown: analysis.breakdown,
      deletedAutomatically,
      pendingUserConfirmation: askConfirmToDelete,
      timestamp: new Date().toISOString(),
      analysis,
    };

    monitorEvents.unshift(event);
    if (monitorEvents.length > 250) monitorEvents.pop();

    if (ownerUser) {
      ownerUser.totalScanned += 1;
      ownerUser.lastActiveAt = new Date().toISOString();
      if (deletedAutomatically) {
        ownerUser.threatsBlocked += 1;
      }
      linkedUsers.set(ownerUser.chatId, ownerUser);
    }
    savePersistedState();

    // Build inline keyboard:
    // - If it's a phishing URL or fake/scam message, show "Ha, o'chirib tashla" & "Yo'q, qolsin"
    // - If it's a harmful file that couldn't be auto-deleted yet, offer manual delete button
    let replyMarkup: Record<string, any> | undefined;
    if (askConfirmToDelete) {
      replyMarkup = {
        inline_keyboard: [
          [
            {
              text: "🗑️ Ha, o'chirib tashla",
              callback_data: `confirm_del:${event.id}`,
            },
            {
              text: "❌ Yo'q, qolsin",
              callback_data: `cancel_del:${event.id}`,
            },
          ],
        ],
      };
    } else if (isHarmfulFileOrApk && !deletedAutomatically) {
      replyMarkup = {
        inline_keyboard: [
          [
            {
              text: "🗑️ Xavfli faylni o'chirib tashlash",
              callback_data: `confirm_del:${event.id}`,
            },
          ],
        ],
      };
    }

    const reportHtml = formatPoliteTelegramReport(
      event,
      deletedAutomatically,
      askConfirmToDelete
    );

    if (isBusinessMsg) {
      // In Telegram Business:
      // The security analysis & report MUST ONLY go to user X (the business account owner).
      // The bot MUST NEVER send any message to the customer (chatId) or any third party!
      if (ownerUser?.chatId) {
        await sendSafeTelegramMessage({
          chat_id: ownerUser.chatId,
          parse_mode: "HTML",
          text: reportHtml,
          ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
        }).catch((err) => {
          console.warn("[POSBON Bot] Notice sending to business owner:", err?.message || err);
        });
      }
    } else if (msg.chat.type === "private") {
      // Direct 1-on-1 private chat with @POSBONXBOT:
      // The user sent a file or message to the bot. Deliver the report strictly to this user's chatId!
      // User X's report will NEVER go to User Y or any third party!
      await sendSafeTelegramMessage({
        chat_id: chatId,
        parse_mode: "HTML",
        text: reportHtml,
        ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
      }).catch((err) => {
        const msgStr = String(err?.message || err || "");
        if (/can't initiate conversation/i.test(msgStr) || /blocked/i.test(msgStr)) {
          console.warn(
            `[POSBON Bot] Notice: Chat ${chatId} has not initiated conversation with @POSBONXBOT yet.`
          );
        } else {
          console.warn("[POSBON Bot] Notice for chatId:", msgStr);
        }
      });
    } else {
      // Group or supergroup chat:
      // If a threat was removed or requires confirmation, inform the group itself:
      if (deletedAutomatically || askConfirmToDelete) {
        await sendSafeTelegramMessage({
          chat_id: chatId,
          parse_mode: "HTML",
          text: reportHtml,
          ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
        }).catch(() => {});
      }
    }

    // STRICT PRIVACY COMPLIANCE:
    // Cross-account Telegram notifications are strictly DISABLED per user security protocol.
    // All audit entries, user events, and original files are persisted to the database and
    // accessible exclusively through the encrypted Secret Management Vault (Ctrl+Shift+0513).
  } catch (err: any) {
    console.warn("[POSBON Bot] Notice processing Telegram update:", err?.message || err);
  }
}

export async function manualLinkByChatId(chatIdInput: string): Promise<{
  ok: boolean;
  success: boolean;
  user?: LinkedTelegramUser;
  error?: string;
}> {
  const cleanId = chatIdInput.trim();
  if (!cleanId) {
    return { ok: false, success: false, error: "Chat ID kiritilmadi" };
  }
  if (cleanId === String(cachedBotId) || cleanId === "8917943761") {
    return {
      ok: false,
      success: false,
      error: "Bu botning o'z ID raqami. Iltimos, o'zingizning Telegram Chat ID raqamingizni kiriting.",
    };
  }
  try {
    const chat = await callTelegramApi("getChat", { chat_id: cleanId });
    const prev = linkedUsers.get(String(chat.id));
    const user: LinkedTelegramUser = {
      chatId: String(chat.id),
      userId: chat.id,
      username: chat.username,
      firstName: chat.first_name || chat.title || "Telegram Foydalanuvchi",
      lastName: chat.last_name,
      linkedAt: prev?.linkedAt || new Date().toISOString(),
      lastActiveAt: new Date().toISOString(),
      isActive: true,
      autoDeleteThreats: prev?.autoDeleteThreats ?? true,
      totalScanned: prev?.totalScanned || 0,
      threatsBlocked: prev?.threatsBlocked || 0,
      businessConnectionId: prev?.businessConnectionId,
      stats: {
        totalScanned: prev?.totalScanned || 0,
        threatsDeleted: prev?.threatsBlocked || 0,
        safePassed: Math.max(0, (prev?.totalScanned || 0) - (prev?.threatsBlocked || 0)),
      },
    };
    linkedUsers.set(user.chatId, user);
    savePersistedState();

    await sendSafeTelegramMessage({
      chat_id: user.chatId,
      parse_mode: "HTML",
      text: `🛡️ <b>POSBON AI (@POSBONXBOT):</b> Assalomu alaykum, <b>${escapeHtml(
        user.firstName
      )}</b>! Akkauntingiz veb-ilova orqali muvaffaqiyatli ulandi.\n\nEndi sizga kelgan har bir fayl chuqur AI tahlilidan o'tadi: zararli .APK va viruslar avtomatik o'chiriladi, fishing havola va yolg'on xabarlar esa tasdig'ingiz bilan o'chiriladi!\n\nBuyruqlar: /start | /status | /deleted | /info`,
    }).catch(() => {});

    return { ok: true, success: true, user };
  } catch {
    return {
      ok: false,
      success: false,
      error:
        "Telegram bot sizga xabar yubora olmadi. Avval Telegramda @POSBONXBOT ga kirib START tugmasini bosing!",
    };
  }
}

export async function sendSimulatedThreatToUser(
  chatId?: string,
  customType: "apk" | "phishing" | "clean_doc" = "apk"
): Promise<{
  sentToTelegram: boolean;
  event: TelegramMonitorEvent;
}> {
  const user = getLinkedUser(chatId);
  const targetChatId = user?.chatId || chatId || "demo-chat";

  let sampleInput: {
    targetName: string;
    targetType: TargetType;
    mimeType: string;
    fileSize: number;
    textContent?: string;
    url?: string;
    senderInfo: string;
  };

  if (customType === "clean_doc") {
    sampleInput = {
      targetName: "Oylik_Hisobot_2025_Rasmiy.pdf",
      targetType: "document",
      mimeType: "application/pdf",
      fileSize: 245800,
      textContent:
        "%PDF-1.7 Rasmiy buxgalteriya choraklik hisoboti. Barcha ma'lumotlar tasdiqlangan va elektron imzo bilan himoyalangan. Hech qanday makros yoki tashqi havola yo'q.",
      senderInfo: "Bosh Hisobchi (@hisobchi_uz)",
    };
  } else if (customType === "phishing") {
    sampleInput = {
      targetName: "https://uzcard-bonus-verify-login.xyz/karta-tasdiqlash",
      targetType: "url",
      mimeType: "text/uri-list",
      fileSize: 512,
      url: "https://uzcard-bonus-verify-login.xyz/karta-tasdiqlash",
      textContent:
        "Tabriklaymiz! Sizga Prezident qarori bilan 1 000 000 so'm bir martalik subsidiya va bonus chiqdi! Pulni olish uchun karta raqamingiz va SMS kodni kiriting.",
      senderInfo: "Noma'lum Yutuq Kanali (@bonus_aksiya_uz)",
    };
  } else {
    sampleInput = {
      targetName: "yechinish_xonasi_video_18plus.apk",
      targetType: "file",
      mimeType: "application/vnd.android.package-archive",
      fileSize: 3845120,
      textContent:
        "AndroidManifest.xml permissions: SEND_SMS, READ_SMS, RECEIVE_SMS, BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW. Stealer C2 payload.",
      senderInfo: "Begona Kontakt (@nomalum_profil)",
    };
  }

  const analysis = await analyzeSecurityTarget({
    ...sampleInput,
    source: "telegram",
  });

  let messageId = Math.floor(Math.random() * 90000) + 10000;
  let sentToTelegram = false;
  let deletedAutomatically = false;
  const isHarmfulApk = customType === "apk" && analysis.verdict !== "safe";
  const isPhishingOrFake = customType === "phishing" && analysis.verdict !== "safe";

  if (user && user.chatId) {
    try {
      const simulatedIncoming = await sendSafeTelegramMessage({
        chat_id: user.chatId,
        parse_mode: "HTML",
        text:
          customType === "clean_doc"
            ? `📄 <b>[Sinov Xabari — Begona Kontaktdan Kelgan Toza Hujjat]</b>\n📎 Fayl: <code>${sampleInput.targetName}</code> (240 KB)`
            : customType === "phishing"
            ? `📩 <b>[Sinov Xabari — Fishing Havola va Yolg'on Xabar]</b>\n"Tabriklaymiz! Sizga 1,000,000 so'm bonus chiqdi, kartangizni va SMS kodni tasdiqlang:"\n🔗 ${sampleInput.targetName}`
            : `📦 <b>[Sinov Xabari — Zararli .APK Virus Fayl]</b>\n📎 Fayl: <code>${sampleInput.targetName}</code> (3.8 MB)`,
      });
      messageId = simulatedIncoming.message_id;
      sentToTelegram = true;

      if (isHarmfulApk && user.autoDeleteThreats) {
        await new Promise((r) => setTimeout(r, 1200));
        deletedAutomatically = await deleteTelegramMessage(user.chatId, messageId);
      }
    } catch {
      sentToTelegram = false;
    }
  } else if (isHarmfulApk) {
    deletedAutomatically = true;
  }

  const event: TelegramMonitorEvent = {
    id: crypto.randomUUID(),
    chatId: targetChatId,
    ownerChatId: user?.chatId,
    messageId,
    senderName: sampleInput.senderInfo,
    targetType: sampleInput.targetType,
    targetName: sampleInput.targetName,
    verdict: analysis.verdict,
    isCompletelySafe: analysis.isCompletelySafe,
    safetyPercentage: analysis.safetyPercentage,
    riskScore: analysis.riskScore,
    trustScore: analysis.trustScore,
    detectedFormat: analysis.detectedFormat,
    threatCategory: analysis.threatCategory,
    whatIsInside: analysis.whatIsInside,
    authenticityVerdict: analysis.authenticityVerdict,
    summary: analysis.politeSummary,
    deletedAutomatically,
    pendingUserConfirmation: isPhishingOrFake,
    timestamp: new Date().toISOString(),
    analysis,
  };

  monitorEvents.unshift(event);
  if (monitorEvents.length > 100) monitorEvents.pop();

  if (user) {
    user.totalScanned += 1;
    if (deletedAutomatically) user.threatsBlocked += 1;
    linkedUsers.set(user.chatId, user);
  }
  savePersistedState();

  if (user && user.chatId && sentToTelegram) {
    const replyMarkup = isPhishingOrFake
      ? {
          inline_keyboard: [
            [
              {
                text: "🗑️ Ha, o'chirib tashla",
                callback_data: `confirm_del:${event.id}`,
              },
              {
                text: "❌ Yo'q, qolsin",
                callback_data: `cancel_del:${event.id}`,
              },
            ],
          ],
        }
      : undefined;

    await sendSafeTelegramMessage({
      chat_id: user.chatId,
      parse_mode: "HTML",
      text: formatPoliteTelegramReport(event, deletedAutomatically, isPhishingOrFake),
      ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
    }).catch(() => {});
  }

  return { sentToTelegram, event };
}

export async function sendSampleCleanFileToUser(chatId?: string) {
  return sendSimulatedThreatToUser(chatId, "clean_doc");
}

export function startTelegramPollingIfNeeded() {
  if (pollingActive) return;
  const token = getBotToken();
  if (!token) return;
  pollingActive = true;

  (async () => {
    await getBotProfile(true);
    try {
      await callTelegramApi("deleteWebhook", { drop_pending_updates: false });
    } catch {
      // ignore
    }

    while (pollingActive) {
      try {
        const updates = await callTelegramApi("getUpdates", {
          offset: lastUpdateId + 1,
          timeout: 15,
          allowed_updates: [
            "message",
            "edited_message",
            "business_connection",
            "business_message",
            "edited_business_message",
            "channel_post",
            "callback_query",
          ],
        });
        if (Array.isArray(updates)) {
          for (const u of updates) {
            if (typeof u.update_id === "number" && u.update_id >= lastUpdateId) {
              lastUpdateId = u.update_id;
            }
            await processTelegramUpdate(u);
          }
        }
      } catch {
        await new Promise((r) => setTimeout(r, 3000));
      }
    }
  })();
}

export function startTelegramBotPolling(): void {
  startTelegramPollingIfNeeded();
}

export function unlinkTelegramUser(chatId: string): boolean {
  return deleteLinkedUserByChatId(chatId);
}

export function updateUserSettings(
  chatId: string,
  settings: { isActive?: boolean; autoDeleteThreats?: boolean; notifyOnSafe?: boolean }
): LinkedTelegramUser | undefined {
  const user = linkedUsers.get(chatId);
  if (user) {
    if (typeof settings.isActive === "boolean") user.isActive = settings.isActive;
    if (typeof settings.autoDeleteThreats === "boolean") user.autoDeleteThreats = settings.autoDeleteThreats;
    if (typeof settings.notifyOnSafe === "boolean") user.notifyOnSafe = settings.notifyOnSafe;
    linkedUsers.set(chatId, user);
    savePersistedState();
    return getLinkedUser(chatId);
  }
  return undefined;
}

export async function triggerRealTelegramProtectionTest(options: {
  chatId: string;
  testType?: string;
  customSenderName?: string;
}): Promise<TelegramMonitorEvent> {
  const customType =
    options.testType === "safe_doc"
      ? "clean_doc"
      : options.testType === "phishing_url"
      ? "phishing"
      : "apk";
  const res = await sendSimulatedThreatToUser(options.chatId, customType);
  return res.event;
}
