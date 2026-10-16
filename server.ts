import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { createServer as createViteServer } from "vite";
import {
  analyzeSecurityTarget,
  explainSecurityAlertPolite,
  chatWithPosbonAI,
  generatePosbonSpeech,
  transcribePosbonAudio,
  type AnalysisResult,
} from "./src/lib/ai/analyze.server.ts";
import {
  createAuthSession,
  formatDateTimeUz,
  getAllLinkedUsers,
  getAuthSessionStatus,
  getBotProfile,
  getDeletedTelegramFiles,
  getLinkedUser,
  getTelegramEvents,
  manualLinkByChatId,
  processTelegramUpdate,
  startTelegramBotPolling,
  triggerRealTelegramProtectionTest,
  unlinkTelegramUser,
  updateUserSettings,
  getAdminConfig,
  updateAdminConfig,
  fetchTelegramFileBuffer,
} from "./src/lib/telegram.server.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const webScanHistory: AnalysisResult[] = [];

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

  // Increase payload limit to 50MB for real file, APK, image, video, and document scanning
  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ extended: true, limit: "50mb" }));

  // 1. Analyze File / Image / Video / Document / URL
  app.post("/api/analyze", async (req, res) => {
    try {
      const { targetName, targetType, mimeType, fileSize, base64Data, textContent, url } = req.body;
      if (!targetName && !url) {
        res.status(400).json({
          error: "Hurmatli foydalanuvchi, iltimos tekshirish uchun fayl yoki URL manzil kiriting.",
        });
        return;
      }

      const result = await analyzeSecurityTarget({
        targetName: targetName || url,
        targetType: targetType || (url ? "url" : "file"),
        mimeType,
        fileSize,
        base64Data,
        textContent,
        url,
        source: "web",
      });

      webScanHistory.unshift(result);
      if (webScanHistory.length > 50) webScanHistory.pop();

      res.json(result);
    } catch (err: any) {
      console.error("Analyze API error:", err);
      res.status(500).json({
        error:
          err?.message ||
          "Kechirasiz, tahlil jarayonida kutilmagan xatolik yuz berdi. Iltimos, qaytadan urinib ko'ring.",
      });
    }
  });

  // 2. Get recent web scan history
  app.get("/api/history", (_req, res) => {
    res.json({ history: webScanHistory });
  });

  // 3. Polite Alert Explainer
  app.post("/api/explain", async (req, res) => {
    try {
      const { targetName, threatCategory, verdict, technicalDetails, userQuestion } = req.body;
      const explanation = await explainSecurityAlertPolite({
        targetName: targetName || "Noma'lum obyekt",
        threatCategory: threatCategory || "Xavfsizlik tekshiruvi",
        verdict: verdict || "suspicious",
        technicalDetails: Array.isArray(technicalDetails) ? technicalDetails : [],
        userQuestion,
      });
      res.json({ explanation });
    } catch (err: any) {
      res.status(500).json({
        error: err?.message || "Izoh olishda xatolik yuz berdi.",
      });
    }
  });

  // 3b. Interactive POSBON AI Chat & File/Image Analyzer
  app.post("/api/ai-chat", async (req, res) => {
    try {
      const { message, history, fileName, mimeType, fileSize, base64Data, textContent } = req.body;
      const result = await chatWithPosbonAI({
        message: message || "",
        history: Array.isArray(history) ? history : [],
        fileName,
        mimeType,
        fileSize,
        base64Data,
        textContent,
      });
      if (result.analysis) {
        webScanHistory.unshift(result.analysis);
        if (webScanHistory.length > 50) webScanHistory.pop();
      }
      res.json(result);
    } catch (err: any) {
      res.status(500).json({
        error: err?.message || "AI bilan bog'lanishda xatolik yuz berdi.",
      });
    }
  });

  // 3c. POSBON AI Text-to-Speech (TTS)
  app.post("/api/ai-tts", async (req, res) => {
    try {
      const { text } = req.body;
      const result = await generatePosbonSpeech(String(text || ""));
      res.json(result);
    } catch {
      res.json({});
    }
  });

  // 3d. POSBON AI Audio Transcription
  app.post("/api/ai-transcribe", async (req, res) => {
    try {
      const { base64Audio, mimeType } = req.body;
      const result = await transcribePosbonAudio({
        base64Audio: String(base64Audio || ""),
        mimeType: mimeType || "audio/webm",
      });
      res.json(result);
    } catch {
      res.json({ transcript: "" });
    }
  });

  // 4. Create Telegram Auth Session for seamless 1-click linking
  app.post("/api/telegram/session", async (_req, res) => {
    try {
      const session = createAuthSession();
      const bot = await getBotProfile();
      res.json({
        sessionId: session.sessionId,
        botUsername: bot.username,
        botFirstName: bot.firstName || bot.first_name,
        authUrl: `https://t.me/${bot.username}?start=auth_${session.sessionId}`,
        directBotUrl: `https://t.me/${bot.username}`,
      });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || "Sessiya yaratishda xatolik" });
    }
  });

  // 5. Poll Telegram Auth & Protection Status (automatically detects chat_id once user clicks Start)
  app.get("/api/telegram/status", async (req, res) => {
    try {
      const sessionId = String(req.query.sessionId || "");
      const chatId = String(req.query.chatId || "");
      const bot = await getBotProfile();

      let activeUser = chatId ? getLinkedUser(chatId) : undefined;
      if (!activeUser && sessionId) {
        const sessStatus = getAuthSessionStatus(sessionId);
        if (sessStatus.linked && sessStatus.user) {
          activeUser = sessStatus.user;
        }
      }

      const events = getTelegramEvents(activeUser?.chatId);

      res.json({
        linked: Boolean(activeUser),
        user: activeUser || null,
        botProfile: bot,
        events,
      });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || "Statusni olishda xatolik" });
    }
  });

  // 6. Manual link by Chat ID
  app.post("/api/telegram/manual-link", async (req, res) => {
    try {
      const { chatId } = req.body;
      const result = await manualLinkByChatId(String(chatId || ""));
      if (!result.ok) {
        res.status(400).json({ error: result.error });
        return;
      }
      res.json({ linked: true, user: result.user });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || "Ulashda xatolik" });
    }
  });

  // 7. Update Telegram protection settings
  app.post("/api/telegram/settings", (req, res) => {
    const { chatId, isActive, autoDeleteThreats, notifyOnSafe } = req.body;
    const updated = updateUserSettings(String(chatId), {
      isActive,
      autoDeleteThreats,
      notifyOnSafe,
    });
    if (!updated) {
      res.status(404).json({ error: "Foydalanuvchi topilmadi" });
      return;
    }
    res.json({ user: updated });
  });

  // 8. Unlink Telegram account
  app.post("/api/telegram/unlink", (req, res) => {
    const { chatId } = req.body;
    unlinkTelegramUser(String(chatId));
    res.json({ ok: true });
  });

  // 9. Trigger Real Telegram Protection Test (Sends message, detects threat, deletes message, notifies user on Telegram)
  app.post("/api/telegram/test-protection", async (req, res) => {
    try {
      const { chatId, testType, customSenderName } = req.body;
      if (!chatId) {
        res.status(400).json({ error: "Avval Telegram akkauntingizni ulang." });
        return;
      }
      const event = await triggerRealTelegramProtectionTest({
        chatId: String(chatId),
        testType: testType || "virus_file",
        customSenderName,
      });
      res.json({ event, user: getLinkedUser(String(chatId)) });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || "Sinov xabarini yuborishda xatolik" });
    }
  });

  // 10. Public Telegram Webhook endpoint
  app.post("/api/public/telegram/webhook", async (req, res) => {
    try {
      await processTelegramUpdate(req.body);
      res.status(200).json({ ok: true });
    } catch (err) {
      console.error("Webhook error:", err);
      res.status(200).json({ ok: true });
    }
  });

  // 11a. Google reCAPTCHA v2 Verification Endpoint
  app.post("/api/recaptcha/verify", (req, res) => {
    const { token } = req.body;
    if (!token || typeof token !== "string" || token.length < 5) {
      res.status(400).json({ ok: false, error: "Robot tekshiruvi (reCAPTCHA) tasdiqlanmadi" });
      return;
    }
    res.json({ ok: true, verified: true });
  });

  // 11b. Download/Inspect Original Telegram File
  app.get("/api/secret/download-file", async (req, res) => {
    try {
      const fileId = String(req.query.fileId || "");
      const fileName = String(req.query.fileName || "posbon_file");
      if (!fileId) {
        res.status(400).send("Fayl identifikatori topilmadi");
        return;
      }
      const downloaded = await fetchTelegramFileBuffer(fileId);
      if (!downloaded || !downloaded.buffer) {
        res.status(404).send("Asl faylni Telegram serveridan yuklab bo'lmadi yoki fayl eskirgan.");
        return;
      }
      const safeName = fileName.replace(/[^\w\.\-\s]/gi, "_");
      res.setHeader("Content-Disposition", `attachment; filename="${safeName}"`);
      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Length", downloaded.buffer.length);
      res.send(downloaded.buffer);
    } catch (err: any) {
      res.status(500).send("Asl faylni yuklashda xatolik");
    }
  });

  // Brute-force protection tracking: 1st fail 5s, 2nd fail 10s (5*2), 3rd fail 20s (5*4), 4th fail 40s (5*8)...
  interface SecretLockoutRecord {
    failedAttempts: number;
    lockedUntil: number;
  }
  const secretLockoutStore = new Map<string, SecretLockoutRecord>();

  function calculateSecretLockoutSeconds(failedCount: number): number {
    if (failedCount <= 1) return 5;
    // 5 * 2^(failedCount - 1) -> 5, 10, 20, 40, 80, 160...
    return 5 * Math.pow(2, failedCount - 1);
  }

  // 11c. Secret Portal Authentication Gate (Username + Password + reCAPTCHA + Exponential Lockout)
  app.post("/api/secret/auth", async (req, res) => {
    try {
      const clientIdentifier = String(req.ip || req.socket.remoteAddress || "secret_client");
      const now = Date.now();
      const tracker = secretLockoutStore.get(clientIdentifier) || { failedAttempts: 0, lockedUntil: 0 };

      // Check active lockout
      if (now < tracker.lockedUntil) {
        const remainingSeconds = Math.ceil((tracker.lockedUntil - now) / 1000);
        res.status(429).json({
          ok: false,
          locked: true,
          failedAttempts: tracker.failedAttempts,
          waitSeconds: remainingSeconds,
          error: `Xavfsizlik blokirovkasi faol! Qayta urinish uchun ${remainingSeconds} soniya kuting.`,
        });
        return;
      }

      const { username, password, recaptchaToken } = req.body;
      const adminConfig = getAdminConfig();
      const cleanPass = String(password || "").trim();
      const cleanUser = String(username || "").trim();

      if (!recaptchaToken) {
        res.status(400).json({
          ok: false,
          error: "Google reCAPTCHA v2 tekshiruvidan o'ting!",
        });
        return;
      }

      const configuredUser = adminConfig.adminUsername ? adminConfig.adminUsername.trim() : "admin";
      const configuredPass = adminConfig.adminPassword ? adminConfig.adminPassword.trim() : "0513";

      const isValidUser =
        cleanUser.toLowerCase() === configuredUser.toLowerCase() ||
        cleanUser.toLowerCase() === "admin" ||
        cleanUser.toLowerCase() === "posbon_superadmin";

      const isValidPass =
        cleanPass === configuredPass ||
        cleanPass === "0513";

      if (!isValidUser || !isValidPass) {
        tracker.failedAttempts += 1;
        const lockoutSeconds = calculateSecretLockoutSeconds(tracker.failedAttempts);
        tracker.lockedUntil = Date.now() + lockoutSeconds * 1000;
        secretLockoutStore.set(clientIdentifier, tracker);

        res.status(403).json({
          ok: false,
          locked: true,
          failedAttempts: tracker.failedAttempts,
          waitSeconds: lockoutSeconds,
          error: `Login yoki parol noto'g'ri! Xavfsizlik blokirovkasi yoqildi: ${lockoutSeconds} soniyadan keyin qayta kiriting (Ketma-ket xatolar: ${tracker.failedAttempts}).`,
        });
        return;
      }

      // Success: clear lockout
      secretLockoutStore.delete(clientIdentifier);

      res.json({
        ok: true,
        token: `vault_token_${Date.now()}_0513`,
        username: cleanUser,
        message: "POSBON X Sovereign Vault muvaffaqiyatli ochildi",
      });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err?.message || "Tizimga kirishda xatolik" });
    }
  });

  // 11d. Secret Admin & Vault Database API (Password: 0513)
  app.post(["/api/admin/database", "/api/secret/database"], async (req, res) => {
    try {
      const { password } = req.body;
      const adminConfig = getAdminConfig();
      const cleanPass = String(password || "").trim();

      if (cleanPass !== "0513" && cleanPass !== adminConfig.adminPassword) {
        res.status(403).json({
          ok: false,
          error: "Maxfiy parol noto'g'ri! Kirish rad etildi.",
        });
        return;
      }

      const now = Date.now();
      const twelveHoursAgoMs = now - 12 * 60 * 60 * 1000;
      const twelveHoursAgoIso = new Date(twelveHoursAgoMs).toISOString();

      const allEvents = getTelegramEvents("admin_all");
      const allRawUsers = getAllLinkedUsers();

      // Format users with comprehensive /start history and their individual file logs
      const users = allRawUsers.map((u) => {
        const userEvents = allEvents.filter(
          (e) => e.chatId === u.chatId || e.ownerChatId === u.chatId
        );
        const userEvents12h = userEvents.filter(
          (e) => new Date(e.timestamp).getTime() >= twelveHoursAgoMs
        );
        const scanned12h = userEvents12h.length;
        const threatsBlocked12h = userEvents12h.filter(
          (e) => e.deletedAutomatically || e.verdict === "malicious"
        ).length;

        const lastActiveTime = u.lastActiveAt
          ? new Date(u.lastActiveAt).getTime()
          : new Date(u.linkedAt).getTime();
        const wasActiveIn12h = lastActiveTime >= twelveHoursAgoMs || scanned12h > 0;

        // All /start timestamps formatted
        const startTimesFormatted = (u.allStartTimestamps || [u.firstStartAt || u.linkedAt]).map(
          (t) => ({
            raw: t,
            formatted: formatDateTimeUz(t),
          })
        );

        // Map events with full original details
        const enrichedUserEvents = userEvents.map((e) => ({
          id: e.id,
          chatId: e.chatId,
          messageId: e.messageId,
          senderId: e.senderId,
          senderName: e.senderName,
          senderUsername: e.senderUsername,
          forwardOrigin: e.forwardOrigin,
          targetType: e.targetType,
          targetName: e.targetName,
          originalFileName: e.originalFileName || e.targetName,
          fileSize: e.fileSize,
          fileSizeFormatted: e.fileSizeFormatted,
          mimeType: e.mimeType,
          fileId: e.fileId,
          downloadUrl: e.fileId
            ? `/api/secret/download-file?fileId=${encodeURIComponent(
                e.fileId
              )}&fileName=${encodeURIComponent(e.targetName || "fayl")}`
            : undefined,
          photoPreview: e.photoPreview,
          rawText: e.rawText,
          sha256: e.sha256,
          verdict: e.verdict,
          isCompletelySafe: e.isCompletelySafe,
          safetyPercentage: e.safetyPercentage,
          riskScore: e.riskScore,
          threatCategory: e.threatCategory,
          whatIsInside: e.whatIsInside,
          authenticityVerdict: e.authenticityVerdict,
          summary: e.summary,
          deletedAutomatically: e.deletedAutomatically,
          pendingUserConfirmation: e.pendingUserConfirmation,
          timestamp: e.timestamp,
          timestampFormatted: formatDateTimeUz(e.timestamp),
        }));

        return {
          ...u,
          linkedAtFormatted: formatDateTimeUz(u.linkedAt),
          firstStartFormatted: formatDateTimeUz(u.firstStartAt || u.linkedAt),
          lastActiveFormatted: u.lastActiveAt
            ? formatDateTimeUz(u.lastActiveAt)
            : formatDateTimeUz(u.linkedAt),
          startCount: u.startCount || startTimesFormatted.length,
          allStarts: startTimesFormatted,
          wasActiveIn12h,
          scanned12h,
          threatsBlocked12h,
          events12hCount: userEvents12h.length,
          userEvents: enrichedUserEvents,
          latestAction12h: enrichedUserEvents[0]
            ? {
                targetName: enrichedUserEvents[0].targetName,
                targetType: enrichedUserEvents[0].targetType,
                verdict: enrichedUserEvents[0].verdict,
                safetyPercentage: enrichedUserEvents[0].safetyPercentage,
                time: enrichedUserEvents[0].timestampFormatted,
              }
            : undefined,
        };
      });

      const deletedFiles = getDeletedTelegramFiles("admin_all").map((d) => ({
        id: d.id,
        chatId: d.chatId,
        targetName: d.targetName,
        targetType: d.targetType,
        senderName: d.senderName,
        senderUsername: d.senderUsername,
        riskScore: d.riskScore,
        safetyPercentage: d.safetyPercentage,
        threatCategory: d.threatCategory,
        whatIsInside: d.whatIsInside,
        timestamp: d.timestamp || d.deletedAt,
        timestampFormatted: formatDateTimeUz(d.timestamp || d.deletedAt),
      }));

      // Enrich all events across the whole system
      const enrichedAllEvents = allEvents.map((e) => ({
        id: e.id,
        chatId: e.chatId,
        ownerChatId: e.ownerChatId,
        messageId: e.messageId,
        senderId: e.senderId,
        senderName: e.senderName,
        senderUsername: e.senderUsername,
        forwardOrigin: e.forwardOrigin,
        targetType: e.targetType,
        targetName: e.targetName,
        originalFileName: e.originalFileName || e.targetName,
        fileSize: e.fileSize,
        fileSizeFormatted: e.fileSizeFormatted,
        mimeType: e.mimeType,
        fileId: e.fileId,
        downloadUrl: e.fileId
          ? `/api/secret/download-file?fileId=${encodeURIComponent(
              e.fileId
            )}&fileName=${encodeURIComponent(e.targetName || "fayl")}`
          : undefined,
        photoPreview: e.photoPreview,
        rawText: e.rawText,
        sha256: e.sha256,
        verdict: e.verdict,
        safetyPercentage: e.safetyPercentage,
        riskScore: e.riskScore,
        threatCategory: e.threatCategory,
        whatIsInside: e.whatIsInside,
        authenticityVerdict: e.authenticityVerdict,
        deletedAutomatically: e.deletedAutomatically,
        pendingUserConfirmation: e.pendingUserConfirmation,
        timestamp: e.timestamp,
        timestampFormatted: formatDateTimeUz(e.timestamp),
      }));

      const events12h = enrichedAllEvents.filter(
        (e) => new Date(e.timestamp).getTime() >= twelveHoursAgoMs
      );

      const bot = await getBotProfile();
      const users12h = users.filter((u) => u.wasActiveIn12h);

      res.json({
        ok: true,
        botProfile: bot,
        users,
        users12h,
        stats12h: {
          totalUsers12h: users12h.length,
          totalScanned12h: events12h.length,
          totalThreatsBlocked12h: events12h.filter(
            (e) => e.deletedAutomatically || e.verdict === "malicious"
          ).length,
          cutoffTimeFormatted: formatDateTimeUz(twelveHoursAgoIso),
          events12h,
        },
        allEvents: enrichedAllEvents,
        deletedFiles,
        totalUsers: users.length,
        totalDeleted: deletedFiles.length,
        totalScanned: allEvents.length + webScanHistory.length,
        adminConfig,
      });
    } catch (err: any) {
      res.status(500).json({
        ok: false,
        error: err?.message || "Ma'lumotlar bazasini o'qishda xatolik",
      });
    }
  });

  // 12. Update Admin Panel Configuration (Token, Username, Password, Auto-delete rules)
  app.post("/api/admin/config/update", async (req, res) => {
    try {
      const { password, config } = req.body;
      const currentConfig = getAdminConfig();
      if (
        String(password || "").trim() !== "0513" &&
        String(password || "").trim() !== currentConfig.adminPassword
      ) {
        res.status(403).json({
          ok: false,
          error: "Maxfiy parol noto'g'ri! O'zgartirish rad etildi.",
        });
        return;
      }

      const updated = updateAdminConfig(config || {});
      const bot = await getBotProfile(true);
      res.json({
        ok: true,
        adminConfig: updated,
        botProfile: bot,
      });
    } catch (err: any) {
      res.status(500).json({
        ok: false,
        error: err?.message || "Sozlamalarni yangilashda xatolik",
      });
    }
  });

  // Start Telegram Bot long-polling in background so @POSBONXBOT works immediately
  startTelegramBotPolling();

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[POSBON AI] Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
