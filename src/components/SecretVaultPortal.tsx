import React, { useState, useEffect, useMemo } from "react";
import {
  Shield,
  Lock,
  Unlock,
  Key,
  Users,
  FileText,
  AlertTriangle,
  Clock,
  Download,
  Search,
  RefreshCw,
  LogOut,
  ChevronRight,
  ChevronDown,
  FileCheck,
  CheckCircle,
  XCircle,
  ExternalLink,
  Sliders,
  Database,
  Radio,
  Eye,
  X,
  FileCode,
  Image as ImageIcon,
  Paperclip,
  Activity,
  Layers,
  Sparkles,
  MessageSquare,
  KeyRound,
  ShieldAlert,
} from "lucide-react";
import { ReCaptchaV2 } from "./ReCaptchaV2";

export interface SecretUserRecord {
  chatId: string;
  userId: number;
  username?: string;
  firstName: string;
  lastName?: string;
  languageCode?: string;
  isPremium?: boolean;
  linkedAt: string;
  linkedAtFormatted: string;
  firstStartFormatted: string;
  lastActiveFormatted: string;
  startCount: number;
  allStarts?: Array<{ raw: string; formatted: string }>;
  wasActiveIn12h: boolean;
  scanned12h: number;
  threatsBlocked12h: number;
  totalScanned: number;
  threatsBlocked: number;
  isActive: boolean;
  autoDeleteThreats: boolean;
  businessConnectionId?: string;
  userEvents?: SecretEventRecord[];
  latestAction12h?: {
    targetName: string;
    targetType: string;
    verdict: string;
    safetyPercentage: number;
    time: string;
  };
}

export interface SecretEventRecord {
  id: string;
  chatId: string;
  ownerChatId?: string;
  messageId?: number;
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
  targetType: "file" | "document" | "image" | "video" | "audio" | "url";
  targetName: string;
  originalFileName?: string;
  fileSize?: number;
  fileSizeFormatted?: string;
  mimeType?: string;
  fileId?: string;
  downloadUrl?: string;
  photoPreview?: string;
  rawText?: string;
  sha256?: string;
  verdict: "safe" | "suspicious" | "malicious";
  isCompletelySafe?: boolean;
  safetyPercentage: number;
  riskScore: number;
  threatCategory: string;
  whatIsInside: string;
  authenticityVerdict: string;
  summary?: string;
  deletedAutomatically: boolean;
  pendingUserConfirmation?: boolean;
  timestamp: string;
  timestampFormatted: string;
}

interface SecretVaultPortalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SecretVaultPortal: React.FC<SecretVaultPortalProps> = ({ isOpen, onClose }) => {
  // Auth state
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    return sessionStorage.getItem("posbon_secret_vault_auth") === "true";
  });
  const [loginUser, setLoginUser] = useState<string>("admin");
  const [password, setPassword] = useState<string>("");
  const [recaptchaToken, setRecaptchaToken] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState<boolean>(false);

  // Exponential lockout countdown state
  const [lockoutSeconds, setLockoutSeconds] = useState<number>(0);
  const [failedAttemptsCount, setFailedAttemptsCount] = useState<number>(0);

  // Portal tabs: users | files | messages | 12h | settings
  const [activeTab, setActiveTab] = useState<"users" | "files" | "messages" | "12h" | "settings">("users");

  // Data state
  const [loadingData, setLoadingData] = useState<boolean>(false);
  const [users, setUsers] = useState<SecretUserRecord[]>([]);
  const [allEvents, setAllEvents] = useState<SecretEventRecord[]>([]);
  const [stats12h, setStats12h] = useState<{
    totalUsers12h: number;
    totalScanned12h: number;
    totalThreatsBlocked12h: number;
    cutoffTimeFormatted?: string;
  } | null>(null);
  const [totalScanned, setTotalScanned] = useState<number>(0);
  const [botProfile, setBotProfile] = useState<any>(null);
  const [adminConfig, setAdminConfig] = useState<any>({
    adminUsername: "admin",
    adminPassword: "0513",
    botToken: "8917943761:AAE0KEsbRAmDHC1B2yXZaEhUPxhBfBq6k6w",
    botUsername: "POSBONXBOT",
    autoDeleteApkAndViruses: true,
    askBeforeDeletePhishingAndScam: true,
    system24x7Active: true,
    additionalGeminiApiKey: "",
  });

  // Selected user for deep inspect
  const [selectedUser, setSelectedUser] = useState<SecretUserRecord | null>(null);

  // Search & filter
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [fileFilter, setFileFilter] = useState<"all" | "file" | "image" | "url" | "malicious">("all");
  const [timeFilter12hOnly, setTimeFilter12hOnly] = useState<boolean>(false);

  // Media preview modal
  const [previewMedia, setPreviewMedia] = useState<{
    type: "image" | "text" | "json";
    title: string;
    url?: string;
    content?: string;
  } | null>(null);

  // Config save feedback
  const [configNotice, setConfigNotice] = useState<string | null>(null);
  const [configSaving, setConfigSaving] = useState<boolean>(false);

  // Lockout countdown timer effect
  useEffect(() => {
    if (lockoutSeconds > 0) {
      const timer = setInterval(() => {
        setLockoutSeconds((prev) => (prev > 0 ? prev - 1 : 0));
      }, 1000);
      return () => clearInterval(timer);
    }
  }, [lockoutSeconds]);

  // Load database once authenticated
  const fetchDatabase = async (overridePassword?: string) => {
    setLoadingData(true);
    try {
      const passToSend = overridePassword || password || adminConfig.adminPassword || "0513";
      const res = await fetch("/api/secret/database", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: passToSend }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Baza ma'lumotlarini o'qib bo'lmadi");
      }
      setUsers(data.users || []);
      setAllEvents(data.allEvents || []);
      setStats12h(data.stats12h || null);
      setTotalScanned(data.totalScanned || 0);
      if (data.botProfile) setBotProfile(data.botProfile);
      if (data.adminConfig) setAdminConfig(data.adminConfig);

      // Keep selectedUser fresh
      if (selectedUser) {
        const fresh = (data.users || []).find((u: SecretUserRecord) => u.chatId === selectedUser.chatId);
        if (fresh) setSelectedUser(fresh);
      }
    } catch (err: any) {
      console.error("Vault fetch error:", err);
    } finally {
      setLoadingData(false);
    }
  };

  useEffect(() => {
    if (isOpen && isAuthenticated) {
      fetchDatabase();
    }
  }, [isOpen, isAuthenticated]);

  // Handle Login Gate Submit with Exponential Lockout
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);

    if (lockoutSeconds > 0) {
      setAuthError(`Xavfsizlik blokirovkasi! Qayta urinish uchun ${lockoutSeconds} soniya kuting.`);
      return;
    }

    if (!recaptchaToken) {
      setAuthError("Iltimos, Google reCAPTCHA v2 tekshiruvidan o'ting!");
      return;
    }

    if (!password.trim()) {
      setAuthError("Maxfiy parolni kiriting");
      return;
    }

    setAuthLoading(true);
    try {
      const res = await fetch("/api/secret/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: loginUser,
          password: password.trim(),
          recaptchaToken,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        if (data.waitSeconds) {
          setLockoutSeconds(data.waitSeconds);
        }
        if (data.failedAttempts) {
          setFailedAttemptsCount(data.failedAttempts);
        }
        throw new Error(data.error || "Kirish rad etildi");
      }

      setIsAuthenticated(true);
      sessionStorage.setItem("posbon_secret_vault_auth", "true");
      setFailedAttemptsCount(0);
      setLockoutSeconds(0);
      await fetchDatabase(password.trim());
    } catch (err: any) {
      setAuthError(err?.message || "Avtorizatsiyada xatolik");
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    sessionStorage.removeItem("posbon_secret_vault_auth");
    setPassword("");
    setRecaptchaToken(null);
    onClose();
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setConfigSaving(true);
    setConfigNotice(null);
    try {
      const res = await fetch("/api/admin/config/update", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          password: password || adminConfig.adminPassword || "0513",
          config: adminConfig,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Sozlamalarni saqlashda xatolik");
      }
      setConfigNotice("Sozlamalar, yangi login/parol va API konfiguratsiyasi muvaffaqiyatli saqlandi!");
      setTimeout(() => setConfigNotice(null), 5000);
      fetchDatabase();
    } catch (err: any) {
      setConfigNotice(`Xatolik: ${err?.message || "Saqlab bo'lmadi"}`);
    } finally {
      setConfigSaving(false);
    }
  };

  // Filtered users
  const filteredUsers = useMemo(() => {
    return users.filter((u) => {
      if (timeFilter12hOnly && !u.wasActiveIn12h) return false;
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      const matchChatId = u.chatId.toLowerCase().includes(q);
      const matchName = (u.firstName + " " + (u.lastName || "")).toLowerCase().includes(q);
      const matchUsername = (u.username || "").toLowerCase().includes(q);
      return matchChatId || matchName || matchUsername;
    });
  }, [users, searchQuery, timeFilter12hOnly]);

  // Filtered files & events
  const filteredEvents = useMemo(() => {
    return allEvents.filter((evt) => {
      if (fileFilter === "malicious" && evt.verdict !== "malicious") return false;
      if (fileFilter === "file" && evt.targetType !== "file" && evt.targetType !== "document") return false;
      if (fileFilter === "image" && evt.targetType !== "image") return false;
      if (fileFilter === "url" && evt.targetType !== "url") return false;
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      const matchName = (evt.targetName || "").toLowerCase().includes(q);
      const matchSender = (evt.senderName || "").toLowerCase().includes(q);
      const matchChatId = (evt.chatId || "").includes(q);
      const matchHash = (evt.sha256 || "").toLowerCase().includes(q);
      const matchText = (evt.rawText || "").toLowerCase().includes(q);
      return matchName || matchSender || matchChatId || matchHash || matchText;
    });
  }, [allEvents, fileFilter, searchQuery]);

  // All incoming chat messages ("bot habarlarni tahlil qilmasin lekin habarlar secret faylda korinib tursin")
  const allChatMessages = useMemo(() => {
    return allEvents.filter((evt) => Boolean(evt.rawText && evt.rawText.trim().length > 0));
  }, [allEvents]);

  // Export JSON audit log
  const handleExportData = () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      system: "POSBON X Sovereign Intelligence Vault 0513",
      bot: botProfile,
      totalUsers: users.length,
      totalInterceptedEvents: allEvents.length,
      totalChatMessages: allChatMessages.length,
      users,
      events: allEvents,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `posbon_vault_full_audit_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-[#050811] text-slate-100 font-sans antialiased overflow-hidden select-text animate-in fade-in duration-200">
      {/* Background Matrix/Cyber Grid Overlay */}
      <div
        className="pointer-events-none absolute inset-0 opacity-15"
        style={{
          backgroundImage: `radial-gradient(#10b981 1px, transparent 1px), radial-gradient(#0ea5e9 1px, transparent 1px)`,
          backgroundSize: "40px 40px",
          backgroundPosition: "0 0, 20px 20px",
        }}
      />

      {/* 1. NOT AUTHENTICATED: CLASSIFIED LOGIN GATE WITH EXPONENTIAL LOCKOUT */}
      {!isAuthenticated ? (
        <div className="relative flex flex-1 items-center justify-center p-4">
          <div className="relative w-full max-w-md rounded-2xl border border-emerald-500/30 bg-[#0a0f1d]/95 p-6 sm:p-8 shadow-2xl shadow-emerald-950/50 backdrop-blur-xl">
            {/* Top Close Button */}
            <button
              onClick={onClose}
              className="absolute right-4 top-4 rounded-xl p-2 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
              title="Yopish"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="text-center space-y-2">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 shadow-lg shadow-emerald-500/20">
                <Shield className="h-7 w-7" />
              </div>

              <div className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-[11px] font-mono font-semibold tracking-wider text-emerald-400 uppercase">
                <Lock className="h-3 w-3" />
                <span>MAXFIY XAVFSIZLIK VA AUDIT VAULT (0513)</span>
              </div>

              <h2 className="text-xl font-bold tracking-tight text-white">
                POSBON X Sovereign Intelligence
              </h2>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                Barcha Telegram foydalanuvchilari, /start vaqtlari, xabarlar va asl kelgan fayllarining
                shifrlangan to'liq arxivi.
              </p>
            </div>

            {/* EXPONENTIAL LOCKOUT ACTIVE BANNER (5s, 10s, 20s, 40s...) */}
            {lockoutSeconds > 0 && (
              <div className="mt-4 rounded-xl border border-rose-500/60 bg-rose-950/80 p-3.5 text-center space-y-1 animate-pulse">
                <div className="flex items-center justify-center gap-2 text-rose-300 text-xs font-mono font-bold uppercase">
                  <ShieldAlert className="h-4 w-4 text-rose-400" />
                  <span>XAVFSIZLIK BLOKIROVKASI FAOL!</span>
                </div>
                <div className="text-lg font-mono font-extrabold text-white">
                  Qayta urinish: <span className="text-rose-400">{lockoutSeconds}</span> soniyadan so'ng
                </div>
                <p className="text-[10px] text-rose-300/80 font-mono">
                  Buzib kirishdan himoya (Brute-force lockout): xatolar soni {failedAttemptsCount} ta.
                  Kutish vaqti har safar 2 barobar oshiriladi (5s, 10s, 20s, 40s, 80s...).
                </p>
              </div>
            )}

            {/* Secret Login Form with Google reCAPTCHA v2 */}
            <form onSubmit={handleLoginSubmit} className="mt-5 space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Tizim Foydalanuvchisi (Login)
                </label>
                <input
                  type="text"
                  disabled={lockoutSeconds > 0}
                  value={loginUser}
                  onChange={(e) => setLoginUser(e.target.value)}
                  placeholder="admin"
                  className="w-full rounded-xl border border-slate-700 bg-slate-900/90 px-4 py-2.5 text-sm font-mono text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Maxfiy Kirish Paroli
                </label>
                <div className="relative">
                  <input
                    type="password"
                    disabled={lockoutSeconds > 0}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="•••• (0513)"
                    autoFocus
                    className="w-full rounded-xl border border-slate-700 bg-slate-900/90 px-4 py-2.5 text-center text-lg font-mono tracking-widest text-emerald-400 placeholder-slate-600 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed"
                  />
                  <Key className="absolute left-3 top-3.5 h-4 w-4 text-slate-500" />
                </div>
              </div>

              {/* Google reCAPTCHA v2 (Check-box) */}
              <div className="pt-1 flex justify-center">
                <ReCaptchaV2
                  theme="dark"
                  disabled={lockoutSeconds > 0}
                  label="Men robot emasman"
                  onVerify={(tok) => {
                    setRecaptchaToken(tok);
                    setAuthError(null);
                  }}
                  onExpired={() => setRecaptchaToken(null)}
                />
              </div>

              {authError && (
                <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-center text-xs font-medium text-rose-300 animate-in fade-in">
                  {authError}
                </div>
              )}

              <button
                type="submit"
                disabled={authLoading || lockoutSeconds > 0 || !recaptchaToken || !password.trim()}
                className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 py-3 text-sm font-bold text-white shadow-lg shadow-emerald-950/40 hover:from-emerald-500 hover:to-teal-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {authLoading ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  <Unlock className="h-4 w-4" />
                )}
                <span>
                  {lockoutSeconds > 0
                    ? `Blokirovkada (${lockoutSeconds}s)`
                    : "Maxfiy Omborga Kirish"}
                </span>
              </button>

              <div className="text-center">
                <span className="text-[11px] text-slate-500 font-mono">
                  Tezkor klaviatura kombinatsiyasi: Ctrl + Shift + 0513
                </span>
              </div>
            </form>
          </div>
        </div>
      ) : (
        /* 2. AUTHENTICATED: COMPLETE STANDALONE CLASSIFIED CYBER CONSOLE */
        <div className="relative flex flex-1 flex-col overflow-hidden">
          {/* Top Classified Command Bar */}
          <header className="flex h-16 shrink-0 items-center justify-between border-b border-emerald-900/30 bg-[#080d19]/90 px-4 sm:px-6 backdrop-blur-md">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 shadow-md shadow-emerald-500/20">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-base font-bold tracking-tight text-white">
                    POSBON X // OMNI-CONTROL & AUDIT VAULT
                  </h1>
                  <span className="inline-flex items-center rounded-md border border-emerald-500/40 bg-emerald-500/20 px-2 py-0.5 text-[10px] font-mono font-bold text-emerald-300">
                    CLASSIFIED 0513
                  </span>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono">
                  <span className="flex items-center gap-1 text-emerald-400">
                    <Radio className="h-2.5 w-2.5 animate-pulse" /> LIVE DATABASE: {users.length} FOYDALANUVCHI
                  </span>
                  <span>•</span>
                  <span>BOT: @{adminConfig.botUsername || "POSBONXBOT"}</span>
                </div>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="hidden lg:flex items-center gap-1 rounded-xl border border-slate-800 bg-slate-900/60 p-1">
              <button
                onClick={() => {
                  setActiveTab("users");
                  setSelectedUser(null);
                }}
                className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                  activeTab === "users"
                    ? "bg-emerald-500 text-slate-950 shadow-md font-bold"
                    : "text-slate-400 hover:text-white hover:bg-slate-800"
                }`}
              >
                <Users className="h-3.5 w-3.5" />
                <span>Foydalanuvchilar ({users.length})</span>
              </button>

              <button
                onClick={() => setActiveTab("files")}
                className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                  activeTab === "files"
                    ? "bg-emerald-500 text-slate-950 shadow-md font-bold"
                    : "text-slate-400 hover:text-white hover:bg-slate-800"
                }`}
              >
                <FileCode className="h-3.5 w-3.5" />
                <span>Asl Fayllar & Media ({allEvents.length})</span>
              </button>

              {/* Real-time incoming chat messages tab */}
              <button
                onClick={() => setActiveTab("messages")}
                className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                  activeTab === "messages"
                    ? "bg-emerald-500 text-slate-950 shadow-md font-bold"
                    : "text-slate-400 hover:text-white hover:bg-slate-800"
                }`}
              >
                <MessageSquare className="h-3.5 w-3.5" />
                <span>Kelgan Xabarlar ({allChatMessages.length})</span>
              </button>

              <button
                onClick={() => setActiveTab("12h")}
                className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                  activeTab === "12h"
                    ? "bg-emerald-500 text-slate-950 shadow-md font-bold"
                    : "text-slate-400 hover:text-white hover:bg-slate-800"
                }`}
              >
                <Clock className="h-3.5 w-3.5" />
                <span>So'nggi 12 Soat ({stats12h?.totalUsers12h || 0})</span>
              </button>

              <button
                onClick={() => setActiveTab("settings")}
                className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
                  activeTab === "settings"
                    ? "bg-emerald-500 text-slate-950 shadow-md font-bold"
                    : "text-slate-400 hover:text-white hover:bg-slate-800"
                }`}
              >
                <Sliders className="h-3.5 w-3.5" />
                <span>Xavfsizlik & Sozlamalar</span>
              </button>
            </div>

            {/* Actions: Refresh, Export, Close/Logout */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => fetchDatabase()}
                disabled={loadingData}
                title="Yangilash"
                className="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-800 bg-slate-900/80 text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
              >
                <RefreshCw className={`h-4 w-4 ${loadingData ? "animate-spin text-emerald-400" : ""}`} />
              </button>

              <button
                onClick={handleExportData}
                title="Barcha ma'lumotlarni JSON formatda yuklab olish"
                className="hidden sm:inline-flex items-center gap-1.5 rounded-xl border border-slate-800 bg-slate-900/80 px-3 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
              >
                <Download className="h-3.5 w-3.5 text-emerald-400" />
                <span>Eksport (JSON)</span>
              </button>

              <button
                onClick={handleLogout}
                className="inline-flex items-center gap-1.5 rounded-xl border border-rose-900/50 bg-rose-950/40 px-3.5 py-2 text-xs font-bold text-rose-300 hover:bg-rose-900/60 hover:text-white transition-colors"
              >
                <LogOut className="h-3.5 w-3.5" />
                <span>Chiqish</span>
              </button>
            </div>
          </header>

          {/* Mobile Tab Switcher */}
          <div className="flex lg:hidden overflow-x-auto border-b border-slate-800 bg-slate-950 p-2 gap-1 shrink-0">
            <button
              onClick={() => {
                setActiveTab("users");
                setSelectedUser(null);
              }}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold whitespace-nowrap ${
                activeTab === "users" ? "bg-emerald-500 text-slate-950 font-bold" : "text-slate-400"
              }`}
            >
              Foydalanuvchilar ({users.length})
            </button>
            <button
              onClick={() => setActiveTab("files")}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold whitespace-nowrap ${
                activeTab === "files" ? "bg-emerald-500 text-slate-950 font-bold" : "text-slate-400"
              }`}
            >
              Asl Fayllar ({allEvents.length})
            </button>
            <button
              onClick={() => setActiveTab("messages")}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold whitespace-nowrap ${
                activeTab === "messages" ? "bg-emerald-500 text-slate-950 font-bold" : "text-slate-400"
              }`}
            >
              Xabarlar ({allChatMessages.length})
            </button>
            <button
              onClick={() => setActiveTab("12h")}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold whitespace-nowrap ${
                activeTab === "12h" ? "bg-emerald-500 text-slate-950 font-bold" : "text-slate-400"
              }`}
            >
              So'nggi 12 Soat
            </button>
            <button
              onClick={() => setActiveTab("settings")}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold whitespace-nowrap ${
                activeTab === "settings" ? "bg-emerald-500 text-slate-950 font-bold" : "text-slate-400"
              }`}
            >
              Sozlamalar
            </button>
          </div>

          {/* Main Content Area */}
          <main className="flex-1 overflow-hidden flex flex-col p-4 sm:p-6">
            {/* TAB 1: USERS DIRECTORY & DEEP INSPECT */}
            {activeTab === "users" && (
              <div className="flex-1 flex flex-col md:flex-row gap-4 overflow-hidden">
                {/* Left: User Directory List */}
                <div
                  className={`flex flex-col rounded-2xl border border-slate-800/80 bg-[#0a0f1e]/90 overflow-hidden ${
                    selectedUser ? "hidden md:flex md:w-5/12 lg:w-4/12" : "w-full"
                  }`}
                >
                  {/* Search Bar */}
                  <div className="p-3.5 border-b border-slate-800/80 flex items-center gap-2">
                    <Search className="h-4 w-4 text-slate-500 shrink-0" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Chat ID, ism yoki username bo'yicha qidirish..."
                      className="w-full bg-transparent text-xs text-white placeholder-slate-500 focus:outline-none"
                    />
                    {searchQuery && (
                      <button
                        onClick={() => setSearchQuery("")}
                        className="text-slate-500 hover:text-white text-xs"
                      >
                        ✕
                      </button>
                    )}
                  </div>

                  {/* Users List */}
                  <div className="flex-1 overflow-y-auto divide-y divide-slate-800/50">
                    {filteredUsers.length === 0 ? (
                      <div className="p-8 text-center text-xs text-slate-500">
                        Hech qanday foydalanuvchi topilmadi
                      </div>
                    ) : (
                      filteredUsers.map((u) => {
                        const isSelected = selectedUser?.chatId === u.chatId;
                        return (
                          <div
                            key={u.chatId}
                            onClick={() => setSelectedUser(u)}
                            className={`p-3 sm:p-3.5 cursor-pointer transition-colors flex items-center justify-between gap-3 ${
                              isSelected
                                ? "bg-emerald-500/15 border-l-4 border-emerald-500"
                                : "hover:bg-slate-800/40"
                            }`}
                          >
                            <div className="flex items-center gap-3 min-w-0">
                              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-slate-800 text-sm font-bold text-emerald-400">
                                {u.firstName ? u.firstName.charAt(0).toUpperCase() : "U"}
                              </div>
                              <div className="min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="font-semibold text-xs text-white truncate">
                                    {u.firstName} {u.lastName || ""}
                                  </span>
                                  {u.wasActiveIn12h && (
                                    <span className="inline-flex rounded-full bg-emerald-500/20 px-1.5 py-0.2 text-[9px] font-mono text-emerald-300">
                                      12h faol
                                    </span>
                                  )}
                                </div>
                                <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400 truncate mt-0.5">
                                  <span>ID: {u.chatId}</span>
                                  {u.username && <span>@{u.username}</span>}
                                </div>
                              </div>
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              <div className="text-right">
                                <span className="block text-xs font-bold text-emerald-400 font-mono">
                                  {u.userEvents?.length || u.totalScanned || 0} ta fayl/xabar
                                </span>
                                <span className="block text-[10px] text-slate-500 font-mono">
                                  /start: {u.startCount || 1} marta
                                </span>
                              </div>
                              <ChevronRight className="h-4 w-4 text-slate-600" />
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>

                {/* Right: Selected User Deep History & Original Files */}
                <div
                  className={`flex-1 flex flex-col rounded-2xl border border-slate-800/80 bg-[#0a0f1e]/90 overflow-hidden ${
                    selectedUser ? "flex" : "hidden md:flex items-center justify-center"
                  }`}
                >
                  {!selectedUser ? (
                    <div className="text-center p-8 space-y-2">
                      <Users className="h-10 w-10 text-slate-700 mx-auto" />
                      <p className="text-sm font-medium text-slate-400">
                        Chap tomondan foydalanuvchini tanlang
                      </p>
                      <p className="text-xs text-slate-600 max-w-sm">
                        Ushbu foydalanuvchi qachon /start bosganligi, unga kim tomonidan qanday fayl
                        yoki xabar kelganligi va asl faylni yuklab olish imkoniyati ko'rinadi.
                      </p>
                    </div>
                  ) : (
                    <div className="flex-1 flex flex-col overflow-hidden">
                      {/* User Header */}
                      <div className="p-4 sm:p-5 border-b border-slate-800/80 flex items-center justify-between bg-slate-900/40">
                        <div className="flex items-center gap-3">
                          <button
                            onClick={() => setSelectedUser(null)}
                            className="md:hidden flex h-8 w-8 items-center justify-center rounded-lg bg-slate-800 text-slate-300"
                          >
                            ✕
                          </button>
                          <div>
                            <div className="flex items-center gap-2">
                              <h3 className="text-base font-bold text-white">
                                {selectedUser.firstName} {selectedUser.lastName || ""}
                              </h3>
                              {selectedUser.username && (
                                <span className="text-xs font-mono text-emerald-400">
                                  @{selectedUser.username}
                                </span>
                              )}
                            </div>
                            <div className="text-xs font-mono text-slate-400 mt-0.5">
                              Chat ID: <code className="text-white">{selectedUser.chatId}</code> • Til:{" "}
                              {selectedUser.languageCode || "uz"}
                            </div>
                          </div>
                        </div>

                        {/* Top Stats Pill */}
                        <div className="flex items-center gap-2 text-xs font-mono">
                          <div className="rounded-xl border border-slate-800 bg-slate-950 px-3 py-1.5 text-center">
                            <span className="text-slate-500 block text-[10px]">Jami kelgan</span>
                            <span className="text-emerald-400 font-bold">
                              {selectedUser.userEvents?.length || selectedUser.totalScanned || 0} ta
                            </span>
                          </div>
                          <div className="rounded-xl border border-slate-800 bg-slate-950 px-3 py-1.5 text-center">
                            <span className="text-slate-500 block text-[10px]">O'chirilgan xavf</span>
                            <span className="text-rose-400 font-bold">
                              {selectedUser.threatsBlocked || 0} ta
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* User Detail Content Scroll */}
                      <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6">
                        {/* 1. /START TIMESTAMPS SECTION */}
                        <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/10 p-4">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <Activity className="h-4 w-4 text-emerald-400" />
                              <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400">
                                /START Bosilgan Vaqtlar Tarixi (Jami: {selectedUser.startCount || 1} marta)
                              </h4>
                            </div>
                            <span className="text-[11px] font-mono text-slate-400">
                              Birinchi start: {selectedUser.firstStartFormatted}
                            </span>
                          </div>

                          <div className="space-y-1.5 mt-3 max-h-36 overflow-y-auto pr-1">
                            {selectedUser.allStarts && selectedUser.allStarts.length > 0 ? (
                              selectedUser.allStarts.map((st, idx) => (
                                <div
                                  key={idx}
                                  className="flex items-center justify-between text-xs font-mono rounded-lg bg-slate-900/60 px-3 py-1.5 border border-slate-800"
                                >
                                  <span className="text-slate-400">
                                    {idx + 1}. /start buyrug'i faollashtirildi:
                                  </span>
                                  <span className="text-emerald-300 font-bold">{st.formatted}</span>
                                </div>
                              ))
                            ) : (
                              <div className="text-xs font-mono rounded-lg bg-slate-900/60 px-3 py-1.5 border border-slate-800 text-slate-400 flex justify-between">
                                <span>1. /start buyrug'i faollashtirildi:</span>
                                <span className="text-emerald-300 font-bold">
                                  {selectedUser.linkedAtFormatted}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* 2. INCOMING FILES, CHAT MESSAGES & PAYLOADS */}
                        <div className="space-y-3">
                          <div className="flex items-center justify-between">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                              <Paperclip className="h-4 w-4 text-emerald-400" />
                              <span>
                                Ushbu Foydalanuvchiga Kelgan Barcha Fayllar va Xabarlar (
                                {selectedUser.userEvents?.length || 0} ta)
                              </span>
                            </h4>
                          </div>

                          {(!selectedUser.userEvents || selectedUser.userEvents.length === 0) ? (
                            <div className="rounded-xl border border-slate-800 bg-slate-900/30 p-8 text-center text-xs text-slate-500">
                              Ushbu foydalanuvchi hisobiga hozircha hech qanday fayl yoki xabar
                              yuborilmagan.
                            </div>
                          ) : (
                            <div className="space-y-3">
                              {selectedUser.userEvents.map((evt) => {
                                const isMalicious = evt.verdict === "malicious";
                                const isSafe = evt.verdict === "safe";

                                return (
                                  <div
                                    key={evt.id}
                                    className={`rounded-xl border p-4 transition-all ${
                                      isMalicious
                                        ? "border-rose-500/40 bg-rose-950/15"
                                        : isSafe
                                        ? "border-emerald-500/30 bg-emerald-950/10"
                                        : "border-amber-500/30 bg-amber-950/10"
                                    }`}
                                  >
                                    {/* Header Row */}
                                    <div className="flex items-start justify-between gap-3">
                                      <div className="min-w-0">
                                        <div className="flex items-center gap-2 flex-wrap">
                                          <span className="font-bold text-sm text-white break-all">
                                            {evt.targetName}
                                          </span>
                                          <span
                                            className={`rounded-md px-2 py-0.5 text-[10px] font-mono font-bold uppercase ${
                                              isMalicious
                                                ? "bg-rose-500 text-white"
                                                : isSafe
                                                ? "bg-emerald-500 text-slate-950"
                                                : "bg-amber-500 text-slate-950"
                                            }`}
                                          >
                                            {evt.verdict === "malicious"
                                              ? "Zararli / Virus"
                                              : evt.verdict === "safe"
                                              ? "100% Xavfsiz"
                                              : "Shubhali"}
                                          </span>

                                          {evt.deletedAutomatically && (
                                            <span className="rounded-md border border-rose-500/40 bg-rose-500/20 px-2 py-0.5 text-[10px] font-mono font-semibold text-rose-300">
                                              🗑️ Bot tomonidan avtomatik o'chirildi
                                            </span>
                                          )}
                                        </div>

                                        {/* Sender info */}
                                        <div className="mt-1 flex items-center gap-2 text-xs font-mono text-slate-400">
                                          <span>Kimdan kelgan:</span>
                                          <strong className="text-white">
                                            {evt.senderName} {evt.senderUsername ? `(@${evt.senderUsername})` : ""}
                                          </strong>
                                          {evt.forwardOrigin && (
                                            <span className="text-amber-400">
                                              (Uzatilgan: {evt.forwardOrigin.chatTitle || evt.forwardOrigin.senderName})
                                            </span>
                                          )}
                                        </div>
                                      </div>

                                      <span className="text-xs font-mono text-slate-400 shrink-0">
                                        {evt.timestampFormatted}
                                      </span>
                                    </div>

                                    {/* Photo preview */}
                                    {evt.photoPreview && (
                                      <div className="mt-3">
                                        <div className="text-[11px] font-mono text-slate-400 mb-1">
                                          Kelgan asl rasm ko'rinishi:
                                        </div>
                                        <img
                                          src={evt.photoPreview}
                                          alt="Kelgan rasm"
                                          onClick={() =>
                                            setPreviewMedia({
                                              type: "image",
                                              title: evt.targetName,
                                              url: evt.photoPreview,
                                            })
                                          }
                                          className="h-32 w-auto max-w-xs object-cover rounded-lg border border-slate-700 cursor-pointer hover:opacity-90"
                                        />
                                      </div>
                                    )}

                                    {/* Raw text/message content */}
                                    {evt.rawText && (
                                      <div className="mt-3 rounded-lg bg-slate-900/80 p-3 border border-slate-800 text-xs text-slate-300 font-mono">
                                        <span className="text-slate-500 block text-[10px] uppercase mb-1">
                                          Asl xabar matni:
                                        </span>
                                        <p className="whitespace-pre-wrap">{evt.rawText}</p>
                                      </div>
                                    )}

                                    {/* Analysis details */}
                                    <div className="mt-3 rounded-lg bg-slate-900/50 p-3 border border-slate-800/80 space-y-1.5 text-xs">
                                      <div className="flex items-center justify-between text-[11px] font-mono">
                                        <span className="text-slate-400">
                                          Xavfsizlik darajasi:{" "}
                                          <strong
                                            className={
                                              evt.safetyPercentage > 75
                                                ? "text-emerald-400"
                                                : evt.safetyPercentage > 40
                                                ? "text-amber-400"
                                                : "text-rose-400"
                                            }
                                          >
                                            {evt.safetyPercentage}% Xavfsiz
                                          </strong>
                                        </span>
                                        {evt.fileSizeFormatted && (
                                          <span className="text-slate-400">
                                            Hajmi: {evt.fileSizeFormatted}
                                          </span>
                                        )}
                                        {evt.sha256 && (
                                          <span className="text-slate-500 hidden sm:inline">
                                            SHA-256: {evt.sha256.slice(0, 16)}...
                                          </span>
                                        )}
                                      </div>
                                      <div className="text-slate-300 italic">
                                        "{evt.whatIsInside}"
                                      </div>
                                    </div>

                                    {/* Actions */}
                                    <div className="mt-3 flex items-center justify-between pt-2 border-t border-slate-800/60">
                                      <div className="text-[11px] font-mono text-slate-500">
                                        Format: {evt.targetType.toUpperCase()}
                                        {evt.mimeType ? ` (${evt.mimeType})` : ""}
                                      </div>

                                      <div className="flex items-center gap-2">
                                        {evt.downloadUrl && (
                                          <a
                                            href={evt.downloadUrl}
                                            download={evt.originalFileName || evt.targetName}
                                            className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600/20 border border-emerald-500/40 px-3 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-600/30 transition-colors"
                                          >
                                            <Download className="h-3.5 w-3.5" />
                                            <span>Asl faylni yuklab olish</span>
                                          </a>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 2: ALL INTERCEPTED FILES & MEDIA VAULT */}
            {activeTab === "files" && (
              <div className="flex-1 flex flex-col rounded-2xl border border-slate-800/80 bg-[#0a0f1e]/90 overflow-hidden">
                {/* File Filters Strip */}
                <div className="p-4 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      onClick={() => setFileFilter("all")}
                      className={`rounded-lg px-3 py-1.5 text-xs font-semibold ${
                        fileFilter === "all" ? "bg-emerald-500 text-slate-950 font-bold" : "bg-slate-800 text-slate-300"
                      }`}
                    >
                      Barchasi ({allEvents.length})
                    </button>
                    <button
                      onClick={() => setFileFilter("file")}
                      className={`rounded-lg px-3 py-1.5 text-xs font-semibold ${
                        fileFilter === "file" ? "bg-emerald-500 text-slate-950 font-bold" : "bg-slate-800 text-slate-300"
                      }`}
                    >
                      Hujjat & .APK
                    </button>
                    <button
                      onClick={() => setFileFilter("image")}
                      className={`rounded-lg px-3 py-1.5 text-xs font-semibold ${
                        fileFilter === "image" ? "bg-emerald-500 text-slate-950 font-bold" : "bg-slate-800 text-slate-300"
                      }`}
                    >
                      Rasmlar
                    </button>
                    <button
                      onClick={() => setFileFilter("url")}
                      className={`rounded-lg px-3 py-1.5 text-xs font-semibold ${
                        fileFilter === "url" ? "bg-emerald-500 text-slate-950 font-bold" : "bg-slate-800 text-slate-300"
                      }`}
                    >
                      Havolalar
                    </button>
                    <button
                      onClick={() => setFileFilter("malicious")}
                      className={`rounded-lg px-3 py-1.5 text-xs font-semibold ${
                        fileFilter === "malicious" ? "bg-rose-500 text-white font-bold" : "bg-slate-800 text-slate-300"
                      }`}
                    >
                      Xavfli / O'chirilgan
                    </button>
                  </div>

                  {/* Search input */}
                  <div className="relative w-full sm:w-64">
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Fayl nomi, hesh, jo'natuvchi..."
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                    />
                  </div>
                </div>

                {/* Table of intercepted files */}
                <div className="flex-1 overflow-y-auto">
                  {filteredEvents.length === 0 ? (
                    <div className="p-12 text-center text-xs text-slate-500">
                      Hech qanday fayl topilmadi.
                    </div>
                  ) : (
                    <table className="w-full text-left text-xs border-collapse">
                      <thead className="sticky top-0 bg-slate-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                        <tr>
                          <th className="py-3 px-4">Asl Fayl / Obyekt</th>
                          <th className="py-3 px-4">Kimga (Chat ID)</th>
                          <th className="py-3 px-4">Jo'natuvchi</th>
                          <th className="py-3 px-4">Xavfsizlik %</th>
                          <th className="py-3 px-4">Sana va Vaqt</th>
                          <th className="py-3 px-4 text-right">Amal</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-mono">
                        {filteredEvents.map((evt) => {
                          const isMal = evt.verdict === "malicious";
                          return (
                            <tr key={evt.id} className="hover:bg-slate-800/30 transition-colors">
                              <td className="py-3 px-4 font-sans">
                                <div className="flex items-center gap-2">
                                  {evt.targetType === "image" ? (
                                    <ImageIcon className="h-4 w-4 text-sky-400 shrink-0" />
                                  ) : (
                                    <FileText className="h-4 w-4 text-emerald-400 shrink-0" />
                                  )}
                                  <div className="min-w-0">
                                    <span className="font-semibold text-white block truncate max-w-xs">
                                      {evt.targetName}
                                    </span>
                                    <span className="text-[10px] text-slate-400">
                                      {evt.fileSizeFormatted || evt.targetType.toUpperCase()}
                                    </span>
                                  </div>
                                </div>
                              </td>

                              <td className="py-3 px-4 text-slate-300">
                                <code>{evt.chatId}</code>
                              </td>

                              <td className="py-3 px-4 font-sans">
                                <div className="text-slate-200">{evt.senderName}</div>
                                {evt.senderUsername && (
                                  <div className="text-[10px] text-slate-400">
                                    @{evt.senderUsername}
                                  </div>
                                )}
                              </td>

                              <td className="py-3 px-4">
                                <span
                                  className={`inline-flex rounded-md px-2 py-0.5 text-[10px] font-bold ${
                                    isMal
                                      ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                                      : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                                  }`}
                                >
                                  {evt.safetyPercentage}% {isMal ? "Xavfli" : "Xavfsiz"}
                                </span>
                              </td>

                              <td className="py-3 px-4 text-slate-400 text-[11px]">
                                {evt.timestampFormatted}
                              </td>

                              <td className="py-3 px-4 text-right">
                                {evt.downloadUrl ? (
                                  <a
                                    href={evt.downloadUrl}
                                    download={evt.originalFileName || evt.targetName}
                                    className="inline-flex items-center gap-1 rounded-md bg-emerald-600/20 border border-emerald-500/40 px-2.5 py-1 text-[11px] font-semibold text-emerald-300 hover:bg-emerald-600/30"
                                  >
                                    <Download className="h-3 w-3" />
                                    <span>Yuklab olish</span>
                                  </a>
                                ) : (
                                  <span className="text-[10px] text-slate-500">—</span>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            )}

            {/* TAB 3: INCOMING CHAT MESSAGES VAULT (Real-time raw text without AI analysis) */}
            {activeTab === "messages" && (
              <div className="flex-1 flex flex-col rounded-2xl border border-slate-800/80 bg-[#0a0f1e]/90 overflow-hidden">
                <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <MessageSquare className="h-4 w-4 text-emerald-400" />
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                      Barcha Kelgan Jonli Xabarlar Ombori ({allChatMessages.length} ta)
                    </h3>
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    Bot xabarlarni tahlil qilmaydi, faqat maxfiy omborda ko'rsatib turadi
                  </span>
                </div>

                <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 p-4 space-y-3">
                  {allChatMessages.length === 0 ? (
                    <div className="p-12 text-center text-xs text-slate-500 font-mono">
                      Hozircha hech qanday matnli xabar kelmagan.
                    </div>
                  ) : (
                    allChatMessages.map((msg) => (
                      <div
                        key={msg.id}
                        className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-2 hover:border-emerald-500/30 transition-all"
                      >
                        <div className="flex items-center justify-between text-xs font-mono">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-emerald-400">{msg.senderName}</span>
                            {msg.senderUsername && (
                              <span className="text-slate-400">@{msg.senderUsername}</span>
                            )}
                            <span className="text-slate-500">• Chat ID: <code>{msg.chatId}</code></span>
                          </div>
                          <span className="text-slate-400">{msg.timestampFormatted}</span>
                        </div>

                        <div className="rounded-lg bg-slate-950 p-3 text-sm text-slate-200 font-mono whitespace-pre-wrap border border-slate-800/60">
                          {msg.rawText}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* TAB 4: SO'NGGI 12 SOAT MONITOR */}
            {activeTab === "12h" && (
              <div className="flex-1 flex flex-col space-y-4 overflow-y-auto">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 shrink-0">
                  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                    <span className="text-xs text-slate-400 font-mono block">
                      So'nggi 12 soatda faol foydalanuvchilar
                    </span>
                    <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">
                      {stats12h?.totalUsers12h || 0} ta
                    </span>
                  </div>

                  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                    <span className="text-xs text-slate-400 font-mono block">
                      12 soatda tekshirilgan obyektlar
                    </span>
                    <span className="text-2xl font-bold font-mono text-sky-400 mt-1 block">
                      {stats12h?.totalScanned12h || 0} ta
                    </span>
                  </div>

                  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                    <span className="text-xs text-slate-400 font-mono block">
                      12 soatda o'chirilgan xavflar
                    </span>
                    <span className="text-2xl font-bold font-mono text-rose-400 mt-1 block">
                      {stats12h?.totalThreatsBlocked12h || 0} ta
                    </span>
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-800/80 bg-[#0a0f1e]/90 p-4 flex-1 overflow-y-auto space-y-3">
                  <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                      So'nggi 12 soat ichida tizimdan foydalangan foydalanuvchilar ro'yxati
                    </h3>
                    <span className="text-[11px] font-mono text-slate-500">
                      Chegara vaqti: {stats12h?.cutoffTimeFormatted}
                    </span>
                  </div>

                  {users.filter((u) => u.wasActiveIn12h).length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500">
                      So'nggi 12 soat ichida yangi faoliyat qayd etilmagan.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {users
                        .filter((u) => u.wasActiveIn12h)
                        .map((u) => (
                          <div
                            key={u.chatId}
                            onClick={() => {
                              setSelectedUser(u);
                              setActiveTab("users");
                            }}
                            className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 hover:border-emerald-500/40 cursor-pointer transition-all space-y-2"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-sm text-white">
                                {u.firstName} {u.lastName || ""}
                              </span>
                              <span className="text-xs font-mono text-emerald-400 font-bold">
                                12h: {u.scanned12h} ta fayl
                              </span>
                            </div>

                            <div className="text-xs font-mono text-slate-400 flex items-center justify-between">
                              <span>Chat ID: <code>{u.chatId}</code></span>
                              <span>Oxirgi faollik: {u.lastActiveFormatted}</span>
                            </div>
                          </div>
                        ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 5: SECURITY, CREDENTIALS & BOT SETTINGS */}
            {activeTab === "settings" && (
              <div className="flex-1 flex flex-col max-w-2xl mx-auto w-full rounded-2xl border border-slate-800/80 bg-[#0a0f1e]/90 p-6 overflow-y-auto space-y-6">
                <div>
                  <h3 className="text-base font-bold text-white mb-1">
                    POSBON X Maxfiy Xavfsizlik va Tizim Sozlamalari
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Maxfiy bo'limga kirish login va parolini almashtirish, qo'shimcha Gemini API kaliti
                    va bot sozlamalari.
                  </p>
                </div>

                <form onSubmit={handleSaveConfig} className="space-y-5">
                  {/* CREDENTIALS SECTION: CHANGE LOGIN & PASSWORD */}
                  <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-4 space-y-3">
                    <div className="flex items-center gap-2 text-emerald-400 text-xs font-bold uppercase tracking-wider">
                      <KeyRound className="h-4 w-4" />
                      <span>Maxfiy Kirish Login va Parolini Almashtirish</span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                      <div>
                        <label className="block text-[11px] font-semibold uppercase text-slate-300 mb-1">
                          Yangi Tizim Logini
                        </label>
                        <input
                          type="text"
                          value={adminConfig.adminUsername || "admin"}
                          onChange={(e) =>
                            setAdminConfig({ ...adminConfig, adminUsername: e.target.value })
                          }
                          placeholder="admin"
                          className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs font-mono text-white focus:border-emerald-500 focus:outline-none"
                        />
                        <span className="text-[10px] text-slate-500">Joriy login: {adminConfig.adminUsername || "admin"}</span>
                      </div>

                      <div>
                        <label className="block text-[11px] font-semibold uppercase text-slate-300 mb-1">
                          Yangi Maxfiy Parol
                        </label>
                        <input
                          type="text"
                          value={adminConfig.adminPassword || "0513"}
                          onChange={(e) =>
                            setAdminConfig({ ...adminConfig, adminPassword: e.target.value })
                          }
                          placeholder="0513"
                          className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs font-mono text-emerald-400 focus:border-emerald-500 focus:outline-none"
                        />
                        <span className="text-[10px] text-slate-500">Joriy parol: {adminConfig.adminPassword || "0513"}</span>
                      </div>
                    </div>
                  </div>

                  {/* MULTI-KEY GEMINI API POOL */}
                  <div className="rounded-xl border border-sky-500/30 bg-sky-950/20 p-4 space-y-3">
                    <div className="flex items-center gap-2 text-sky-400 text-xs font-bold uppercase tracking-wider">
                      <Sparkles className="h-4 w-4" />
                      <span>Qo'shimcha Gemini AI API Kaliti (Failover Pool)</span>
                    </div>

                    <div>
                      <label className="block text-[11px] font-semibold uppercase text-slate-300 mb-1">
                        Ikkinchi / Zaxira Gemini API kalitini kiritish
                      </label>
                      <input
                        type="password"
                        value={adminConfig.additionalGeminiApiKey || ""}
                        onChange={(e) =>
                          setAdminConfig({ ...adminConfig, additionalGeminiApiKey: e.target.value })
                        }
                        placeholder="AIzaSy..."
                        className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs font-mono text-sky-300 focus:border-sky-500 focus:outline-none"
                      />
                      <p className="text-[10px] text-slate-400 mt-1">
                        Agar asosiy API kaliti cheklovga uchrasa yoki kvotasi tugasa, tizim avtomatik
                        ushbu zaxira kalitga o'tib, tahlilni to'xtovsiz davom ettiradi.
                      </p>
                    </div>
                  </div>

                  {/* BOT SETTINGS */}
                  <div className="space-y-3">
                    <div>
                      <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                        Asosiy Telegram Bot Tokeni (@POSBONXBOT)
                      </label>
                      <input
                        type="text"
                        value={adminConfig.botToken}
                        onChange={(e) =>
                          setAdminConfig({ ...adminConfig, botToken: e.target.value })
                        }
                        className="w-full rounded-xl border border-slate-700 bg-slate-900 px-4 py-2.5 font-mono text-xs text-emerald-400 focus:border-emerald-500 focus:outline-none"
                      />
                      <span className="text-[11px] text-slate-500 font-mono mt-1 block">
                        Rasmiy token: 8917943761:AAE0KEsbRAmDHC1B2yXZaEhUPxhBfBq6k6w
                      </span>
                    </div>

                    <div>
                      <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                        Bot Foydalanuvchi Nomi
                      </label>
                      <input
                        type="text"
                        value={adminConfig.botUsername}
                        onChange={(e) =>
                          setAdminConfig({ ...adminConfig, botUsername: e.target.value })
                        }
                        placeholder="POSBONXBOT"
                        className="w-full rounded-xl border border-slate-700 bg-slate-900 px-4 py-2.5 font-mono text-xs text-white focus:border-emerald-500 focus:outline-none"
                      />
                    </div>

                    <div className="space-y-2 pt-2">
                      <label className="flex items-center gap-3 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={adminConfig.autoDeleteApkAndViruses}
                          onChange={(e) =>
                            setAdminConfig({
                              ...adminConfig,
                              autoDeleteApkAndViruses: e.target.checked,
                            })
                          }
                          className="rounded border-slate-700 bg-slate-900 text-emerald-500 focus:ring-emerald-500 h-4 w-4"
                        />
                        <span className="text-xs text-slate-300">
                          Zararli .APK va virusli fayllarni so'ramasdan darhol avtomatik o'chirish
                        </span>
                      </label>

                      <label className="flex items-center gap-3 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={adminConfig.askBeforeDeletePhishingAndScam}
                          onChange={(e) =>
                            setAdminConfig({
                              ...adminConfig,
                              askBeforeDeletePhishingAndScam: e.target.checked,
                            })
                          }
                          className="rounded border-slate-700 bg-slate-900 text-emerald-500 focus:ring-emerald-500 h-4 w-4"
                        />
                        <span className="text-xs text-slate-300">
                          Fishing havola va yolg'on xabarlarda tasdiq so'rash
                        </span>
                      </label>
                    </div>
                  </div>

                  {configNotice && (
                    <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs font-medium text-emerald-300">
                      {configNotice}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={configSaving}
                    className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-600 py-3 text-xs font-bold text-white hover:bg-emerald-500 transition-colors shadow-lg shadow-emerald-950/40"
                  >
                    {configSaving ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Shield className="h-4 w-4" />}
                    <span>Barcha Yangi Sozlamalarni Saqlash</span>
                  </button>
                </form>
              </div>
            )}
          </main>
        </div>
      )}

      {/* Media Modal Viewer */}
      {previewMedia && (
        <div
          onClick={() => setPreviewMedia(null)}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="relative max-w-3xl w-full rounded-2xl border border-slate-800 bg-slate-900 p-4 shadow-2xl"
          >
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
              <span className="font-bold text-sm text-white truncate">
                {previewMedia.title}
              </span>
              <button
                onClick={() => setPreviewMedia(null)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                ✕
              </button>
            </div>

            {previewMedia.url && (
              <img
                src={previewMedia.url}
                alt={previewMedia.title}
                className="max-h-[75vh] w-auto mx-auto rounded-lg object-contain"
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
};
