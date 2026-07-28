"use client";
export const dynamic = "force-dynamic";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import {
  checkAdmin,
  getAdminStats,
  getAdminUsers,
  getAdminScans,
  getSystemHealth,
  disableUserScanning,
  enableUserScanning,
  resetUserLimit,
} from "@/lib/adminApi";
import { getReportUrl } from "@/lib/api";

type Tab = "overview" | "users" | "scans" | "health";

export default function AdminPage() {
  const router = useRouter();
  const [userId, setUserId]     = useState<string | null>(null);
  const [loading, setLoading]   = useState(true);
  const [activeTab, setActiveTab] = useState<Tab>("overview");
  const [stats, setStats]       = useState<any>(null);
  const [users, setUsers]       = useState<any[]>([]);
  const [scans, setScans]       = useState<any[]>([]);
  const [health, setHealth]     = useState<any>(null);
  const [actionMsg, setActionMsg] = useState("");

  // Auth + admin check
  useEffect(() => {
    supabase.auth.getSession().then(async ({ data: { session } }) => {
      if (!session) { router.push("/auth"); return; }
      const uid = session.user.id;
      const result = await checkAdmin(uid);
      if (!result.is_admin) { router.push("/"); return; }
      setUserId(uid);
      setLoading(false);
    });
  }, [router]);

  // Fetch data when tab changes
  useEffect(() => {
    if (!userId) return;
    if (activeTab === "overview") {
      getAdminStats(userId).then(setStats).catch(console.error);
    } else if (activeTab === "users") {
      getAdminUsers(userId).then((d) => setUsers(d.users)).catch(console.error);
    } else if (activeTab === "scans") {
      getAdminScans(userId).then((d) => setScans(d.scans)).catch(console.error);
    } else if (activeTab === "health") {
      getSystemHealth(userId).then(setHealth).catch(console.error);
    }
  }, [activeTab, userId]);

  const handleAction = async (fn: () => Promise<any>, successMsg: string) => {
    try {
      await fn();
      setActionMsg(successMsg);
      setTimeout(() => setActionMsg(""), 3000);
      // Refresh users list
      if (userId) getAdminUsers(userId).then((d) => setUsers(d.users));
    } catch { setActionMsg("Action failed"); }
  };

  if (loading) return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center">
      <div className="text-gray-500">Verifying admin access...</div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-gray-900 text-white px-6 py-4 shadow-lg">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold">🛡 VulnAssess — Admin Panel</h1>
            <p className="text-xs text-gray-400 mt-0.5">Platform management dashboard</p>
          </div>
          <button
            onClick={() => router.push("/")}
            className="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg transition-colors"
          >
            ← Back to Dashboard
          </button>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Action message */}
        {actionMsg && (
          <div className="mb-4 p-3 bg-green-50 text-green-700 text-sm rounded-lg border border-green-200">
            {actionMsg}
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-2 mb-6">
          {(["overview", "users", "scans", "health"] as Tab[]).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === tab
                  ? "bg-indigo-600 text-white"
                  : "bg-white text-gray-600 border border-gray-200 hover:bg-gray-50"
              }`}
            >
              {tab === "overview" ? "📊 Overview" :
               tab === "users"    ? "👥 Users" :
               tab === "scans"    ? "🔍 Scans" : "⚙️ Health"}
            </button>
          ))}
        </div>

        {/* Overview Tab */}
        {activeTab === "overview" && stats && (
          <div>
            <div className="grid grid-cols-3 gap-4 mb-6">
              {[
                { label: "Total Users",     value: stats.total_users,     color: "text-indigo-600" },
                { label: "Total Scans",     value: stats.total_scans,     color: "text-gray-800" },
                { label: "Today's Scans",   value: stats.today_scans,     color: "text-blue-600" },
                { label: "Completed",       value: stats.completed_scans, color: "text-green-600" },
                { label: "Running",         value: stats.running_scans,   color: "text-yellow-600" },
                { label: "Failed",          value: stats.failed_scans,    color: "text-red-600" },
              ].map(({ label, value, color }) => (
                <div key={label} className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
                  <div className={`text-3xl font-bold ${color}`}>{value}</div>
                  <div className="text-sm text-gray-500 mt-1">{label}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Users Tab */}
        {activeTab === "users" && (
          <div className="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-sm">
            <div className="px-6 py-4 border-b border-gray-100">
              <h2 className="font-bold text-gray-800">Users ({users.length})</h2>
              <p className="text-xs text-gray-400 mt-0.5">Users who have performed at least one scan</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-gray-800 text-white text-xs uppercase">
                    <th className="px-4 py-3 text-left">Email</th>
                    <th className="px-4 py-3 text-center">Role</th>
                    <th className="px-4 py-3 text-center">Total Scans</th>
                    <th className="px-4 py-3 text-center">Scans Today</th>
                    <th className="px-4 py-3 text-center">Status</th>
                    <th className="px-4 py-3 text-center">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user, i) => (
                    <tr key={user.user_id} className={i % 2 === 0 ? "bg-white" : "bg-gray-50"}>
                      <td className="px-4 py-3 text-sm text-gray-800">{user.email}</td>
                      <td className="px-4 py-3 text-center">
                        <span className={`text-xs font-bold px-2 py-1 rounded-full ${
                          user.role === "admin"
                            ? "bg-indigo-100 text-indigo-700"
                            : "bg-gray-100 text-gray-600"
                        }`}>
                          {user.role}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center text-sm text-gray-700">{user.total_scans}</td>
                      <td className="px-4 py-3 text-center text-sm text-gray-700">{user.scans_today}</td>
                      <td className="px-4 py-3 text-center">
                        <span className={`text-xs font-bold px-2 py-1 rounded-full ${
                          user.scanning_disabled
                            ? "bg-red-100 text-red-600"
                            : "bg-green-100 text-green-700"
                        }`}>
                          {user.scanning_disabled ? "Disabled" : "Active"}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <div className="flex gap-1 justify-center flex-wrap">
                          {user.scanning_disabled ? (
                            <button
                              onClick={() => handleAction(
                                () => enableUserScanning(userId!, user.user_id),
                                `Enabled scanning for ${user.email}`
                              )}
                              className="text-xs bg-green-100 text-green-700 hover:bg-green-200 px-2 py-1 rounded transition-colors"
                            >
                              Enable
                            </button>
                          ) : (
                            <button
                              onClick={() => handleAction(
                                () => disableUserScanning(userId!, user.user_id),
                                `Disabled scanning for ${user.email}`
                              )}
                              className="text-xs bg-red-100 text-red-600 hover:bg-red-200 px-2 py-1 rounded transition-colors"
                            >
                              Disable
                            </button>
                          )}
                          <button
                            onClick={() => handleAction(
                              () => resetUserLimit(userId!, user.user_id),
                              `Reset limit for ${user.email}`
                            )}
                            className="text-xs bg-blue-100 text-blue-700 hover:bg-blue-200 px-2 py-1 rounded transition-colors"
                          >
                            Reset Limit
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {users.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-6 py-8 text-center text-gray-400 text-sm">
                        No users found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Scans Tab */}
        {activeTab === "scans" && (
          <div className="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-sm">
            <div className="px-6 py-4 border-b border-gray-100">
              <h2 className="font-bold text-gray-800">All Scans ({scans.length})</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-gray-800 text-white text-xs uppercase">
                    <th className="px-4 py-3 text-left">Target URL</th>
                    <th className="px-4 py-3 text-left">Owner</th>
                    <th className="px-4 py-3 text-center">Status</th>
                    <th className="px-4 py-3 text-center">Created</th>
                    <th className="px-4 py-3 text-center">Findings</th>
                    <th className="px-4 py-3 text-center">Reports</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan, i) => (
                    <tr key={scan.scan_id} className={i % 2 === 0 ? "bg-white" : "bg-gray-50"}>
                      <td className="px-4 py-3 text-sm text-gray-800 max-w-xs truncate" title={scan.url}>
                        {scan.url}
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-500">{scan.user_email || "—"}</td>
                      <td className="px-4 py-3 text-center">
                        <span className={`text-xs font-bold px-2 py-1 rounded-full ${
                          scan.status === "completed" ? "bg-green-100 text-green-700" :
                          scan.status === "running"   ? "bg-yellow-100 text-yellow-700" :
                          scan.status === "failed"    ? "bg-red-100 text-red-600" :
                                                        "bg-gray-100 text-gray-500"
                        }`}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center text-xs text-gray-500">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {scan.summary && (
                          <div className="flex gap-1 justify-center text-xs">
                            {scan.summary.critical > 0 && <span className="bg-red-900 text-white px-1.5 py-0.5 rounded font-bold">{scan.summary.critical}C</span>}
                            {scan.summary.high > 0 && <span className="bg-red-500 text-white px-1.5 py-0.5 rounded font-bold">{scan.summary.high}H</span>}
                            {scan.summary.medium > 0 && <span className="bg-orange-400 text-white px-1.5 py-0.5 rounded font-bold">{scan.summary.medium}M</span>}
                            {scan.summary.low > 0 && <span className="bg-blue-500 text-white px-1.5 py-0.5 rounded font-bold">{scan.summary.low}L</span>}
                            {scan.summary.total === 0 && <span className="text-gray-400">—</span>}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {scan.status === "completed" && (
                          <div className="flex gap-1 justify-center">
                            <a
                              href={getReportUrl(scan.scan_id, "pdf")}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs bg-red-100 text-red-700 hover:bg-red-200 px-2 py-1 rounded transition-colors"
                            >
                              PDF
                            </a>
                            
                            <a
                              href={getReportUrl(scan.scan_id, "excel")}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs bg-green-100 text-green-700 hover:bg-green-200 px-2 py-1 rounded transition-colors"
                            >
                              Excel
                            </a>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                  {scans.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-6 py-8 text-center text-gray-400 text-sm">
                        No scans found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Health Tab */}
        {activeTab === "health" && health && (
          <div className="grid grid-cols-2 gap-4">
            {Object.entries(health).map(([service, info]: [string, any]) => (
              <div key={service} className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-semibold text-gray-800 capitalize">{service}</div>
                    {info.version && (
                      <div className="text-xs text-gray-400 mt-0.5">v{info.version}</div>
                    )}
                    {info.error && (
                      <div className="text-xs text-red-500 mt-0.5 max-w-xs truncate">{info.error}</div>
                    )}
                  </div>
                  <div className={`w-3 h-3 rounded-full ${
                    info.status === "healthy" ? "bg-green-400" : "bg-red-500"
                  }`} />
                </div>
                <div className={`text-xs font-medium mt-2 ${
                  info.status === "healthy" ? "text-green-600" : "text-red-600"
                }`}>
                  {info.status === "healthy" ? "● Operational" : "● Degraded"}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}