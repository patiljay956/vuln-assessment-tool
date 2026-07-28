import { api } from "./api";

export const checkAdmin = async (userId: string) => {
  const res = await api.get(`/admin/check?user_id=${userId}`);
  return res.data;
};

export const getAdminStats = async (userId: string) => {
  const res = await api.get(`/admin/stats?user_id=${userId}`);
  return res.data;
};

export const getAdminUsers = async (userId: string) => {
  const res = await api.get(`/admin/users?user_id=${userId}`);
  return res.data;
};

export const getAdminScans = async (userId: string, limit = 50, offset = 0) => {
  const res = await api.get(`/admin/scans?user_id=${userId}&limit=${limit}&offset=${offset}`);
  return res.data;
};

export const getSystemHealth = async (userId: string) => {
  const res = await api.get(`/admin/health?user_id=${userId}`);
  return res.data;
};

export const disableUserScanning = async (userId: string, targetUserId: string) => {
  const res = await api.post(`/admin/users/${targetUserId}/disable-scanning?user_id=${userId}`);
  return res.data;
};

export const enableUserScanning = async (userId: string, targetUserId: string) => {
  const res = await api.post(`/admin/users/${targetUserId}/enable-scanning?user_id=${userId}`);
  return res.data;
};

export const resetUserLimit = async (userId: string, targetUserId: string) => {
  const res = await api.post(`/admin/users/${targetUserId}/reset-limit?user_id=${userId}`);
  return res.data;
};