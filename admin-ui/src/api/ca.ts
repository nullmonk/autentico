import apiClient from "./client";
import { Certificate } from "../types/ca";

const BASE = "/admin/api/certificates";

export async function listCertificates(userId?: string, type: string = "user"): Promise<{ items: Certificate[] }> {
  const params = new URLSearchParams();
  if (userId) params.append("user", userId);
  if (type) params.append("type", type);

  const url = `${BASE}?${params.toString()}`;
  const { data } = await apiClient.get(url);
  return data;
}

export async function listAuthorities(): Promise<{ items: Certificate[] }> {
  const { data } = await apiClient.get(`${BASE}/authorities`);
  return data;
}

export async function revokeCertificate(id: string): Promise<void> {
  await apiClient.delete(`${BASE}/${id}`);
}

export async function generateUserCert(
  username: string,
  interId: string,
  interPw: string,
): Promise<{ success: boolean; id: string }> {
  const { data } = await apiClient.post(BASE, {
    username: username,
    cert_id: interId,
    cert_pw: interPw,
  });
  return data;
}

export async function generateServerCert(
  hosts: string[],
  interId: string,
  interPw: string,
): Promise<{ success: boolean; id: string }> {
  const { data } = await apiClient.post(`${BASE}/server`, {
    hosts: hosts,
    cert_id: interId,
    cert_pw: interPw,
  });
  return data;
}

export async function downloadUserCert(id: string, bundlePw: string): Promise<Blob> {
  const { data } = await apiClient.get(`${BASE}/${id}/bundle?password=${encodeURIComponent(bundlePw)}`, {
    responseType: "blob",
  });
  return data;
}
