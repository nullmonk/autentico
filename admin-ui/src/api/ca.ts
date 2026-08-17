import apiClient from "./client";
import { Certificate } from "../types/ca";

const BASE = "/admin/api/certificates";

export async function listCertificates(userId?: string): Promise<{ items: Certificate[] }> {
  const url = userId ? `${BASE}?user=${userId}` : BASE;
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
  userId: string,
  interId: string,
  interPw: string,
  bundlePw: string
): Promise<Blob> {
  const { data } = await apiClient.post(
    BASE,
    {
      user_id: userId,
      cert_id: interId,
      cert_pw: interPw,
      bundle_password: bundlePw,
    },
    { responseType: "blob" }
  );
  return data;
}

export async function downloadUserCert(id: string, bundlePw: string): Promise<Blob> {
  const { data } = await apiClient.get(`${BASE}/${id}/bundle?password=${encodeURIComponent(bundlePw)}`, {
    responseType: "blob",
  });
  return data;
}
