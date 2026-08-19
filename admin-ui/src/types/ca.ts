export interface Certificate {
  id: string;
  type: "ca" | "intermediary" | "user";
  created_at: string;
  revoked_at?: string;
  user_id?: string;
  username?: string;
  intermediary_id?: string;
  expire_date?: string;
  cert_pem?: string;
}
