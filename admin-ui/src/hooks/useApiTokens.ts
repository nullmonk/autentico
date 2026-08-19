import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { type ListParams, type ListResponse } from "../api/users";
import apiClient from "../api/client";

export interface ApiToken {
  id: string;
  name: string;
  created_by: string;
  created_at: string;
  expires_at: string;
}

export interface CreateApiTokenRequest {
  name: string;
  expires_at: string;
  routes: string[];
}

export interface CreateApiTokenResponse {
  id: string;
  name: string;
  token: string;
  created_at: string;
  expires_at: string;
}

export function useApiTokens(params: ListParams) {
  return useQuery({
    queryKey: ["api-tokens", params],
    queryFn: async () => {
      const { data } = await apiClient.get<{ data: ListResponse<ApiToken> }>("/admin/api/api-tokens", {
        params,
      });
      return data.data;
    },
  });
}

export function useCreateApiToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (req: CreateApiTokenRequest) => {
      const { data } = await apiClient.post<{ data: CreateApiTokenResponse }>("/admin/api/api-tokens", req);
      return data.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-tokens"] });
    },
  });
}

export function useRevokeApiToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/admin/api/api-tokens/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-tokens"] });
    },
  });
}
