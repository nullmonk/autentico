import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, postJSON, getResponse, deleteRequest } from '../helpers';

const API_TOKENS_ENDPOINT = `${BASE_URL}/admin/api/api-tokens`;
const API_TOKENS_ROUTES_ENDPOINT = `${BASE_URL}/admin/api/api-tokens/routes`;

describe('Admin API Tokens', () => {
  let createdTokenId: string;
  let createdTokenValue: string;

  it('should list available routes', async () => {
    const adminToken = await getAdminToken();
    const resp = await getResponse(API_TOKENS_ROUTES_ENDPOINT, adminToken);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.data).toBeInstanceOf(Array);
    expect(body.data.length).toBeGreaterThan(0);
    expect(body.data[0]).toHaveProperty('method');
    expect(body.data[0]).toHaveProperty('path');
  });

  it('should create an API token with specific routes', async () => {
    const adminToken = await getAdminToken();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days from now

    const reqBody = {
      name: 'Test API Token',
      expires_at: expiresAt.toISOString(),
      routes: ['/admin/api/users:GET', '/admin/api/users:POST']
    };

    const createResp = await postJSON(API_TOKENS_ENDPOINT, reqBody, adminToken);
    expect(createResp.status).toBe(201);
    const createBody = await createResp.json();

    expect(createBody.data).toHaveProperty('id');
    expect(createBody.data).toHaveProperty('token');
    expect(createBody.data.name).toBe('Test API Token');

    createdTokenId = createBody.data.id;
    createdTokenValue = createBody.data.token;
  });

  it('should allow access to configured route', async () => {
    const getUsersResp = await getResponse(`${BASE_URL}/admin/api/users`, createdTokenValue);
    expect(getUsersResp.status).toBe(200);
  });

  it('should deny access to unconfigured route', async () => {
    const getClientsResp = await getResponse(`${BASE_URL}/admin/api/clients`, createdTokenValue);
    expect(getClientsResp.status).toBe(403);
  });

  it('should revoke the token', async () => {
    const adminToken = await getAdminToken();
    const deleteResp = await deleteRequest(`${API_TOKENS_ENDPOINT}/${createdTokenId}`, adminToken);
    expect(deleteResp.status).toBe(204);
  });

  it('should deny access after revocation', async () => {
    const getUsersResp = await getResponse(`${BASE_URL}/admin/api/users`, createdTokenValue);
    expect(getUsersResp.status).toBe(401);
  });
});
