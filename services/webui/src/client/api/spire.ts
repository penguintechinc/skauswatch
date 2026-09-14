import api from '../lib/api';

const BASE = '/spire';

export const spireApi = {
  // ── Status ─────────────────────────────────────────────────────────
  async getStatus(): Promise<any> {
    const res = await api.get<any>(`${BASE}/status`);
    return res.data;
  },

  // ── Entries ────────────────────────────────────────────────────────
  async listEntries(): Promise<any> {
    const res = await api.get<any>(`${BASE}/entries`);
    return res.data;
  },

  async createEntry(data: {
    spiffe_id: string;
    parent_id: string;
    selectors: { type: string; value: string }[];
    ttl?: number;
  }): Promise<any> {
    const res = await api.post<any>(`${BASE}/entries`, data);
    return res.data;
  },

  async deleteEntry(id: string): Promise<void> {
    await api.delete(`${BASE}/entries/${id}`);
  },

  // ── Nodes ──────────────────────────────────────────────────────────
  async listNodes(): Promise<any> {
    const res = await api.get<any>(`${BASE}/nodes`);
    return res.data;
  },

  async createJoinToken(ttl?: number): Promise<any> {
    const res = await api.post<any>(`${BASE}/nodes/join-token`, ttl ? { ttl } : {});
    return res.data;
  },

  // ── Federation ─────────────────────────────────────────────────────
  async getFederation(): Promise<any> {
    const res = await api.get<any>(`${BASE}/federation`);
    return res.data;
  },

  async addFederationPeer(data: {
    trust_domain: string;
    endpoint_url: string;
  }): Promise<any> {
    const res = await api.post<any>(`${BASE}/federation/peers`, data);
    return res.data;
  },

  async removeFederationPeer(trustDomain: string): Promise<void> {
    await api.delete(`${BASE}/federation/peers/${trustDomain}`);
  },

  // ── Datastore ──────────────────────────────────────────────────────
  async migrateDatastore(data: {
    type: 'sqlite' | 'postgresql';
    host?: string;
    port?: number;
    db_name?: string;
    secret_name?: string;
  }): Promise<any> {
    const res = await api.post<any>(`${BASE}/datastore/migrate`, data);
    return res.data;
  },
};
