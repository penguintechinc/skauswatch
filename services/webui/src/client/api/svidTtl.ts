import api from '../lib/api';
import type { SvidTtlSettings, UpdateSvidTtlRequest } from '../types/svidTtl';

const BASE = '/admin/svid-ttl';

/**
 * Client for the super-admin SPIFFE SVID TTL settings endpoint. Routes
 * through the centralized `api` client (auth interceptor injects the JWT)
 * to the manager backend — never a bare fetch.
 */
export const svidTtlApi = {
  async get(): Promise<SvidTtlSettings> {
    const res = await api.get<SvidTtlSettings>(BASE);
    return res.data;
  },

  async update(data: UpdateSvidTtlRequest): Promise<void> {
    await api.put(BASE, data);
  },
};
