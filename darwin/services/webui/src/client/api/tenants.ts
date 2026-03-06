import api from '../lib/api';
import type {
  Tenant,
  CreateTenantData,
  UpdateTenantData,
  TenantMember,
  AddTenantMemberData,
  PaginatedResponse,
} from '../types';

export const tenantsApi = {
  list: async (page = 1, perPage = 20): Promise<PaginatedResponse<Tenant>> => {
    const response = await api.get('/tenants', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number): Promise<Tenant> => {
    const response = await api.get(`/tenants/${id}`);
    return response.data;
  },

  create: async (data: CreateTenantData): Promise<Tenant> => {
    const response = await api.post('/tenants', data);
    return response.data;
  },

  update: async (id: number, data: UpdateTenantData): Promise<Tenant> => {
    const response = await api.put(`/tenants/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/tenants/${id}`);
  },

  getMembers: async (id: number, page = 1, perPage = 20): Promise<PaginatedResponse<TenantMember>> => {
    const response = await api.get(`/tenants/${id}/members`, { params: { page, per_page: perPage } });
    return response.data;
  },

  addMember: async (id: number, data: AddTenantMemberData): Promise<TenantMember> => {
    const response = await api.post(`/tenants/${id}/members`, data);
    return response.data;
  },

  removeMember: async (id: number, userId: number): Promise<void> => {
    await api.delete(`/tenants/${id}/members/${userId}`);
  },
};
