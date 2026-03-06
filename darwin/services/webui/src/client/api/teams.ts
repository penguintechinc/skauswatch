import api from '../lib/api';
import type {
  Team,
  CreateTeamData,
  UpdateTeamData,
  TeamMember,
  AddTeamMemberData,
  PaginatedResponse,
} from '../types';

export const teamsApi = {
  list: async (page = 1, perPage = 20): Promise<PaginatedResponse<Team>> => {
    const response = await api.get('/teams', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number): Promise<Team> => {
    const response = await api.get(`/teams/${id}`);
    return response.data;
  },

  create: async (data: CreateTeamData): Promise<Team> => {
    const response = await api.post('/teams', data);
    return response.data;
  },

  update: async (id: number, data: UpdateTeamData): Promise<Team> => {
    const response = await api.put(`/teams/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/teams/${id}`);
  },

  getMembers: async (id: number, page = 1, perPage = 20): Promise<PaginatedResponse<TeamMember>> => {
    const response = await api.get(`/teams/${id}/members`, { params: { page, per_page: perPage } });
    return response.data;
  },

  addMember: async (id: number, data: AddTeamMemberData): Promise<TeamMember> => {
    const response = await api.post(`/teams/${id}/members`, data);
    return response.data;
  },

  removeMember: async (id: number, userId: number): Promise<void> => {
    await api.delete(`/teams/${id}/members/${userId}`);
  },
};
