import api from '../lib/api';
import type {
  ResearchLookupRequest,
  ResearchLookupResponse,
  ResearchConfig,
  WhoisResult,
  DnsResult,
  AsnResult,
} from '../types/research';

// Research API
export const researchApi = {
  lookup: async (
    request: ResearchLookupRequest
  ): Promise<ResearchLookupResponse> => {
    const response = await api.post('/research/lookup', request);
    return response.data;
  },

  whois: async (
    query: string,
    indicatorType?: string
  ): Promise<WhoisResult> => {
    const response = await api.get('/research/whois', {
      params: { query, indicator_type: indicatorType },
    });
    return response.data;
  },

  dns: async (query: string): Promise<DnsResult> => {
    const response = await api.get('/research/dns', { params: { query } });
    return response.data;
  },

  asn: async (
    query: string,
    indicatorType?: string
  ): Promise<AsnResult> => {
    const response = await api.get('/research/asn', {
      params: { query, indicator_type: indicatorType },
    });
    return response.data;
  },

  shodan: async (
    query: string,
    indicatorType?: string
  ): Promise<Record<string, unknown>> => {
    const response = await api.get('/research/shodan', {
      params: { query, indicator_type: indicatorType },
    });
    return response.data;
  },

  maltego: async (
    query: string,
    indicatorType?: string
  ): Promise<Record<string, unknown>> => {
    const response = await api.get('/research/maltego', {
      params: { query, indicator_type: indicatorType },
    });
    return response.data;
  },

  getConfig: async (): Promise<ResearchConfig> => {
    const response = await api.get('/research/config');
    return response.data;
  },
};
