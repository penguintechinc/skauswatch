// Enum
export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'asn' | 'email';

// Result interfaces
export interface WhoisResult {
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  updated_date?: string;
  nameservers?: string[];
  registrant?: Record<string, unknown>;
  raw_data?: string;
}

export interface DnsResult {
  a_records?: string[];
  aaaa_records?: string[];
  mx_records?: string[];
  ns_records?: string[];
  txt_records?: string[];
  cname_records?: string[];
  soa_record?: string;
}

export interface AsnResult {
  asn?: string;
  organization?: string;
  country?: string;
  network?: string;
  registry?: string;
  description?: string;
}

export interface ShodanResult {
  ip?: string;
  ports?: number[];
  services?: string[];
  vulns?: string[];
  ssl_cert?: Record<string, unknown>;
  last_update?: string;
}

export interface MaltegoResult {
  related_domains?: string[];
  emails?: string[];
  social_profiles?: Record<string, unknown>;
  shared_hosting?: string[];
  infrastructure?: Record<string, unknown>;
}

export interface ThreatIntelResult {
  virustotal_malicious?: number;
  virustotal_total?: number;
  otx_pulses?: Record<string, unknown>[];
  dns_blacklist_hits?: string[];
  local_ioc_match?: boolean;
}

export interface ResearchSummary {
  indicator_type: IndicatorType;
  risk_score: number;
  key_findings: string[];
}

// Request/Response
export interface ResearchLookupRequest {
  query: string;
  indicator_type?: IndicatorType;
  include_threat_intel?: boolean;
  include_shodan?: boolean;
  include_maltego?: boolean;
}

export interface ResearchLookupResponse {
  query: string;
  indicator_type: IndicatorType;
  timestamp: string;
  summary: ResearchSummary;
  whois?: WhoisResult;
  dns?: DnsResult;
  asn?: AsnResult;
  shodan?: ShodanResult;
  maltego?: MaltegoResult;
  threat_intel?: ThreatIntelResult;
  processing_time_ms: number;
}

// Config
export interface ResearchConfig {
  research_enabled: boolean;
  shodan_enabled: boolean;
  maltego_enabled: boolean;
  whois_timeout: number;
  dns_timeout: number;
  asn_timeout: number;
}
