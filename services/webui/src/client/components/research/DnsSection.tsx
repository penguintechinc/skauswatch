import { DnsResult } from '../../types/research';

interface DnsSectionProps {
  data: DnsResult | null;
}

interface DnsRecord {
  type: string;
  values: string[];
  badge: string;
}

export default function DnsSection({ data }: DnsSectionProps) {
  if (!data) {
    return null;
  }

  const records: DnsRecord[] = [];

  if (data.a_records && data.a_records.length > 0) {
    records.push({ type: 'A', values: data.a_records, badge: 'bg-blue-500' });
  }
  if (data.aaaa_records && data.aaaa_records.length > 0) {
    records.push({ type: 'AAAA', values: data.aaaa_records, badge: 'bg-cyan-500' });
  }
  if (data.mx_records && data.mx_records.length > 0) {
    records.push({ type: 'MX', values: data.mx_records, badge: 'bg-purple-500' });
  }
  if (data.ns_records && data.ns_records.length > 0) {
    records.push({ type: 'NS', values: data.ns_records, badge: 'bg-indigo-500' });
  }
  if (data.txt_records && data.txt_records.length > 0) {
    records.push({ type: 'TXT', values: data.txt_records, badge: 'bg-green-500' });
  }
  if (data.cname_records && data.cname_records.length > 0) {
    records.push({ type: 'CNAME', values: data.cname_records, badge: 'bg-orange-500' });
  }
  if (data.soa_record) {
    records.push({ type: 'SOA', values: [data.soa_record], badge: 'bg-red-500' });
  }

  if (records.length === 0) {
    return null;
  }

  return (
    <div className="space-y-3">
      {records.map((record) => (
        <div key={record.type} className="bg-dark-700 p-4 rounded">
          <div className="flex items-center gap-2 mb-3">
            <span className={`${record.badge} text-white text-xs font-semibold px-2 py-1 rounded`}>
              {record.type}
            </span>
            <span className="text-dark-400 text-sm">
              ({record.values.length} record{record.values.length !== 1 ? 's' : ''})
            </span>
          </div>
          <ul className="space-y-2">
            {record.values.map((value, index) => (
              <li key={index} className="text-gold-400 font-mono text-sm break-all">
                {value}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
