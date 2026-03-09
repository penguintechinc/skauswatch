import { AsnResult } from '../../types/research';

interface AsnSectionProps {
  data: AsnResult | null;
}

interface AsnField {
  label: string;
  value: string | undefined;
}

export default function AsnSection({ data }: AsnSectionProps) {
  if (!data) {
    return null;
  }

  const fields: AsnField[] = [
    { label: 'ASN', value: data.asn },
    { label: 'Organization', value: data.organization },
    { label: 'Country', value: data.country },
    { label: 'Network CIDR', value: data.network },
    { label: 'Registry', value: data.registry },
    { label: 'Description', value: data.description },
  ];

  const visibleFields = fields.filter((f) => f.value);

  if (visibleFields.length === 0) {
    return null;
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {visibleFields.map((field) => (
        <div key={field.label} className="bg-dark-700 p-4 rounded">
          <p className="text-dark-400 text-sm font-medium mb-2">{field.label}</p>
          <p className="text-gold-400 break-all">{field.value}</p>
        </div>
      ))}
    </div>
  );
}
