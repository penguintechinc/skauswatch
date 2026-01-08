import { WhoisResult } from '../../types/research';

interface WhoisSectionProps {
  data: WhoisResult | null;
}

export default function WhoisSection({ data }: WhoisSectionProps) {
  if (!data) {
    return null;
  }

  const formatDate = (dateStr: string | undefined): string => {
    if (!dateStr) return 'N/A';
    try {
      return new Date(dateStr).toLocaleDateString();
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {data.registrar && (
          <div className="bg-dark-700 p-3 rounded">
            <p className="text-dark-400 text-sm font-medium">Registrar</p>
            <p className="text-gold-400 mt-1">{data.registrar}</p>
          </div>
        )}

        {data.creation_date && (
          <div className="bg-dark-700 p-3 rounded">
            <p className="text-dark-400 text-sm font-medium">Created</p>
            <p className="text-gold-400 mt-1">{formatDate(data.creation_date)}</p>
          </div>
        )}

        {data.updated_date && (
          <div className="bg-dark-700 p-3 rounded">
            <p className="text-dark-400 text-sm font-medium">Updated</p>
            <p className="text-gold-400 mt-1">{formatDate(data.updated_date)}</p>
          </div>
        )}

        {data.expiration_date && (
          <div className="bg-dark-700 p-3 rounded">
            <p className="text-dark-400 text-sm font-medium">Expires</p>
            <p className="text-gold-400 mt-1">{formatDate(data.expiration_date)}</p>
          </div>
        )}
      </div>

      {data.nameservers && data.nameservers.length > 0 && (
        <div className="bg-dark-700 p-4 rounded">
          <p className="text-dark-400 text-sm font-medium mb-3">Nameservers</p>
          <ul className="space-y-2">
            {data.nameservers.map((ns, index) => (
              <li key={index} className="text-gold-400 font-mono text-sm">
                {ns}
              </li>
            ))}
          </ul>
        </div>
      )}

      {data.registrant && Object.keys(data.registrant).length > 0 && (
        <div className="bg-dark-700 p-4 rounded">
          <p className="text-dark-400 text-sm font-medium mb-3">Registrant Information</p>
          <div className="space-y-2">
            {Object.entries(data.registrant).map(([key, value]) => (
              <div key={key} className="flex justify-between items-start gap-4">
                <span className="text-dark-400 text-sm capitalize">{key.replace(/_/g, ' ')}:</span>
                <span className="text-gold-400 text-sm text-right">
                  {typeof value === 'string' ? value : JSON.stringify(value)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
