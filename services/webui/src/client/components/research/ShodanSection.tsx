import { ShodanResult } from '../../types/research';

interface ShodanSectionProps {
  data: ShodanResult | null;
  enabled: boolean;
}

export default function ShodanSection({ data, enabled }: ShodanSectionProps) {
  if (!enabled) {
    return (
      <div className="bg-dark-800 rounded-lg p-6 border border-dark-600">
        <h3 className="text-lg font-semibold text-gold-400 mb-4">Shodan Integration</h3>
        <p className="text-dark-400">Shodan integration not configured</p>
      </div>
    );
  }

  if (data === null) {
    return null;
  }

  return (
    <div className="bg-dark-800 rounded-lg p-6 border border-dark-600">
      <h3 className="text-lg font-semibold text-gold-400 mb-4">Shodan Results</h3>

      <div className="space-y-4">
        {/* IP Address */}
        {data.ip && (
          <div>
            <label className="block text-sm font-medium text-gold-400 mb-1">IP Address</label>
            <p className="text-dark-200">{data.ip}</p>
          </div>
        )}

        {/* Open Ports */}
        {data.ports && data.ports.length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gold-400 mb-2">Open Ports</label>
            <div className="flex flex-wrap gap-2">
              {data.ports.map((port) => (
                <span
                  key={port}
                  className="inline-block bg-dark-700 text-gold-300 px-3 py-1 rounded text-sm border border-gold-600"
                >
                  {port}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Services */}
        {data.services && data.services.length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gold-400 mb-2">Services</label>
            <ul className="space-y-1">
              {data.services.map((service, idx) => (
                <li key={idx} className="text-dark-200 text-sm">
                  • {service}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Vulnerabilities */}
        {data.vulns && data.vulns.length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gold-400 mb-2">Vulnerabilities</label>
            <ul className="space-y-1">
              {data.vulns.map((vuln, idx) => (
                <li key={idx} className="text-red-400 text-sm flex items-start">
                  <span className="mr-2">⚠</span>
                  <span>{vuln}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* SSL Certificate */}
        {data.ssl_cert && Object.keys(data.ssl_cert).length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gold-400 mb-2">SSL Certificate</label>
            <div className="bg-dark-700 rounded p-3 text-sm">
              <pre className="text-dark-200 overflow-auto max-h-40 whitespace-pre-wrap break-words">
                {JSON.stringify(data.ssl_cert, null, 2)}
              </pre>
            </div>
          </div>
        )}

        {/* Last Update */}
        {data.last_update && (
          <div>
            <label className="block text-sm font-medium text-gold-400 mb-1">Last Updated</label>
            <p className="text-dark-400 text-sm">{data.last_update}</p>
          </div>
        )}
      </div>
    </div>
  );
}
