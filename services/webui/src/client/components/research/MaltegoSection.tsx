import { MaltegoResult } from '../../types/research';

interface MaltegoSectionProps {
  data: MaltegoResult | null;
  enabled: boolean;
}

export default function MaltegoSection({ data, enabled }: MaltegoSectionProps) {
  if (!enabled) {
    return (
      <div className="bg-dark-800 rounded-lg p-6 border border-dark-600">
        <h3 className="text-lg font-semibold text-gold-400 mb-4">Maltego Integration</h3>
        <p className="text-dark-400">Maltego integration not configured</p>
      </div>
    );
  }

  if (data === null) {
    return null;
  }

  return (
    <div className="bg-dark-800 rounded-lg p-6 border border-dark-600">
      <h3 className="text-lg font-semibold text-gold-400 mb-4">Maltego Results</h3>

      <div className="space-y-4">
        {/* Related Domains */}
        {data.related_domains && data.related_domains.length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gold-400 mb-2">Related Domains</label>
            <ul className="space-y-1">
              {data.related_domains.map((domain, idx) => (
                <li key={idx} className="text-dark-200 text-sm">
                  • {domain}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Email Addresses */}
        {data.emails && data.emails.length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gold-400 mb-2">Email Addresses</label>
            <ul className="space-y-1">
              {data.emails.map((email, idx) => (
                <li key={idx} className="text-dark-200 text-sm">
                  • {email}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Social Profiles */}
        {data.social_profiles && Object.keys(data.social_profiles).length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gold-400 mb-2">Social Profiles</label>
            <div className="space-y-2">
              {Object.entries(data.social_profiles).map(([platform, profile], idx) => (
                <div key={idx} className="bg-dark-700 rounded p-3 text-sm">
                  <p className="text-gold-300 font-medium">{platform}</p>
                  <pre className="text-dark-200 overflow-auto max-h-32 whitespace-pre-wrap break-words mt-1">
                    {typeof profile === 'string' ? profile : JSON.stringify(profile, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Shared Hosting */}
        {data.shared_hosting && data.shared_hosting.length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gold-400 mb-2">Shared Hosting Info</label>
            <ul className="space-y-1">
              {data.shared_hosting.map((host, idx) => (
                <li key={idx} className="text-dark-200 text-sm">
                  • {host}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Infrastructure Details */}
        {data.infrastructure && Object.keys(data.infrastructure).length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gold-400 mb-2">Infrastructure Details</label>
            <div className="bg-dark-700 rounded p-3 text-sm">
              <pre className="text-dark-200 overflow-auto max-h-40 whitespace-pre-wrap break-words">
                {JSON.stringify(data.infrastructure, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
