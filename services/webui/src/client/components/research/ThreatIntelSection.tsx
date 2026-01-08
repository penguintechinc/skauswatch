import { ThreatIntelResult } from '../../types/research';

interface ThreatIntelSectionProps {
  data: ThreatIntelResult | null;
}

export default function ThreatIntelSection({ data }: ThreatIntelSectionProps) {
  if (!data) {
    return null;
  }

  const virusTotal = data.virustotal_malicious !== undefined && data.virustotal_total !== undefined;
  const otxPulses = data.otx_pulses && data.otx_pulses.length > 0;
  const dnsBlacklists = data.dns_blacklist_hits && data.dns_blacklist_hits.length > 0;
  const hasLocalIOC = data.local_ioc_match !== undefined;

  // If no meaningful data, return null
  if (!virusTotal && !otxPulses && !dnsBlacklists && !hasLocalIOC) {
    return null;
  }

  const isMalicious = data.virustotal_malicious && data.virustotal_malicious > 0;
  const progressPercentage = virusTotal
    ? Math.round((data.virustotal_malicious! / data.virustotal_total!) * 100)
    : 0;

  return (
    <div className="space-y-4">
      {virusTotal && (
        <div className="bg-dark-700 p-4 rounded">
          <div className="flex items-center justify-between mb-3">
            <p className="text-dark-400 text-sm font-medium">VirusTotal</p>
            <p className={isMalicious ? 'text-red-400 font-bold' : 'text-green-400 font-bold'}>
              {data.virustotal_malicious}/{data.virustotal_total} engines flagged as malicious
            </p>
          </div>

          <div className="w-full bg-dark-800 rounded-full h-2 overflow-hidden">
            <div
              className={isMalicious ? 'bg-red-400 h-full' : 'bg-green-400 h-full'}
              style={{ width: `${progressPercentage}%` }}
            />
          </div>
          {isMalicious && (
            <p className="text-red-400 text-xs mt-2">Malicious detection detected</p>
          )}
        </div>
      )}

      {otxPulses && (
        <div className="bg-dark-700 p-4 rounded">
          <p className="text-dark-400 text-sm font-medium mb-3">AlienVault OTX</p>
          <p className="text-gold-400 mb-3">
            Found in {data.otx_pulses!.length} threat pulse{data.otx_pulses!.length !== 1 ? 's' : ''}
          </p>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {data.otx_pulses!.map((pulse, index) => {
              const pulseName = typeof pulse === 'object' && 'name' in pulse ? pulse.name : `Pulse ${index + 1}`;
              return (
                <div key={index} className="text-gold-400 text-sm">
                  {typeof pulseName === 'string' ? pulseName : JSON.stringify(pulseName)}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {dnsBlacklists && (
        <div className="bg-dark-700 p-4 rounded">
          <p className="text-dark-400 text-sm font-medium mb-3">DNS Blacklists</p>
          <div className="flex flex-wrap gap-2">
            {data.dns_blacklist_hits!.map((blacklist, index) => (
              <span key={index} className="bg-red-400 text-dark-900 text-xs px-3 py-1 rounded-full font-medium">
                {blacklist}
              </span>
            ))}
          </div>
        </div>
      )}

      {hasLocalIOC && (
        <div className="bg-dark-700 p-4 rounded">
          <div className="flex items-center gap-3">
            <div className="flex-1">
              <p className="text-dark-400 text-sm font-medium">Local IOC Database</p>
            </div>
            <div className="flex items-center gap-2">
              {data.local_ioc_match ? (
                <>
                  <span className="w-5 h-5 flex items-center justify-center bg-red-400 rounded-full">
                    <svg className="w-3 h-3 text-dark-900" fill="currentColor" viewBox="0 0 20 20">
                      <path
                        fillRule="evenodd"
                        d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                        clipRule="evenodd"
                      />
                    </svg>
                  </span>
                  <p className="text-red-400 font-medium">Match found</p>
                </>
              ) : (
                <>
                  <span className="w-5 h-5 flex items-center justify-center bg-green-400 rounded-full">
                    <svg className="w-3 h-3 text-dark-900" fill="currentColor" viewBox="0 0 20 20">
                      <path
                        fillRule="evenodd"
                        d="M4.293 5.293a1 1 0 011.414 0L10 9.586l4.293-4.293a1 1 0 111.414 1.414L11.414 11l4.293 4.293a1 1 0 01-1.414 1.414L10 12.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 11 4.293 6.707a1 1 0 010-1.414z"
                        clipRule="evenodd"
                      />
                    </svg>
                  </span>
                  <p className="text-green-400 font-medium">No matches</p>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
