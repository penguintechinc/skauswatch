import { ResearchLookupResponse, ResearchConfig } from '../../types/research';
import ResearchSummary from './ResearchSummary';
import CollapsibleSection from './CollapsibleSection';
import WhoisSection from './WhoisSection';
import DnsSection from './DnsSection';
import AsnSection from './AsnSection';
import ShodanSection from './ShodanSection';
import MaltegoSection from './MaltegoSection';
import ThreatIntelSection from './ThreatIntelSection';

interface ResearchResultsProps {
  results: ResearchLookupResponse | null;
  config: ResearchConfig;
}

export default function ResearchResults({ results, config }: ResearchResultsProps) {
  if (!results) {
    return null;
  }

  return (
    <div className="space-y-4">
      {/* Always shown at top, not collapsible */}
      <ResearchSummary summary={results.summary} />

      {/* Collapsible sections */}
      {results.whois && (
        <CollapsibleSection title="WHOIS Information" defaultOpen={false}>
          <WhoisSection data={results.whois} />
        </CollapsibleSection>
      )}

      {results.dns && (
        <CollapsibleSection title="DNS Records" defaultOpen={false}>
          <DnsSection data={results.dns} />
        </CollapsibleSection>
      )}

      {results.asn && (
        <CollapsibleSection title="ASN Information" defaultOpen={false}>
          <AsnSection data={results.asn} />
        </CollapsibleSection>
      )}

      {config.shodan_enabled && results.shodan && (
        <CollapsibleSection title="Shodan Data" defaultOpen={false}>
          <ShodanSection data={results.shodan} enabled={config.shodan_enabled} />
        </CollapsibleSection>
      )}

      {config.maltego_enabled && results.maltego && (
        <CollapsibleSection title="Maltego Transforms" defaultOpen={false}>
          <MaltegoSection data={results.maltego} enabled={config.maltego_enabled} />
        </CollapsibleSection>
      )}

      {results.threat_intel && (
        <CollapsibleSection title="Threat Intelligence" defaultOpen={false}>
          <ThreatIntelSection data={results.threat_intel} />
        </CollapsibleSection>
      )}

      {/* Processing time footer */}
      <div className="bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-right">
        <p className="text-dark-400 text-xs">
          Processing time: <span className="text-gold-400 font-mono">{results.processing_time_ms}ms</span>
        </p>
      </div>
    </div>
  );
}
