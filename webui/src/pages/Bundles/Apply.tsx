import { useState, useRef } from 'react';
import {
  PageSection,
  Title,
  Button,
  Alert,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
} from '@patternfly/react-core';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import { applyDeltas, type ApplyResult } from '../../api/bundles';
import { errorMessage } from '../../api/client';
import { fmtBytes } from '../../utils';

/// Trigger a browser download of base64-encoded bytes as a .ahu file.
function downloadBase64(b64: string, filename: string) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export default function BundleApply() {
  const [result, setResult] = useState<ApplyResult | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const baseRef = useRef<HTMLInputElement>(null);
  const deltaRef = useRef<HTMLInputElement>(null);

  const handleApply = async () => {
    const base = baseRef.current?.files?.[0];
    const deltaFiles = deltaRef.current?.files;
    if (!base) {
      setError('Select a base bundle.');
      return;
    }
    if (!deltaFiles || deltaFiles.length === 0) {
      setError('Select at least one delta bundle.');
      return;
    }
    // Deltas must be applied in order; sort by filename so a multi-select
    // (which yields OS-dependent order) is deterministic.
    const deltas = Array.from(deltaFiles).sort((a, b) => a.name.localeCompare(b.name));
    setLoading(true);
    setError('');
    setResult(null);
    try {
      setResult(await applyDeltas(base, deltas));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Apply Deltas</Title>
      </PageSection>
      <PageSection>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1rem', maxWidth: 720 }}>
          <label>
            <strong>Base bundle</strong> (full):{' '}
            <input type="file" accept=".ahu" ref={baseRef} />
          </label>
          <label>
            <strong>Delta bundles</strong> (applied in filename order):{' '}
            <input type="file" accept=".ahu" ref={deltaRef} multiple />
          </label>
          <div>
            <Button variant="primary" onClick={handleApply} isLoading={loading} isDisabled={loading}>
              Apply
            </Button>
          </div>
        </div>

        {error && <Alert variant="danger" title="Apply failed">{error}</Alert>}

        {result && (
          <>
            <Alert variant="success" title="Materialized full bundle" style={{ marginBottom: '1rem' }} />
            <DescriptionList isHorizontal columnModifier={{ default: '2Col' }} style={{ maxWidth: 720, marginBottom: '1rem' }}>
              <DescriptionListGroup>
                <DescriptionListTerm>Entry count</DescriptionListTerm>
                <DescriptionListDescription>{result.entry_count}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Final epoch</DescriptionListTerm>
                <DescriptionListDescription>{result.final_epoch}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Size</DescriptionListTerm>
                <DescriptionListDescription>{fmtBytes(result.byte_length)}</DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>

            <Title headingLevel="h3" style={{ marginBottom: '0.5rem' }}>Per-delta changes</Title>
            <Table aria-label="Delta application stats" variant="compact">
              <Thead>
                <Tr>
                  <Th>Delta</Th>
                  <Th>Added</Th>
                  <Th>Replaced</Th>
                  <Th>Removed</Th>
                  <Th>Warning</Th>
                </Tr>
              </Thead>
              <Tbody>
                {result.deltas.map((s, i) => (
                  <Tr key={i}>
                    <Td>{i + 1}</Td>
                    <Td>{s.added}</Td>
                    <Td>{s.replaced}</Td>
                    <Td>{s.removed}</Td>
                    <Td>{s.chain_length_warning ? 'chain length exceeds recommended max' : '—'}</Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>

            <div style={{ marginTop: '1rem' }}>
              <Button variant="secondary" onClick={() => downloadBase64(result.bundle_b64, `materialized-epoch-${result.final_epoch}.ahu`)}>
                Download bundle
              </Button>
            </div>
          </>
        )}
      </PageSection>
    </>
  );
}
