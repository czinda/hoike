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
  Label,
} from '@patternfly/react-core';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import { inspectBundle, type InspectResult } from '../../api/bundles';
import { fmtTs } from '../../utils';
import { errorMessage } from '../../api/client';

export default function BundleInspect() {
  const [result, setResult] = useState<InspectResult | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleUpload = async () => {
    const file = fileRef.current?.files?.[0];
    if (!file) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const res = await inspectBundle(file);
      setResult(res);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Inspect Bundle</Title>
      </PageSection>
      <PageSection>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1rem' }}>
          <input type="file" accept=".ahu" ref={fileRef} />
          <Button variant="primary" onClick={handleUpload} isLoading={loading} isDisabled={loading}>
            Inspect
          </Button>
        </div>

        {error && <Alert variant="danger" title="Inspect failed">{error}</Alert>}

        {result && (
          <>
            <Title headingLevel="h2" style={{ marginBottom: '1rem' }}>Result</Title>
            <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: 640, marginBottom: '1.5rem' }}>
              <DescriptionListGroup>
                <DescriptionListTerm>Bundle ID</DescriptionListTerm>
                <DescriptionListDescription style={{ fontFamily: 'monospace' }}>{result.bundle_id}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Producer</DescriptionListTerm>
                <DescriptionListDescription>{result.producer_id}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Type</DescriptionListTerm>
                <DescriptionListDescription>{result.bundle_type}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Created At</DescriptionListTerm>
                <DescriptionListDescription>{fmtTs(result.created_at)}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Entry Count</DescriptionListTerm>
                <DescriptionListDescription>{result.entry_count}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Index Records</DescriptionListTerm>
                <DescriptionListDescription>{result.index_records}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Seal Present</DescriptionListTerm>
                <DescriptionListDescription>
                  <Label color={result.seal_present ? 'green' : 'red'}>
                    {result.seal_present ? 'Yes' : 'No'}
                  </Label>
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>

            <Title headingLevel="h3" style={{ marginBottom: '0.5rem' }}>Scopes</Title>
            <Table aria-label="Bundle scopes" variant="compact">
              <Thead>
                <Tr>
                  <Th>Epoch</Th>
                  <Th>Completeness</Th>
                  <Th>Issuer Name Hash</Th>
                  <Th>Issuer Key Hash</Th>
                  <Th>Sig Algorithm</Th>
                </Tr>
              </Thead>
              <Tbody>
                {result.scopes.map((s, i) => (
                  <Tr key={i}>
                    <Td>{s.epoch}</Td>
                    <Td>{s.completeness}</Td>
                    <Td style={{ fontFamily: 'monospace', fontSize: '0.85em' }}>{s.issuer_name_hash}</Td>
                    <Td style={{ fontFamily: 'monospace', fontSize: '0.85em' }}>{s.issuer_key_hash}</Td>
                    <Td style={{ fontFamily: 'monospace', fontSize: '0.85em' }}>{s.signature_algorithm}</Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </>
        )}
      </PageSection>
    </>
  );
}
