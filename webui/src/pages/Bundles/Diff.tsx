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
import { diffBundles, type DiffResult, type EntryRef } from '../../api/bundles';
import { errorMessage } from '../../api/client';

const MAX_LIST = 50;

function EntryTable({ title, refs }: { title: string; refs: EntryRef[] }) {
  if (refs.length === 0) return null;
  const shown = refs.slice(0, MAX_LIST);
  return (
    <>
      <Title headingLevel="h3" style={{ marginTop: '1rem', marginBottom: '0.5rem' }}>
        {title} ({refs.length})
      </Title>
      <Table aria-label={`${title} entries`} variant="compact">
        <Thead>
          <Tr>
            <Th>Entry Key</Th>
            <Th>Discriminator</Th>
          </Tr>
        </Thead>
        <Tbody>
          {shown.map((r, i) => (
            <Tr key={i}>
              <Td style={{ fontFamily: 'monospace', fontSize: '0.85em' }}>{r.entry_key}</Td>
              <Td>{r.discriminator}</Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
      {refs.length > MAX_LIST && (
        <p style={{ color: 'var(--pf-t--global--text--color--subtle)', marginTop: '0.5rem' }}>
          …and {refs.length - MAX_LIST} more (showing first {MAX_LIST}).
        </p>
      )}
    </>
  );
}

export default function BundleDiff() {
  const [result, setResult] = useState<DiffResult | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const aRef = useRef<HTMLInputElement>(null);
  const bRef = useRef<HTMLInputElement>(null);

  const handleDiff = async () => {
    const a = aRef.current?.files?.[0];
    const b = bRef.current?.files?.[0];
    if (!a || !b) {
      setError('Select both bundle A and bundle B.');
      return;
    }
    setLoading(true);
    setError('');
    setResult(null);
    try {
      setResult(await diffBundles(a, b));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Diff Bundles</Title>
      </PageSection>
      <PageSection>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1rem', maxWidth: 640 }}>
          <label>
            <strong>Bundle A</strong> (older / left):{' '}
            <input type="file" accept=".ahu" ref={aRef} />
          </label>
          <label>
            <strong>Bundle B</strong> (newer / right):{' '}
            <input type="file" accept=".ahu" ref={bRef} />
          </label>
          <div>
            <Button variant="primary" onClick={handleDiff} isLoading={loading} isDisabled={loading}>
              Compute Diff
            </Button>
          </div>
        </div>

        {error && <Alert variant="danger" title="Diff failed">{error}</Alert>}

        {result && (
          <>
            <Title headingLevel="h2" style={{ marginBottom: '1rem' }}>Summary</Title>
            <DescriptionList isHorizontal columnModifier={{ default: '2Col' }} style={{ maxWidth: 720, marginBottom: '1rem' }}>
              <DescriptionListGroup>
                <DescriptionListTerm>Entries in A</DescriptionListTerm>
                <DescriptionListDescription>{result.a_entry_count} (epochs {result.a_epochs.join(', ') || '—'})</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Entries in B</DescriptionListTerm>
                <DescriptionListDescription>{result.b_entry_count} (epochs {result.b_epochs.join(', ') || '—'})</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Added</DescriptionListTerm>
                <DescriptionListDescription><Label color="green">{result.added.length}</Label></DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Removed</DescriptionListTerm>
                <DescriptionListDescription><Label color="red">{result.removed.length}</Label></DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Changed</DescriptionListTerm>
                <DescriptionListDescription><Label color="orange">{result.changed.length}</Label></DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Unchanged</DescriptionListTerm>
                <DescriptionListDescription>{result.unchanged}</DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>

            <EntryTable title="Added" refs={result.added} />
            <EntryTable title="Removed" refs={result.removed} />
            <EntryTable title="Changed" refs={result.changed} />
          </>
        )}
      </PageSection>
    </>
  );
}
