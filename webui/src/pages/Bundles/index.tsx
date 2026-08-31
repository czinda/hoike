import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  PageSection,
  Title,
  Button,
  Spinner,
  Alert,
  Flex,
  FlexItem,
} from '@patternfly/react-core';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import { listBundles, reloadBundles, type BundleInfo } from '../../api/bundles';
import { fmtTs } from '../../utils';
import { errorMessage } from '../../api/client';

export default function Bundles() {
  const [bundles, setBundles] = useState<BundleInfo[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [reloadMsg, setReloadMsg] = useState<{ type: 'success' | 'danger'; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const resp = await listBundles();
      setBundles(resp.bundles);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleReload = async () => {
    setReloadMsg(null);
    try {
      const result = await reloadBundles();
      setReloadMsg({ type: 'success', text: `Reloaded: ${result.bundle_count} bundles, ${result.total_entries} entries` });
      load();
    } catch (e) {
      setReloadMsg({ type: 'danger', text: errorMessage(e) });
    }
  };

  if (loading) return <PageSection><Spinner /></PageSection>;
  if (error) return <PageSection><Alert variant="danger" title="Error">{error}</Alert></PageSection>;

  return (
    <>
      <PageSection>
        <Flex>
          <FlexItem><Title headingLevel="h1">Bundles</Title></FlexItem>
          <FlexItem align={{ default: 'alignRight' }}>
            <Button variant="secondary" onClick={handleReload}>Reload Bundles</Button>
          </FlexItem>
        </Flex>
      </PageSection>
      <PageSection>
        {reloadMsg && (
          <Alert variant={reloadMsg.type} title={reloadMsg.type === 'success' ? 'Reload successful' : 'Reload failed'} style={{ marginBottom: '1rem' }}>
            {reloadMsg.text}
          </Alert>
        )}
        <Table aria-label="Bundle list" variant="compact">
          <Thead>
            <Tr>
              <Th>CA Label</Th>
              <Th>Epoch</Th>
              <Th>Entry Count</Th>
              <Th>Completeness</Th>
              <Th>Produced At</Th>
              <Th>Next Update</Th>
            </Tr>
          </Thead>
          <Tbody>
            {bundles.map(b => (
              <Tr key={b.ca_label}>
                <Td><Link to={`/bundles/${encodeURIComponent(b.ca_label)}`}>{b.ca_label}</Link></Td>
                <Td>{b.epoch}</Td>
                <Td>{b.entry_count}</Td>
                <Td>{b.completeness}</Td>
                <Td>{b.window ? fmtTs(b.window.produced_at) : '—'}</Td>
                <Td>{b.window ? fmtTs(b.window.next_update_min) : '—'}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </PageSection>
    </>
  );
}
