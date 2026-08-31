import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  Label,
} from '@patternfly/react-core';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import { getConfig, type CaConfigInfo } from '../../api/config';
import { listCerts, type CertInfo } from '../../api/certs';
import { getRotation, type RotationStatus } from '../../api/signing';
import { errorMessage } from '../../api/client';

interface CaRow {
  config: CaConfigInfo;
  cert: CertInfo | null;
  rotation: RotationStatus | null;
}

function expiryColor(days: number): 'red' | 'gold' | 'green' {
  if (days < 7) return 'red';
  if (days < 30) return 'gold';
  return 'green';
}

function rotationColor(status: string): 'green' | 'gold' | 'red' | 'grey' {
  switch (status) {
    case 'ok': return 'green';
    case 'renew_soon': return 'gold';
    case 'expired': return 'red';
    default: return 'grey';
  }
}

export default function CAs() {
  const [rows, setRows] = useState<CaRow[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [configResp, certsResp, rotationResp] = await Promise.all([
        getConfig(),
        listCerts(),
        getRotation(),
      ]);
      const certMap = new Map(certsResp.certs.map(c => [c.ca_label, c]));
      const rotMap = new Map(rotationResp.rotation.map(r => [r.ca_label, r]));
      setRows(configResp.cas.map(ca => ({
        config: ca,
        cert: certMap.get(ca.label) ?? null,
        rotation: rotMap.get(ca.label) ?? null,
      })));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSection><Spinner /></PageSection>;
  if (error) return <PageSection><Alert variant="danger" title="Error">{error}</Alert></PageSection>;

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Certificate Authorities</Title>
      </PageSection>
      <PageSection>
        <Table aria-label="CA list" variant="compact">
          <Thead>
            <Tr>
              <Th>Label</Th>
              <Th>Sig Algorithm</Th>
              <Th>Nonce Policy</Th>
              <Th>Completeness</Th>
              <Th>Cert Expiry</Th>
              <Th>Rotation Status</Th>
            </Tr>
          </Thead>
          <Tbody>
            {rows.map(r => (
              <Tr key={r.config.label}>
                <Td><Link to={`/cas/${encodeURIComponent(r.config.label)}`}>{r.config.label}</Link></Td>
                <Td>{r.config.sig_alg}</Td>
                <Td>{r.config.nonce_policy}</Td>
                <Td>{r.config.completeness}</Td>
                <Td>
                  {r.cert ? (
                    <Label color={expiryColor(r.cert.days_remaining)}>
                      {r.cert.is_expired ? 'Expired' : `${r.cert.days_remaining}d`}
                    </Label>
                  ) : '—'}
                </Td>
                <Td>
                  {r.rotation ? (
                    <Label color={rotationColor(r.rotation.status)}>{r.rotation.status}</Label>
                  ) : '—'}
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </PageSection>
    </>
  );
}
