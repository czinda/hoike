import { useState, useEffect, useCallback } from 'react';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  Button,
  Card,
  CardTitle,
  CardBody,
  Grid,
  GridItem,
  Flex,
  FlexItem,
} from '@patternfly/react-core';
import { getStatus, type ServerStatus } from '../../api/status';
import { getConfig, type CaConfigInfo } from '../../api/config';
import { signCa, signAll } from '../../api/signing';
import { errorMessage } from '../../api/client';

export default function Signing() {
  const [status, setStatus] = useState<ServerStatus | null>(null);
  const [cas, setCas] = useState<CaConfigInfo[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [resultMsg, setResultMsg] = useState<{ type: 'success' | 'danger'; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [s, c] = await Promise.all([getStatus(), getConfig()]);
      setStatus(s);
      setCas(c.cas);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSignCa = async (label: string) => {
    setResultMsg(null);
    try {
      const res = await signCa(label);
      setResultMsg({ type: 'success', text: res.message });
    } catch (e) {
      setResultMsg({ type: 'danger', text: errorMessage(e) });
    }
  };

  const handleSignAll = async () => {
    setResultMsg(null);
    try {
      const res = await signAll();
      setResultMsg({ type: 'success', text: res.message });
    } catch (e) {
      setResultMsg({ type: 'danger', text: errorMessage(e) });
    }
  };

  if (loading) return <PageSection><Spinner /></PageSection>;
  if (error) return <PageSection><Alert variant="danger" title="Error">{error}</Alert></PageSection>;

  if (status?.mode === 'edge') {
    return (
      <>
        <PageSection><Title headingLevel="h1">Signing</Title></PageSection>
        <PageSection>
          <Alert variant="info" title="Not available">
            Signing operations are not available in edge mode. The server must be running in combined or signer mode.
          </Alert>
        </PageSection>
      </>
    );
  }

  return (
    <>
      <PageSection>
        <Flex>
          <FlexItem><Title headingLevel="h1">Signing</Title></FlexItem>
          <FlexItem align={{ default: 'alignRight' }}>
            <Button variant="primary" onClick={handleSignAll}>Sign All CAs</Button>
          </FlexItem>
        </Flex>
      </PageSection>
      <PageSection>
        {resultMsg && (
          <Alert variant={resultMsg.type} title={resultMsg.type === 'success' ? 'Success' : 'Error'} style={{ marginBottom: '1rem' }}>
            {resultMsg.text}
          </Alert>
        )}
        <Grid hasGutter>
          {cas.map(ca => (
            <GridItem span={4} key={ca.label}>
              <Card>
                <CardTitle>{ca.label}</CardTitle>
                <CardBody>
                  <p style={{ marginBottom: '0.5rem' }}>
                    Algorithm: {ca.sig_alg}<br />
                    Source: {ca.source_type ?? 'none'}<br />
                    Interval: {ca.batch_interval}s
                  </p>
                  <Button variant="secondary" onClick={() => handleSignCa(ca.label)}>
                    Sign Now
                  </Button>
                </CardBody>
              </Card>
            </GridItem>
          ))}
        </Grid>
      </PageSection>
    </>
  );
}
