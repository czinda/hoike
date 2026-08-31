import { useState, useEffect, useCallback } from 'react';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  Card,
  CardTitle,
  CardBody,
  Label,
  EmptyState,
  EmptyStateBody,
} from '@patternfly/react-core';
import { getGossip, type GossipStatus } from '../../api/gossip';
import { errorMessage } from '../../api/client';

export default function GossipPage() {
  const [gossip, setGossip] = useState<GossipStatus | null>(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      setGossip(await getGossip());
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (error) return <PageSection><Alert variant="danger" title={error} /></PageSection>;
  if (!gossip) return <PageSection><Spinner /></PageSection>;

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Gossip Cluster</Title>
      </PageSection>
      <PageSection>
        <Card>
          <CardTitle>Status</CardTitle>
          <CardBody>
            <Label color={gossip.enabled ? 'green' : 'grey'}>
              {gossip.enabled ? 'enabled' : 'disabled'}
            </Label>
            {gossip.message && (
              <p style={{ marginTop: '0.5rem' }}>{gossip.message}</p>
            )}
          </CardBody>
        </Card>
        {!gossip.enabled && (
          <EmptyState style={{ marginTop: '2rem' }}>
            <EmptyStateBody>
              Gossip is not enabled in the server configuration.
              Enable it by setting [gossip] enabled = true in hoike.toml.
            </EmptyStateBody>
          </EmptyState>
        )}
      </PageSection>
    </>
  );
}
