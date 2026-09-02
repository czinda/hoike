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
  Button,
  Flex,
  FlexItem,
  EmptyState,
  EmptyStateBody,
} from '@patternfly/react-core';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import {
  getGossip,
  type GossipStatus,
  type MemberState,
  type GossipGeneration,
} from '../../api/gossip';
import { errorMessage } from '../../api/client';

// SWIM liveness: is the node reachable? Independent of data freshness.
function memberStateColor(s: MemberState): 'green' | 'yellow' | 'red' | 'grey' {
  switch (s) {
    case 'alive': return 'green';
    case 'suspect': return 'yellow';
    case 'down': return 'red';
    default: return 'grey';
  }
}

// A node not heard from in this long is treated as a warning even if its last
// announcement was current — the announcement may simply have stopped arriving.
const GEN_STALE_AGE_SECS = 300;

// Generation freshness combines two signals: how far behind the newest epoch
// this node is (hard staleness → red), and how long since we last heard it
// announce (soft staleness → yellow).
function generationColor(g: GossipGeneration): 'green' | 'yellow' | 'red' | 'grey' {
  if (g.epochs_behind > 0) return 'red';
  if (g.age_secs > GEN_STALE_AGE_SECS) return 'yellow';
  return 'green';
}

function shortHex(hex: string, chars = 16): string {
  return hex.length > chars ? `${hex.slice(0, chars)}…` : hex;
}

function formatAge(secs: number): string {
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
}

export default function GossipPage() {
  const [gossip, setGossip] = useState<GossipStatus | null>(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      setGossip(await getGossip());
      setError('');
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  // SWIM state and generation propagation both evolve over time — poll so the
  // fleet view reflects membership changes and freshly arrived announcements.
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  if (error) return <PageSection><Alert variant="danger" title={error} /></PageSection>;
  if (!gossip) return <PageSection><Spinner /></PageSection>;

  const members = gossip.members ?? [];
  const generations = gossip.generations ?? [];
  const behindCount = generations.filter(g => g.epochs_behind > 0).length;

  return (
    <>
      <PageSection>
        <Flex>
          <FlexItem grow={{ default: 'grow' }}>
            <Title headingLevel="h1">Gossip Cluster</Title>
          </FlexItem>
          <FlexItem>
            <Button variant="secondary" onClick={load}>Refresh</Button>
          </FlexItem>
        </Flex>
      </PageSection>

      <PageSection>
        <Card>
          <CardTitle>Status</CardTitle>
          <CardBody>
            <Flex spaceItems={{ default: 'spaceItemsMd' }} alignItems={{ default: 'alignItemsCenter' }}>
              <FlexItem>
                <Label color={gossip.enabled ? 'green' : 'grey'}>
                  {gossip.enabled ? 'enabled' : 'disabled'}
                </Label>
              </FlexItem>
              {gossip.self && (
                <FlexItem>
                  this node: <strong>{gossip.self.name}</strong> ({gossip.self.addr})
                </FlexItem>
              )}
              {gossip.enabled && (
                <FlexItem>
                  {members.length} member{members.length === 1 ? '' : 's'}
                </FlexItem>
              )}
              {behindCount > 0 && (
                <FlexItem>
                  <Label color="red">{behindCount} node/scope behind</Label>
                </FlexItem>
              )}
            </Flex>
            {gossip.message && (
              <p style={{ marginTop: '0.5rem' }}>{gossip.message}</p>
            )}
          </CardBody>
        </Card>

        {!gossip.enabled && (
          <EmptyState style={{ marginTop: '2rem' }}>
            <EmptyStateBody>
              {gossip.configured
                ? 'Gossip is enabled in configuration but no gossip node is running.'
                : 'Gossip is not enabled in the server configuration. Enable it by setting [gossip] enabled = true in hoike.toml.'}
            </EmptyStateBody>
          </EmptyState>
        )}

        {gossip.enabled && (
          <Card style={{ marginTop: '1.5rem' }}>
            <CardTitle>Members</CardTitle>
            <CardBody>
              <Table aria-label="Gossip members" variant="compact">
                <Thead>
                  <Tr>
                    <Th>Node</Th>
                    <Th>Address</Th>
                    <Th>State</Th>
                    <Th>Incarnation</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {members.map((m) => (
                    <Tr key={`${m.name}@${m.addr}`}>
                      <Td dataLabel="Node">
                        {m.name || <em>(unnamed)</em>}
                        {m.is_self && <Label isCompact color="blue" style={{ marginLeft: '0.5rem' }}>self</Label>}
                      </Td>
                      <Td dataLabel="Address">{m.addr}</Td>
                      <Td dataLabel="State">
                        <Label color={memberStateColor(m.state)}>{m.state}</Label>
                      </Td>
                      <Td dataLabel="Incarnation">{m.incarnation}</Td>
                    </Tr>
                  ))}
                  {members.length === 0 && (
                    <Tr>
                      <Td colSpan={4}><em>No members known yet.</em></Td>
                    </Tr>
                  )}
                </Tbody>
              </Table>
            </CardBody>
          </Card>
        )}

        {gossip.enabled && (
          <Card style={{ marginTop: '1.5rem' }}>
            <CardTitle>Generation Propagation</CardTitle>
            <CardBody>
              <Table aria-label="Gossip generations" variant="compact">
                <Thead>
                  <Tr>
                    <Th>Origin node</Th>
                    <Th>Producer</Th>
                    <Th>Issuer key hash</Th>
                    <Th>Epoch</Th>
                    <Th>Behind</Th>
                    <Th>Last heard</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {generations.map((g) => (
                    <Tr key={`${g.origin_node}|${g.producer_id}|${g.issuer_key_hash}`}>
                      <Td dataLabel="Origin node">{g.origin_node || <em>(unknown)</em>}</Td>
                      <Td dataLabel="Producer">{g.producer_id}</Td>
                      <Td dataLabel="Issuer key hash">
                        <code>{shortHex(g.issuer_key_hash)}</code>
                      </Td>
                      <Td dataLabel="Epoch">
                        <Label color={generationColor(g)}>{g.epoch}</Label>
                      </Td>
                      <Td dataLabel="Behind">
                        {g.epochs_behind > 0 ? `−${g.epochs_behind}` : '—'}
                      </Td>
                      <Td dataLabel="Last heard">{formatAge(g.age_secs)}</Td>
                    </Tr>
                  ))}
                  {generations.length === 0 && (
                    <Tr>
                      <Td colSpan={6}><em>No generation announcements received yet.</em></Td>
                    </Tr>
                  )}
                </Tbody>
              </Table>
            </CardBody>
          </Card>
        )}
      </PageSection>
    </>
  );
}
