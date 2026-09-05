import { useState, useEffect, useCallback } from 'react';
import {
  PageSection,
  Title,
  Grid,
  GridItem,
  Card,
  CardTitle,
  CardBody,
  Spinner,
  Alert,
  Label,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
} from '@patternfly/react-core';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import { getStatus, type ServerStatus } from '../../api/status';
import { listBundles, type BundleInfo, type WindowInfo } from '../../api/bundles';
import { getRotation, type RotationStatus } from '../../api/signing';
import { fmtDuration } from '../../utils';
import { errorMessage } from '../../api/client';

interface DashboardData {
  status: ServerStatus;
  bundles: BundleInfo[];
  rotation: RotationStatus[];
}

function rotationColor(status: string): 'green' | 'yellow' | 'red' | 'grey' {
  switch (status) {
    case 'ok': return 'green';
    case 'renew_soon': return 'yellow';
    case 'expired': return 'red';
    default: return 'grey';
  }
}

type Freshness = 'fresh' | 'due_soon' | 'stale' | 'unknown';

// A bundle should be re-signed before its next_update_min. Past that point it is
// serving stale responses (red); within an hour of it is a warning (yellow).
// Mirrors design §9's "alert well before next_update hits 0".
const DUE_SOON_SECS = 3600;

function bundleFreshness(window: WindowInfo | null, nowSecs: number): {
  freshness: Freshness;
  ageSecs: number | null;
  secsToNext: number | null;
} {
  if (!window) return { freshness: 'unknown', ageSecs: null, secsToNext: null };
  const ageSecs = nowSecs - window.produced_at;
  const secsToNext = window.next_update_min - nowSecs;
  let freshness: Freshness;
  if (secsToNext <= 0) freshness = 'stale';
  else if (secsToNext < DUE_SOON_SECS) freshness = 'due_soon';
  else freshness = 'fresh';
  return { freshness, ageSecs, secsToNext };
}

function freshnessColor(f: Freshness): 'green' | 'yellow' | 'red' | 'grey' {
  switch (f) {
    case 'fresh': return 'green';
    case 'due_soon': return 'yellow';
    case 'stale': return 'red';
    default: return 'grey';
  }
}

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [status, bundlesResp, rotationResp] = await Promise.all([
        getStatus(),
        listBundles(),
        getRotation(),
      ]);
      setData({ status, bundles: bundlesResp.bundles, rotation: rotationResp.rotation });
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSection><Spinner /></PageSection>;
  if (error) return <PageSection><Alert variant="danger" title="Error">{error}</Alert></PageSection>;
  if (!data) return null;

  const { status, bundles, rotation } = data;

  const rotationMap = new Map(rotation.map(r => [r.ca_label, r]));

  const nowSecs = Math.floor(Date.now() / 1000);
  const freshnessByLabel = new Map(
    bundles.map(b => [b.ca_label, bundleFreshness(b.window, nowSecs)]),
  );
  const staleCount = [...freshnessByLabel.values()].filter(f => f.freshness === 'stale').length;
  const dueSoonCount = [...freshnessByLabel.values()].filter(f => f.freshness === 'due_soon').length;

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Dashboard</Title>
      </PageSection>
      <PageSection>
        <Grid hasGutter>
          <GridItem span={3}>
            <Card>
              <CardTitle>Server Mode</CardTitle>
              <CardBody>
                <DescriptionList isHorizontal>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Mode</DescriptionListTerm>
                    <DescriptionListDescription>
                      <Label color="blue">{status.mode}</Label>
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Version</DescriptionListTerm>
                    <DescriptionListDescription>{status.version}</DescriptionListDescription>
                  </DescriptionListGroup>
                </DescriptionList>
              </CardBody>
            </Card>
          </GridItem>
          <GridItem span={3}>
            <Card>
              <CardTitle>Total Entries</CardTitle>
              <CardBody style={{ fontSize: '2rem', fontWeight: 600 }}>
                {status.total_entries.toLocaleString()}
              </CardBody>
            </Card>
          </GridItem>
          <GridItem span={3}>
            <Card>
              <CardTitle>Bundle Count</CardTitle>
              <CardBody style={{ fontSize: '2rem', fontWeight: 600 }}>
                {status.bundle_count}
              </CardBody>
            </Card>
          </GridItem>
          <GridItem span={3}>
            <Card>
              <CardTitle>Uptime</CardTitle>
              <CardBody style={{ fontSize: '2rem', fontWeight: 600 }}>
                {fmtDuration(status.uptime_secs)}
              </CardBody>
            </Card>
          </GridItem>
        </Grid>

        {staleCount > 0 && (
          <Alert
            variant="danger"
            title={`${staleCount} bundle${staleCount > 1 ? 's' : ''} past next-update — serving stale responses`}
            style={{ marginTop: '2rem' }}
          />
        )}
        {staleCount === 0 && dueSoonCount > 0 && (
          <Alert
            variant="warning"
            title={`${dueSoonCount} bundle${dueSoonCount > 1 ? 's' : ''} due for re-signing within the hour`}
            style={{ marginTop: '2rem' }}
          />
        )}

        <Title headingLevel="h2" style={{ marginTop: '2rem' }}>CA Status</Title>
        <Table aria-label="CA status table" variant="compact">
          <Thead>
            <Tr>
              <Th>CA Label</Th>
              <Th>Epoch</Th>
              <Th>Completeness</Th>
              <Th>Bundle Age</Th>
              <Th>Next Update</Th>
              <Th>Rotation Status</Th>
            </Tr>
          </Thead>
          <Tbody>
            {bundles.map(b => {
              const rot = rotationMap.get(b.ca_label);
              const fresh = freshnessByLabel.get(b.ca_label);
              return (
                <Tr key={b.ca_label}>
                  <Td>{b.ca_label}</Td>
                  <Td>{b.epoch}</Td>
                  <Td>{b.completeness}</Td>
                  <Td>{fresh?.ageSecs != null ? fmtDuration(fresh.ageSecs) : '—'}</Td>
                  <Td>
                    {fresh && fresh.freshness !== 'unknown' && fresh.secsToNext != null ? (
                      <Label color={freshnessColor(fresh.freshness)}>
                        {fresh.freshness === 'stale'
                          ? `overdue ${fmtDuration(-fresh.secsToNext)}`
                          : `in ${fmtDuration(fresh.secsToNext)}`}
                      </Label>
                    ) : '—'}
                  </Td>
                  <Td>
                    {rot ? (
                      <Label color={rotationColor(rot.status)}>
                        {rot.status}
                        {rot.expires_in_secs != null && ` (${fmtDuration(rot.expires_in_secs)})`}
                      </Label>
                    ) : '—'}
                  </Td>
                </Tr>
              );
            })}
          </Tbody>
        </Table>
      </PageSection>
    </>
  );
}
