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
import { listBundles, type BundleInfo } from '../../api/bundles';
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

        <Title headingLevel="h2" style={{ marginTop: '2rem' }}>CA Status</Title>
        <Table aria-label="CA status table" variant="compact">
          <Thead>
            <Tr>
              <Th>CA Label</Th>
              <Th>Epoch</Th>
              <Th>Completeness</Th>
              <Th>Rotation Status</Th>
            </Tr>
          </Thead>
          <Tbody>
            {bundles.map(b => {
              const rot = rotationMap.get(b.ca_label);
              return (
                <Tr key={b.ca_label}>
                  <Td>{b.ca_label}</Td>
                  <Td>{b.epoch}</Td>
                  <Td>{b.completeness}</Td>
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
