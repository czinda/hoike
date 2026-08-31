import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
} from '@patternfly/react-core';
import { getBundleDetail, type BundleDetail as BundleDetailType } from '../../api/bundles';
import { errorMessage } from '../../api/client';

export default function BundleDetail() {
  const { label } = useParams<{ label: string }>();
  const [data, setData] = useState<BundleDetailType | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!label) return;
    setLoading(true);
    getBundleDetail(label)
      .then(setData)
      .catch(e => setError(errorMessage(e)))
      .finally(() => setLoading(false));
  }, [label]);

  if (loading) return <PageSection><Spinner /></PageSection>;
  if (error) return <PageSection><Alert variant="danger" title="Error">{error}</Alert></PageSection>;
  if (!data) return null;

  return (
    <>
      <PageSection>
        <Link to="/bundles" style={{ marginBottom: '0.5rem', display: 'inline-block' }}>Back to Bundles</Link>
        <Title headingLevel="h1">Bundle: {data.ca_label}</Title>
      </PageSection>
      <PageSection>
        <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: 640 }}>
          <DescriptionListGroup>
            <DescriptionListTerm>CA Label</DescriptionListTerm>
            <DescriptionListDescription>{data.ca_label}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Epoch</DescriptionListTerm>
            <DescriptionListDescription>{data.epoch}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Completeness</DescriptionListTerm>
            <DescriptionListDescription>{data.completeness}</DescriptionListDescription>
          </DescriptionListGroup>
        </DescriptionList>
      </PageSection>
    </>
  );
}
