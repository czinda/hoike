import { useState, useEffect, useCallback } from 'react';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  Card,
  CardTitle,
  CardBody,
  CodeBlock,
  CodeBlockCode,
} from '@patternfly/react-core';
import { getConfig } from '../../api/config';
import { errorMessage } from '../../api/client';

export default function ConfigPage() {
  const [config, setConfig] = useState<unknown>(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      setConfig(await getConfig());
    } catch (e) {
      setError(errorMessage(e));
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (error) return <PageSection><Alert variant="danger" title={error} /></PageSection>;
  if (!config) return <PageSection><Spinner /></PageSection>;

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Running Configuration</Title>
        <p style={{ color: '#6a6e73', marginTop: '0.25rem' }}>
          Read-only view of the current server config. Passwords and keys are redacted.
        </p>
      </PageSection>
      <PageSection>
        <Card>
          <CardTitle>Config</CardTitle>
          <CardBody>
            <CodeBlock>
              <CodeBlockCode>
                {JSON.stringify(config, null, 2)}
              </CodeBlockCode>
            </CodeBlock>
          </CardBody>
        </Card>
      </PageSection>
    </>
  );
}
