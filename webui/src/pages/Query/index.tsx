import { useState } from 'react';
import {
  PageSection,
  Title,
  Card,
  CardTitle,
  CardBody,
  Form,
  FormGroup,
  TextInput,
  ActionGroup,
  Button,
  Alert,
  Label,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
} from '@patternfly/react-core';
import { queryOcsp, type QueryResult } from '../../api/query';
import { errorMessage } from '../../api/client';

export default function QueryPage() {
  const [serial, setSerial] = useState('');
  const [issuerNameHash, setIssuerNameHash] = useState('');
  const [issuerKeyHash, setIssuerKeyHash] = useState('');
  const [prefer, setPrefer] = useState('');
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const resp = await queryOcsp({
        serial,
        issuer_name_hash: issuerNameHash,
        issuer_key_hash: issuerKeyHash,
        prefer: prefer ? prefer.split(',').map(s => s.trim()) : [],
      });
      setResult(resp);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">OCSP Query</Title>
      </PageSection>
      <PageSection>
        <Card>
          <CardTitle>Query Parameters</CardTitle>
          <CardBody>
            <Form onSubmit={e => { e.preventDefault(); handleSubmit(); }}>
              <FormGroup label="Serial Number (hex)" isRequired fieldId="serial">
                <TextInput id="serial" value={serial} onChange={(_e, v) => setSerial(v)} placeholder="0A1B2C3D" />
              </FormGroup>
              <FormGroup label="Issuer Name Hash (hex)" isRequired fieldId="inh">
                <TextInput id="inh" value={issuerNameHash} onChange={(_e, v) => setIssuerNameHash(v)} />
              </FormGroup>
              <FormGroup label="Issuer Key Hash (hex)" isRequired fieldId="ikh">
                <TextInput id="ikh" value={issuerKeyHash} onChange={(_e, v) => setIssuerKeyHash(v)} />
              </FormGroup>
              <FormGroup label="Preferred Algorithms (comma-separated)" fieldId="prefer">
                <TextInput id="prefer" value={prefer} onChange={(_e, v) => setPrefer(v)} placeholder="ml-dsa-87, ecdsa-p256" />
              </FormGroup>
              <ActionGroup>
                <Button variant="primary" type="submit" isDisabled={loading || !serial || !issuerNameHash || !issuerKeyHash}>
                  {loading ? 'Querying...' : 'Query'}
                </Button>
              </ActionGroup>
            </Form>
          </CardBody>
        </Card>

        {error && <Alert variant="danger" title={error} style={{ marginTop: '1rem' }} />}

        {result && (
          <Card style={{ marginTop: '1rem' }}>
            <CardTitle>Result</CardTitle>
            <CardBody>
              <DescriptionList isHorizontal>
                <DescriptionListGroup>
                  <DescriptionListTerm>Found</DescriptionListTerm>
                  <DescriptionListDescription>
                    <Label color={result.found ? 'green' : 'red'}>{result.found ? 'yes' : 'no'}</Label>
                  </DescriptionListDescription>
                </DescriptionListGroup>
                {result.ca_label && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>CA Label</DescriptionListTerm>
                    <DescriptionListDescription>{result.ca_label}</DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {result.response_bytes_len != null && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Response Size</DescriptionListTerm>
                    <DescriptionListDescription>{result.response_bytes_len} bytes</DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {result.nonce_policy && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Nonce Policy</DescriptionListTerm>
                    <DescriptionListDescription>{result.nonce_policy}</DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {result.message && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Message</DescriptionListTerm>
                    <DescriptionListDescription>{result.message}</DescriptionListDescription>
                  </DescriptionListGroup>
                )}
              </DescriptionList>
            </CardBody>
          </Card>
        )}
      </PageSection>
    </>
  );
}
