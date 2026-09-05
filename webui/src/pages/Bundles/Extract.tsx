import { useState, useRef } from 'react';
import {
  PageSection,
  Title,
  Button,
  Alert,
  TextInput,
  FormGroup,
  ClipboardCopy,
  ClipboardCopyVariant,
} from '@patternfly/react-core';
import { extractEntry, type ExtractResult } from '../../api/bundles';
import { errorMessage } from '../../api/client';

export default function BundleExtract() {
  const [result, setResult] = useState<ExtractResult | null>(null);
  const [certid, setCertid] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const certidValid = /^[0-9a-fA-F]{64}$/.test(certid.trim());

  const handleExtract = async () => {
    const file = fileRef.current?.files?.[0];
    if (!file) {
      setError('Select a bundle file.');
      return;
    }
    if (!certidValid) {
      setError('CertID must be 64 hex characters (SHA-256 of the DER CertID).');
      return;
    }
    setLoading(true);
    setError('');
    setResult(null);
    try {
      setResult(await extractEntry(file, certid.trim()));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <PageSection>
        <Title headingLevel="h1">Extract Entry</Title>
      </PageSection>
      <PageSection>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '1rem', maxWidth: 720 }}>
          <div>
            <strong>Bundle:</strong> <input type="file" accept=".ahu" ref={fileRef} />
          </div>
          <FormGroup label="Entry key (CertID hash)" fieldId="certid">
            <TextInput
              id="certid"
              value={certid}
              onChange={(_e, v) => setCertid(v)}
              placeholder="64 hex chars — SHA-256 of the DER CertID"
              validated={certid === '' ? 'default' : certidValid ? 'success' : 'error'}
            />
          </FormGroup>
          <div>
            <Button variant="primary" onClick={handleExtract} isLoading={loading} isDisabled={loading}>
              Extract
            </Button>
          </div>
        </div>

        {error && <Alert variant="danger" title="Extract failed">{error}</Alert>}

        {result && !result.found && (
          <Alert variant="warning" title="Not found">
            No entry for that key exists in the uploaded bundle.
          </Alert>
        )}

        {result && result.found && result.response_b64 && (
          <>
            <Alert variant="success" title={`Found — ${result.length} bytes`} style={{ marginBottom: '1rem' }} />
            <Title headingLevel="h3" style={{ marginBottom: '0.5rem' }}>OCSP response (base64 DER)</Title>
            <ClipboardCopy isReadOnly variant={ClipboardCopyVariant.expansion} hoverTip="Copy" clickTip="Copied">
              {result.response_b64}
            </ClipboardCopy>
          </>
        )}
      </PageSection>
    </>
  );
}
