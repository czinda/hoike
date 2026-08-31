import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  PageSection,
  Title,
  Spinner,
  Alert,
  Button,
  Label,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
  ActionGroup,
} from '@patternfly/react-core';
import { getConfig, type CaConfigInfo } from '../../api/config';
import { listCerts, type CertInfo } from '../../api/certs';
import { getRotation, signCa, rotateCa, type RotationStatus } from '../../api/signing';
import { fmtDuration } from '../../utils';
import { errorMessage } from '../../api/client';

interface CaDetailData {
  config: CaConfigInfo;
  cert: CertInfo | null;
  rotation: RotationStatus | null;
}

export default function CADetail() {
  const { label } = useParams<{ label: string }>();
  const [data, setData] = useState<CaDetailData | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [actionMsg, setActionMsg] = useState<{ type: 'success' | 'danger'; text: string } | null>(null);

  useEffect(() => {
    if (!label) return;
    setLoading(true);
    Promise.all([getConfig(), listCerts(), getRotation()])
      .then(([configResp, certsResp, rotationResp]) => {
        const ca = configResp.cas.find(c => c.label === label);
        if (!ca) {
          setError(`CA '${label}' not found`);
          return;
        }
        setData({
          config: ca,
          cert: certsResp.certs.find(c => c.ca_label === label) ?? null,
          rotation: rotationResp.rotation.find(r => r.ca_label === label) ?? null,
        });
      })
      .catch(e => setError(errorMessage(e)))
      .finally(() => setLoading(false));
  }, [label]);

  const handleSign = async () => {
    if (!label) return;
    setActionMsg(null);
    try {
      const res = await signCa(label);
      setActionMsg({ type: 'success', text: res.message });
    } catch (e) {
      setActionMsg({ type: 'danger', text: errorMessage(e) });
    }
  };

  const handleRotate = async () => {
    if (!label) return;
    setActionMsg(null);
    try {
      const res = await rotateCa(label);
      setActionMsg({ type: 'success', text: `Rotation command executed for ${res.ca_label}` });
    } catch (e) {
      setActionMsg({ type: 'danger', text: errorMessage(e) });
    }
  };

  if (loading) return <PageSection><Spinner /></PageSection>;
  if (error) return <PageSection><Alert variant="danger" title="Error">{error}</Alert></PageSection>;
  if (!data) return null;

  const { config: ca, cert, rotation } = data;

  return (
    <>
      <PageSection>
        <Link to="/cas" style={{ marginBottom: '0.5rem', display: 'inline-block' }}>Back to CAs</Link>
        <Title headingLevel="h1">CA: {ca.label}</Title>
      </PageSection>
      <PageSection>
        {actionMsg && (
          <Alert variant={actionMsg.type} title={actionMsg.type === 'success' ? 'Success' : 'Error'} style={{ marginBottom: '1rem' }}>
            {actionMsg.text}
          </Alert>
        )}

        <Title headingLevel="h2" style={{ marginBottom: '0.5rem' }}>Configuration</Title>
        <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: 640, marginBottom: '1.5rem' }}>
          <DescriptionListGroup>
            <DescriptionListTerm>Label</DescriptionListTerm>
            <DescriptionListDescription>{ca.label}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Signature Algorithm</DescriptionListTerm>
            <DescriptionListDescription>{ca.sig_alg}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Nonce Policy</DescriptionListTerm>
            <DescriptionListDescription>{ca.nonce_policy}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Completeness</DescriptionListTerm>
            <DescriptionListDescription>{ca.completeness}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Source Type</DescriptionListTerm>
            <DescriptionListDescription>{ca.source_type ?? '—'}</DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Signing Key</DescriptionListTerm>
            <DescriptionListDescription>
              <Label color={ca.has_signing_key ? 'green' : 'grey'}>{ca.has_signing_key ? 'Configured' : 'None'}</Label>
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Seal Key</DescriptionListTerm>
            <DescriptionListDescription>
              <Label color={ca.has_seal_key ? 'green' : 'grey'}>{ca.has_seal_key ? 'Configured' : 'None'}</Label>
            </DescriptionListDescription>
          </DescriptionListGroup>
        </DescriptionList>

        {cert && (
          <>
            <Title headingLevel="h2" style={{ marginBottom: '0.5rem' }}>Responder Certificate</Title>
            <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: 640, marginBottom: '1.5rem' }}>
              <DescriptionListGroup>
                <DescriptionListTerm>Subject</DescriptionListTerm>
                <DescriptionListDescription>{cert.subject}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Issuer</DescriptionListTerm>
                <DescriptionListDescription>{cert.issuer}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Days Remaining</DescriptionListTerm>
                <DescriptionListDescription>
                  <Label color={cert.is_expired ? 'red' : cert.days_remaining < 30 ? 'gold' : 'green'}>
                    {cert.is_expired ? 'Expired' : `${cert.days_remaining} days`}
                  </Label>
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>OCSP Signing EKU</DescriptionListTerm>
                <DescriptionListDescription>
                  <Label color={cert.has_ocsp_signing_eku ? 'green' : 'red'}>
                    {cert.has_ocsp_signing_eku ? 'Yes' : 'No'}
                  </Label>
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </>
        )}

        {rotation && (
          <>
            <Title headingLevel="h2" style={{ marginBottom: '0.5rem' }}>Key Rotation</Title>
            <DescriptionList isHorizontal columnModifier={{ default: '1Col' }} style={{ maxWidth: 640, marginBottom: '1.5rem' }}>
              <DescriptionListGroup>
                <DescriptionListTerm>Status</DescriptionListTerm>
                <DescriptionListDescription>
                  <Label color={rotation.status === 'ok' ? 'green' : rotation.status === 'renew_soon' ? 'gold' : 'red'}>
                    {rotation.status}
                  </Label>
                </DescriptionListDescription>
              </DescriptionListGroup>
              {rotation.expires_in_secs != null && (
                <DescriptionListGroup>
                  <DescriptionListTerm>Expires In</DescriptionListTerm>
                  <DescriptionListDescription>{fmtDuration(rotation.expires_in_secs)}</DescriptionListDescription>
                </DescriptionListGroup>
              )}
            </DescriptionList>
          </>
        )}

        <ActionGroup style={{ marginTop: '1rem' }}>
          <Button variant="primary" onClick={handleSign}>Trigger Sign</Button>
          <Button variant="secondary" onClick={handleRotate}>Run Rotation</Button>
        </ActionGroup>
      </PageSection>
    </>
  );
}
