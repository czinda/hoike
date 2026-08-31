import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  LoginPage as PfLoginPage,
  LoginForm,
  Alert,
} from '@patternfly/react-core';
import { login } from '../api/session';
import { useAuth } from './AuthContext';
import { errorMessage } from '../api/client';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { setAuth } = useAuth();
  const navigate = useNavigate();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const resp = await login({ name: username, password });
      setAuth(resp.session_token, resp.role, resp.operator, resp.expires_in_secs);
      navigate('/');
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <PfLoginPage loginTitle="hoike OCSP" loginSubtitle="Sign in to the admin console">
      {error && (
        <Alert variant="danger" title={error} isInline style={{ marginBottom: '1rem' }} />
      )}
      <LoginForm
        usernameLabel="Username"
        usernameValue={username}
        onChangeUsername={(_e, v) => setUsername(v)}
        passwordLabel="Password"
        passwordValue={password}
        onChangePassword={(_e, v) => setPassword(v)}
        onLoginButtonClick={handleSubmit}
        loginButtonLabel={loading ? 'Signing in...' : 'Sign in'}
        isLoginButtonDisabled={loading}
      />
    </PfLoginPage>
  );
}
