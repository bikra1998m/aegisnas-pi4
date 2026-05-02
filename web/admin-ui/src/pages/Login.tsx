import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import api from '../api/client';

type AuthOptions = {
  token_login: boolean;
  sso: {
    enabled: boolean;
    provider: string;
    supported: boolean;
    redirect_url?: string;
    issuer_url?: string;
  };
};

export default function Login() {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [authOptions, setAuthOptions] = useState<AuthOptions | null>(null);
  const [loadingSSO, setLoadingSSO] = useState(true);
  const { login } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    let active = true;
    const hydrateSSOLogin = async () => {
      const hash = new URLSearchParams(window.location.hash.replace(/^#/, ''));
      const ssoToken = hash.get('sso_token');
      const authMode = hash.get('auth_mode');
      if (ssoToken) {
        try {
          if (!active) {
            return;
          }
          window.history.replaceState({}, document.title, '/login');
          await login(ssoToken, authMode === 'sso' ? 'sso' : 'token');
          navigate('/');
          return;
        } catch {
          if (!active) {
            return;
          }
          setError('Single sign-on session could not be validated.');
          window.history.replaceState({}, document.title, '/login');
        }
      }

      const params = new URLSearchParams(window.location.search);
      const ssoError = params.get('sso_error');
      if (ssoError && active) {
        setError(ssoError);
        window.history.replaceState({}, document.title, '/login');
      }
    };
    void hydrateSSOLogin();
    return () => {
      active = false;
    };
  }, [login, navigate]);

  useEffect(() => {
    let active = true;
    const loadAuthOptions = async () => {
      try {
        const { data } = await api.get('/auth/options');
        if (!active) {
          return;
        }
        setAuthOptions(data);
      } catch {
        if (!active) {
          return;
        }
        setAuthOptions(null);
      } finally {
        if (active) {
          setLoadingSSO(false);
        }
      }
    };
    void loadAuthOptions();
    return () => {
      active = false;
    };
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      await login(token, 'token');
      navigate('/');
    } catch (err) {
      setError('Invalid token');
    }
  };

  const handleSSOLogin = () => {
    window.location.href = '/api/v1/auth/sso/start';
  };

  const ssoEnabled = Boolean(authOptions?.sso?.enabled);
  const ssoSupported = Boolean(authOptions?.sso?.supported);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="bg-white p-8 rounded-lg shadow-md w-[28rem] max-w-full">
        <h1 className="text-2xl font-bold mb-6 text-center">AegisNAS Admin</h1>
        {ssoEnabled ? (
          <div className="mb-6 rounded-md border border-gray-200 bg-gray-50 p-4">
            <div className="text-sm font-medium text-gray-900">Single Sign-On</div>
            <div className="mt-1 text-sm text-gray-600">
              {ssoSupported
                ? `Sign in with your ${authOptions?.sso?.provider?.toUpperCase() || 'SSO'} identity and keep API tokens for break-glass access.`
                : 'Admin SSO is configured, but this provider is not supported by the current runtime.'}
            </div>
            <button
              type="button"
              onClick={handleSSOLogin}
              disabled={loadingSSO || !ssoSupported}
              className="mt-4 w-full rounded-md bg-gray-900 px-4 py-2 text-white disabled:cursor-not-allowed disabled:bg-gray-400"
            >
              Continue With Single Sign-On
            </button>
          </div>
        ) : null}

        {ssoEnabled ? <div className="mb-4 text-center text-xs uppercase tracking-wide text-gray-400">or use a token</div> : null}
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-gray-700 mb-2">API Token</label>
            <input
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter admin token"
              required
            />
          </div>
          {error && <p className="text-red-500 text-sm mb-4">{error}</p>}
          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-2 rounded-md hover:bg-blue-700 transition"
          >
            Sign In With Token
          </button>
        </form>
      </div>
    </div>
  );
}
