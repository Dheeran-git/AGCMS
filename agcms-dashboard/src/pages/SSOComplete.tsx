import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../stores/auth';
import { LogoMark } from '../components/LogoMark';

type Phase = 'parsing' | 'ok' | 'error';

/**
 * Unauthenticated landing page the auth service redirects to after a
 * successful WorkOS SSO exchange. The access/refresh tokens arrive in
 * the URL fragment (never in a query string or header) so they never hit
 * a backend log or the browser's URL-bar history.
 */
export function SSOComplete() {
  const navigate = useNavigate();
  const setTokens = useAuthStore((s) => s.setTokens);
  const [phase, setPhase] = useState<Phase>('parsing');
  const [error, setError] = useState<string>('');

  useEffect(() => {
    const hash = window.location.hash.startsWith('#')
      ? window.location.hash.slice(1)
      : window.location.hash;

    if (!hash) {
      setPhase('error');
      setError('Missing SSO response — no tokens found in URL fragment.');
      return;
    }

    const params = new URLSearchParams(hash);
    const access = params.get('access_token');
    const refresh = params.get('refresh_token');
    if (!access || !refresh) {
      setPhase('error');
      setError('Incomplete SSO response — access_token or refresh_token missing.');
      return;
    }

    setTokens(access, refresh);
    // Remove tokens from the URL so a refresh or back-button doesn't re-apply them.
    window.history.replaceState(null, '', '/auth/sso/complete');
    setPhase('ok');
    const t = window.setTimeout(() => navigate('/', { replace: true }), 600);
    return () => window.clearTimeout(t);
  }, [navigate, setTokens]);

  return (
    <div className="min-h-screen bg-bg-primary text-fg-primary flex items-center justify-center">
      <div className="max-w-md w-full px-6 py-10 space-y-6 text-center">
        <div className="flex justify-center">
          <LogoMark />
        </div>
        {phase === 'parsing' && (
          <>
            <h1 className="text-h1">Completing sign-in…</h1>
            <p className="text-small text-fg-muted">
              Exchanging your SSO response for an AGCMS session.
            </p>
          </>
        )}
        {phase === 'ok' && (
          <>
            <h1 className="text-h1">Signed in</h1>
            <p className="text-small text-fg-muted">
              Redirecting to your dashboard…
            </p>
          </>
        )}
        {phase === 'error' && (
          <>
            <h1 className="text-h1 text-status-danger">Sign-in failed</h1>
            <p className="text-small text-fg-muted">{error}</p>
            <p className="text-small text-fg-muted">
              Please retry from your corporate SSO portal, or contact your
              tenant administrator.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
