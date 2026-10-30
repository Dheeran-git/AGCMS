import { useState, type FormEvent } from 'react';
import { KeyRound } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { LogoMark } from '../components/LogoMark';
import { signIn } from '../lib/api';

/** Exchanges a tenant API key for a JWT session; the key itself is never stored. */
export function SignIn() {
  const [apiKey, setApiKey] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setPending(true);
    setError(null);
    try {
      await signIn(apiKey.trim());
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setPending(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-canvas px-4 text-fg-primary">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <LogoMark size={32} />
          <h1 className="mt-3 text-h2 text-fg-primary">Sign in to AGCMS</h1>
          <CardDescription>Enter your tenant API key. It is exchanged for a session token.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-3">
            <label htmlFor="api-key" className="text-label text-fg-muted">API key</label>
            <Input
              id="api-key"
              type="password"
              autoComplete="off"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="agcms_..."
              required
            />
            {error && <p role="alert" className="text-small text-status-danger">{error}</p>}
            <Button type="submit" variant="primary" className="w-full" disabled={pending || !apiKey.trim()}>
              <KeyRound className="mr-2 h-4 w-4" />
              {pending ? 'Signing in...' : 'Sign in'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
