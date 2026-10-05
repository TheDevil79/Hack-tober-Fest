import { useState } from 'react';
import { Eye, EyeOff, LockKeyhole, LogIn, Shield } from 'lucide-react';
import { api } from '../api';

export default function LoginScreen({ onAuthenticated }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const submit = async event => {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      const session = await api.login(username.trim(), password);
      onAuthenticated(session.user);
    } catch (loginError) {
      setError(loginError.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="login-page">
      <section className="login-card" aria-labelledby="login-title">
        <div className="login-brand">
          <span className="brand-mark"><Shield size={22} /></span>
          <span>Patch<span>Lens</span></span>
        </div>

        <div className="login-heading">
          <span className="eyebrow"><LockKeyhole size={13} /> Restricted workspace</span>
          <h1 id="login-title">Sign in to continue.</h1>
          <p>Use the credentials configured by your PatchLens administrator.</p>
        </div>

        <form className="login-form" onSubmit={submit}>
          <label htmlFor="login-username">Username</label>
          <input
            id="login-username"
            name="username"
            type="text"
            autoComplete="username"
            value={username}
            onChange={event => setUsername(event.target.value)}
            disabled={loading}
            required
          />

          <label htmlFor="login-password">Password</label>
          <div className="password-control">
            <input
              id="login-password"
              name="password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="current-password"
              value={password}
              onChange={event => setPassword(event.target.value)}
              disabled={loading}
              required
            />
            <button type="button" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>
              {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
            </button>
          </div>

          {error && <p className="login-error" role="alert">{error}</p>}

          <button className="login-submit" type="submit" disabled={loading || !username.trim() || !password}>
            <LogIn size={17} /> {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <p className="login-note">Credentials are verified by the server and are never stored in this browser.</p>
      </section>
    </main>
  );
}
