import { useState } from 'react';
import {
  ArrowRight, Check, Eye, EyeOff, Fingerprint, LockKeyhole,
  Shield, Sparkles, UserRound
} from 'lucide-react';
import { api } from '../api';

const initialForm = {
  displayName: '',
  username: '',
  email: '',
  password: '',
  confirmPassword: ''
};

export default function LoginScreen({ onAuthenticated }) {
  const [mode, setMode] = useState('signin');
  const [form, setForm] = useState(initialForm);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const update = event => {
    setForm(current => ({ ...current, [event.target.name]: event.target.value }));
  };

  const switchMode = nextMode => {
    setMode(nextMode);
    setError('');
    setForm(initialForm);
    setShowPassword(false);
  };

  const submit = async event => {
    event.preventDefault();
    setError('');
    if (mode === 'signup' && form.password !== form.confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      const session = mode === 'signin'
        ? await api.login(form.username.trim(), form.password)
        : await api.signup({
          displayName: form.displayName.trim(),
          username: form.username.trim(),
          email: form.email.trim(),
          password: form.password
        });
      onAuthenticated(session.user);
    } catch (authError) {
      setError(authError.message);
    } finally {
      setLoading(false);
    }
  };

  const canSubmit = mode === 'signin'
    ? form.username.trim() && form.password
    : form.displayName.trim() && form.username.trim() && form.email.trim()
      && form.password && form.confirmPassword;

  return (
    <main className="auth-page">
      <section className="auth-intro" aria-label="PatchLens introduction">
        <div className="auth-brand">
          <span className="brand-mark"><Shield size={20} /></span>
          <span>Patch<span>Lens</span></span>
        </div>
        <div className="auth-intro-copy">
          <span className="eyebrow"><Fingerprint size={13} /> Private security workspace</span>
          <h1>Security findings,<br /><span>made actionable.</span></h1>
          <p>Run authorized assessments, preserve scan history, and turn evidence into grounded remediation guidance.</p>
          <ul>
            <li><Check size={14} /> Non-invasive scanner</li>
            <li><Check size={14} /> Account-protected reports</li>
            <li><Check size={14} /> Gemma-powered guidance</li>
          </ul>
        </div>
        <p className="auth-intro-note">Evidence-led assessment for systems you own or are authorized to test.</p>
      </section>

      <section className="auth-panel" aria-labelledby="auth-title">
        <div className="auth-switch" role="tablist" aria-label="Account access">
          <button type="button" role="tab" aria-selected={mode === 'signin'} className={mode === 'signin' ? 'active' : ''} onClick={() => switchMode('signin')}>Sign in</button>
          <button type="button" role="tab" aria-selected={mode === 'signup'} className={mode === 'signup' ? 'active' : ''} onClick={() => switchMode('signup')}>Create account</button>
        </div>

        <div className="auth-heading">
          <span className="auth-icon">{mode === 'signin' ? <LockKeyhole size={18} /> : <UserRound size={18} />}</span>
          <div>
            <h2 id="auth-title">{mode === 'signin' ? 'Welcome back.' : 'Create your workspace.'}</h2>
            <p>{mode === 'signin' ? 'Enter your username or email to continue.' : 'Set up a secure PatchLens account in a minute.'}</p>
          </div>
        </div>

        <form className="auth-form" onSubmit={submit}>
          {mode === 'signup' && (
            <>
              <label htmlFor="auth-name">Full name</label>
              <input id="auth-name" name="displayName" type="text" autoComplete="name" value={form.displayName} onChange={update} disabled={loading} placeholder="Your name" required />
            </>
          )}

          <label htmlFor="auth-username">{mode === 'signin' ? 'Username or email' : 'Username'}</label>
          <input id="auth-username" name="username" type="text" autoComplete="username" value={form.username} onChange={update} disabled={loading} placeholder={mode === 'signin' ? 'you@example.com' : 'Choose a username'} required />

          {mode === 'signup' && (
            <>
              <label htmlFor="auth-email">Email address</label>
              <input id="auth-email" name="email" type="email" autoComplete="email" value={form.email} onChange={update} disabled={loading} placeholder="you@example.com" required />
            </>
          )}

          <label htmlFor="auth-password">Password</label>
          <div className="password-control">
            <input id="auth-password" name="password" type={showPassword ? 'text' : 'password'} autoComplete={mode === 'signin' ? 'current-password' : 'new-password'} value={form.password} onChange={update} disabled={loading} placeholder={mode === 'signup' ? '10+ characters, mixed case and number' : 'Enter your password'} required />
            <button type="button" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>
              {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
            </button>
          </div>

          {mode === 'signup' && (
            <>
              <label htmlFor="auth-confirm">Confirm password</label>
              <div className="password-control">
                <input id="auth-confirm" name="confirmPassword" type={showPassword ? 'text' : 'password'} autoComplete="new-password" value={form.confirmPassword} onChange={update} disabled={loading} placeholder="Repeat your password" required />
              </div>
            </>
          )}

          {error && <p className="auth-error" role="alert">{error}</p>}

          <button className="auth-submit" type="submit" disabled={loading || !canSubmit}>
            <span>{loading ? (mode === 'signin' ? 'Signing in…' : 'Creating account…') : (mode === 'signin' ? 'Sign in securely' : 'Create account')}</span>
            {!loading && <ArrowRight size={17} />}
          </button>
        </form>

        <p className="auth-security"><Sparkles size={13} /> Passwords are salted and hashed before storage.</p>
      </section>
    </main>
  );
}
