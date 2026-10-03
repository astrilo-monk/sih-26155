import { useState } from 'react';
import { Notice } from '../components/ui/primitives';
import { signIn, signOut, signUp, useAccount } from '../lib/account';

// Sign-in is optional: everything works as a guest. It only decides where taught knowledge is kept.

function SignInForm({ onDone }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  const run = (create) => async (event) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      if (create && await signUp(email, password)) {
        setMessage({ ok: true, text: 'Check your email and open the link we sent, then sign in.' });
      } else {
        if (!create) await signIn(email, password);
        onDone();
      }
    } catch (err) {
      setMessage({ ok: false, text: err.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="account-form" onSubmit={run(false)} aria-label="Sign in">
      <label className="field">
        <span className="field-label">Email</span>
        <input className="input" type="email" required autoComplete="email" value={email}
               onChange={(e) => setEmail(e.target.value)} />
      </label>
      <label className="field">
        <span className="field-label">Password</span>
        <input className="input" type="password" required minLength={6} autoComplete="current-password"
               value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      {message && <p className={message.ok ? 'small' : 'field-error'} role="status">{message.text}</p>}
      <div className="account-actions">
        <button type="submit" className="btn btn-sm" disabled={busy}>Sign in</button>
        <button type="button" className="btn btn-sm btn-outline" disabled={busy || !email || password.length < 6}
                onClick={run(true)}>Create account</button>
        <button type="button" className="btn btn-quiet btn-sm" onClick={onDone}>Cancel</button>
      </div>
    </form>
  );
}

export function AccountBox() {
  const { enabled, user } = useAccount();
  const [open, setOpen] = useState(false);
  if (!enabled) return null;
  return (
    <div className="account">
      {user ? (
        <>
          <span className="small muted">{user.email}</span>
          <button type="button" className="btn btn-sm btn-outline" onClick={() => signOut()}>Sign out</button>
        </>
      ) : (
        <>
          <span className="small muted">Guest</span>
          <button type="button" className="btn btn-sm btn-outline" aria-expanded={open}
                  onClick={() => setOpen((v) => !v)}>Sign in</button>
        </>
      )}
      {open && !user && <SignInForm onDone={() => setOpen(false)} />}
    </div>
  );
}

// Shown wherever something is taught or listed, until the person signs in
export function GuestNotice() {
  const { enabled, user } = useAccount();
  if (!enabled || user) return null;
  return (
    <Notice kind="warning" label="Not signed in">
      <strong>What you teach as a guest is not saved.</strong>
      <span>
        It stays on the server only until the server restarts (on the free host, after about 15 minutes with no
        visitors), and only this browser can see it. Sign in to keep what you teach in your own account, where no
        one else can read it.
      </span>
    </Notice>
  );
}
