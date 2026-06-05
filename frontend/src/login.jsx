import React from "react";
import { Icons } from "./icons";
/* ─────────────────────────────────────────────────────────────────
 * Login flow
 *
 *   step:credentials  → step:mfa  → step:success  → onLogin()
 *   step:webauthn (alt)  ─┘
 *
 * Real states: idle, submitting, error per step.
 * Demo creds:  any LFPM.users[].email   password "demo"   MFA "123456"
 * ───────────────────────────────────────────────────────────────── */

const { useState: useStateL, useEffect: useEffectL, useRef: useRefL } = React;

const DEMO_PASSWORD = 'demo';
const DEMO_MFA_CODE = '123456';

function Login({ onLogin, theme, onToggleTheme }) {
  const I = window.Icons;
  const [step, setStep]         = useStateL('credentials');     // credentials | mfa | webauthn | success
  const [pwFallback, setPwFallback] = useStateL(false);          // reveal email+password fallback form
  const [email, setEmail]       = useStateL('hamza@lumina-fpm.local');
  const [password, setPassword] = useStateL('');
  const [pwShow, setPwShow]     = useStateL(false);
  const [mfa, setMfa]           = useStateL('');
  const [pwErr, setPwErr]       = useStateL('');
  const [mfaErr, setMfaErr]     = useStateL('');
  const [submitting, setSubmitting] = useStateL(false);
  const [resolvedUser, setResolvedUser] = useStateL(null);
  const [attempts, setAttempts] = useStateL(0);
  const [log, setLog] = useStateL([
    { t:'14:31:50', kind:'info', text:'auth-gw · awaiting credentials · session pre-auth-3a91' },
    { t:'14:31:50', kind:'ok',   text:'tls · 1.3 · ecdhe-x25519 · acme org-2 · pin ok' },
    { t:'14:31:50', kind:'info', text:'source · 102.43.18.4 · CAI · cairo · score 12 (trusted)' },
    { t:'14:31:50', kind:'info', text:'auth-gw · webauthn primary · password + totp fallback ready' },
  ]);

  const mfaInputs = useRefL([]);

  const append = (entry) => setLog(l => [...l, { t: new Date().toISOString().slice(11, 19), ...entry }]);

  const userByEmail = (em) =>
    window.LFPM.users.find(u => u.email.toLowerCase() === em.toLowerCase());

  /* ── Initial form submit dispatcher ───────────────────────────── */
  /* security key is the primary path; Enter triggers it unless the
     password fallback form is revealed. */
  const handlePrimarySubmit = (e) => {
    e?.preventDefault();
    if (pwFallback) handleCredentials(e);
    else handleWebauthn();
  };

  /* ── Submit credentials ───────────────────────────────────────── */
  const handleCredentials = async (e) => {
    e?.preventDefault();
    setPwErr('');
    if (!email || !password) {
      setPwErr('Email and password are both required.');
      return;
    }
    setSubmitting(true);
    append({ kind:'info', text:`authn · POST /v1/auth/password · ${email}` });

    await new Promise(r => setTimeout(r, 600));

    const u = userByEmail(email);
    if (!u || password !== DEMO_PASSWORD) {
      setSubmitting(false);
      const n = attempts + 1;
      setAttempts(n);
      const remaining = Math.max(0, 5 - n);
      setPwErr(
        !u
          ? `No account matches ${email}.`
          : `Wrong password. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining before lockout.`
      );
      append({ kind:'err', text:`authn · 401 · invalid_credentials · attempt ${n}/5` });
      return;
    }

    append({ kind:'ok', text:`authn · primary factor verified · subj ${u.id} · role ${u.role}` });
    await new Promise(r => setTimeout(r, 250));
    append({ kind:'info', text:'mfa · totp challenge issued · timeout 60s · code expected 6 digits' });
    setResolvedUser(u);
    setSubmitting(false);
    setStep('mfa');
    /* focus first MFA box on next tick */
    setTimeout(() => mfaInputs.current[0]?.focus(), 50);
  };

  /* ── Submit MFA ───────────────────────────────────────────────── */
  const handleMfa = async (e) => {
    e?.preventDefault();
    setMfaErr('');
    if (mfa.length !== 6) {
      setMfaErr('Enter the 6-digit code from your authenticator.');
      return;
    }
    setSubmitting(true);
    append({ kind:'info', text:`mfa · POST /v1/auth/mfa · code ${mfa.replace(/./g, '·')}` });

    await new Promise(r => setTimeout(r, 700));

    if (mfa !== DEMO_MFA_CODE) {
      setSubmitting(false);
      setMfaErr('That code is invalid or expired. Try 123456 for the demo.');
      append({ kind:'err', text:'mfa · 401 · invalid_code · attempt 1/3' });
      return;
    }

    append({ kind:'ok',   text:'mfa · totp verified · authenticator yubico-otp-fallback' });
    append({ kind:'ok',   text:'session · jwt minted · ttl 30m · scope soc:full' });
    append({ kind:'info', text:`redirecting · ${resolvedUser.role}:dashboard` });
    setStep('success');
    await new Promise(r => setTimeout(r, 1100));
    onLogin(resolvedUser);
  };

  /* ── WebAuthn alt path ────────────────────────────────────────── */
  const handleWebauthn = async () => {
    setSubmitting(true);
    append({ kind:'info', text:'authn · POST /v1/auth/webauthn · invoking authenticator' });
    setStep('webauthn');
    await new Promise(r => setTimeout(r, 1200));
    append({ kind:'ok', text:'authn · webauthn assertion · userVerified=true · transport=usb' });
    append({ kind:'ok', text:'session · jwt minted · ttl 30m · scope soc:full' });
    const u = userByEmail(email) || window.LFPM.users[0];
    setResolvedUser(u);
    append({ kind:'info', text:`redirecting · ${u.role}:dashboard` });
    setStep('success');
    await new Promise(r => setTimeout(r, 900));
    onLogin(u);
  };

  /* ── MFA digit input handling ─────────────────────────────────── */
  const onMfaDigit = (i, val) => {
    const cleaned = val.replace(/\D/g, '');
    if (!cleaned) {
      setMfa(prev => prev.slice(0, i) + prev.slice(i + 1));
      return;
    }
    const ch = cleaned[cleaned.length - 1];
    setMfa(prev => {
      const arr = prev.split('');
      arr[i] = ch;
      return arr.join('').slice(0, 6);
    });
    if (i < 5) mfaInputs.current[i + 1]?.focus();
  };
  const onMfaKeyDown = (i, e) => {
    if (e.key === 'Backspace' && !mfa[i] && i > 0) mfaInputs.current[i - 1]?.focus();
    if (e.key === 'ArrowLeft'  && i > 0) mfaInputs.current[i - 1]?.focus();
    if (e.key === 'ArrowRight' && i < 5) mfaInputs.current[i + 1]?.focus();
  };
  const onMfaPaste = (e) => {
    const txt = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
    if (!txt) return;
    e.preventDefault();
    setMfa(txt);
    mfaInputs.current[Math.min(txt.length, 5)]?.focus();
  };

  /* ── Demo helpers ─────────────────────────────────────────────── */
  const fillAccount = (u) => {
    setEmail(u.email);
    setPassword(DEMO_PASSWORD);
    setPwFallback(true);
    setPwErr('');
    append({ kind:'info', text:`demo · prefilled credentials for ${u.email}` });
  };

  return (
    <div className="login-stage">
      {onToggleTheme && (
        <button
          className="tb-iconbtn login-theme-toggle"
          title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          aria-label={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          onClick={onToggleTheme}
        >
          {theme === 'dark'
            ? <I.Sun size={15} stroke={1.7} />
            : <I.Moon size={15} stroke={1.7} />}
        </button>
      )}
      {/* ── Left: form ── */}
      <div className="login-form-wrap">
        <div className="login-form">
          <div className="login-brand">
            <div className="login-mark"><I.Logo size={16} stroke={1.8} /></div>
            <div>
              <h1>Lumina FPM</h1>
              <p>acme · prod · eu-west-1</p>
            </div>
          </div>

          {/* ─────────── Credentials ─────────── */}
          {step === 'credentials' && (
            <form onSubmit={handlePrimarySubmit}>
              <h2 className="login-h">Sign in</h2>
              <p className="login-sub">Access to the SOC platform is restricted to authorized personnel. All sessions are recorded.</p>

              <label htmlFor="li-email" className="field-label">Email</label>
              <input
                id="li-email"
                className="field-input field-mono"
                value={email}
                onChange={(e) => { setEmail(e.target.value); setPwErr(''); }}
                autoComplete="username"
                spellCheck={false}
                disabled={submitting}
                style={{ marginBottom: 0 }}
              />

              {/* ── PRIMARY: security key ── */}
              <button
                type="button"
                className="btn primary"
                style={{
                  width:'100%', padding:'10px', justifyContent:'center',
                  marginTop: 18, fontSize: 13,
                }}
                onClick={handleWebauthn}
                disabled={submitting}
              >
                {submitting
                  ? <><span className="li-spinner" /> Authenticating…</>
                  : <><I.Key size={14} /> Continue with security key</>}
              </button>

              <div style={{
                display:'flex', alignItems:'center', gap:10, margin:'18px 0',
                color:'var(--fg-muted)', fontSize:11,
              }}>
                <div style={{ flex:1, height:1, background:'var(--bd-1)' }} />
                <span>or</span>
                <div style={{ flex:1, height:1, background:'var(--bd-1)' }} />
              </div>

              {/* ── SECONDARY / fallback: email + password ── */}
              {!pwFallback ? (
                <button
                  type="button"
                  className="btn"
                  style={{ width:'100%', padding:'9px', justifyContent:'center', fontSize: 12.5 }}
                  onClick={() => { setPwFallback(true); setPwErr(''); }}
                  disabled={submitting}
                >
                  <I.Lock size={13} /> Sign in with password instead
                </button>
              ) : (
                <>
                  <label htmlFor="li-pw" className="field-label">
                    <div style={{ display:'flex', justifyContent:'space-between' }}>
                      <span>Password</span>
                      <button
                        type="button"
                        style={{ color: 'var(--accent)', fontSize: 11 }}
                        onClick={() => window.toast('Password reset', { kind:'info', sub:'Contact security@acme.local · IT-23' })}
                      >forgot?</button>
                    </div>
                  </label>
                  <div style={{ position: 'relative' }}>
                    <input
                      id="li-pw"
                      type={pwShow ? 'text' : 'password'}
                      className="field-input field-mono"
                      value={password}
                      onChange={(e) => { setPassword(e.target.value); setPwErr(''); }}
                      placeholder="••••••••"
                      autoComplete="current-password"
                      autoFocus
                      disabled={submitting}
                    />
                    <button
                      type="button"
                      onClick={() => setPwShow(s => !s)}
                      style={{ position:'absolute', right:8, top:'50%', transform:'translateY(-50%)', color:'var(--fg-3)' }}
                      tabIndex={-1}
                    >
                      {pwShow ? <I.EyeOff size={14} /> : <I.Eye size={14} />}
                    </button>
                  </div>

                  {pwErr && (
                    <div style={{
                      marginTop: 12, padding: '8px 10px',
                      background: 'var(--sev-critical-bg)',
                      border: '1px solid var(--sev-critical-bd)',
                      borderRadius: 4, color: 'var(--sev-critical)',
                      fontSize: 12, display:'flex', alignItems:'center', gap: 8,
                    }}>
                      <I.AlertCirc size={13} /> {pwErr}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={submitting || !email || !password}
                    className="btn"
                    style={{
                      width:'100%', padding:'9px', justifyContent:'center',
                      marginTop: 14, fontSize: 12.5,
                      opacity: (!email || !password) ? 0.6 : 1,
                    }}
                  >
                    {submitting
                      ? <><span className="li-spinner" /> Authenticating…</>
                      : <>continue with password <I.ArrowRight size={13} /></>}
                  </button>

                  <div style={{ marginTop: 12, textAlign:'center' }}>
                    <button
                      type="button"
                      style={{ color: 'var(--accent)', fontSize: 11.5 }}
                      onClick={() => { setPwFallback(false); setPwErr(''); }}
                      disabled={submitting}
                    >
                      use security key instead
                    </button>
                  </div>
                </>
              )}

              <div style={{
                marginTop: 22, padding: '10px 12px',
                background: 'var(--bg-1)', border: '1px solid var(--bd-1)', borderRadius: 4,
              }}>
                <div className="muted" style={{ fontSize: 10.5, textTransform:'uppercase', letterSpacing:'0.06em', marginBottom: 4 }}>
                  demo accounts · password <span className="mono" style={{ color: 'var(--fg-1)' }}>demo</span> · mfa <span className="mono" style={{ color:'var(--fg-1)' }}>123456</span>
                </div>
                <div className="col" style={{ fontFamily: 'var(--f-mono)', fontSize: 11, color: 'var(--fg-2)', gap: 3 }}>
                  {window.LFPM.users.map(u => (
                    <button
                      key={u.id}
                      type="button"
                      onClick={() => fillAccount(u)}
                      style={{
                        display:'flex', justifyContent:'space-between',
                        textAlign:'left', padding:'2px 0', color: 'var(--fg-2)',
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.color = 'var(--fg-0)'}
                      onMouseLeave={(e) => e.currentTarget.style.color = 'var(--fg-2)'}
                    >
                      <span>{u.email}</span>
                      <span className="muted">{u.role}</span>
                    </button>
                  ))}
                </div>
              </div>
            </form>
          )}

          {/* ─────────── MFA ─────────── */}
          {step === 'mfa' && (
            <form onSubmit={handleMfa}>
              <h2 className="login-h">Two-factor verification</h2>
              <p className="login-sub">
                We sent a 6-digit code to your authenticator for{' '}
                <span className="mono" style={{ color: 'var(--fg-1)' }}>{email}</span>.
                {' '}
                <button type="button" onClick={() => { setStep('credentials'); setMfa(''); setMfaErr(''); }} style={{ color: 'var(--accent)' }}>
                  use a different account
                </button>
              </p>

              <label className="field-label">Verification code</label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }} onPaste={onMfaPaste}>
                {Array.from({ length: 6 }).map((_, i) => (
                  <input
                    key={i}
                    ref={el => mfaInputs.current[i] = el}
                    className="field-input field-mono"
                    style={{
                      textAlign:'center',
                      fontSize: 18,
                      padding: '12px 4px',
                      letterSpacing: 0,
                      borderColor: mfaErr ? 'var(--sev-critical-bd)' : undefined,
                    }}
                    inputMode="numeric"
                    maxLength={1}
                    value={mfa[i] || ''}
                    onChange={(e) => onMfaDigit(i, e.target.value)}
                    onKeyDown={(e) => onMfaKeyDown(i, e)}
                    disabled={submitting}
                  />
                ))}
              </div>

              {mfaErr && (
                <div style={{
                  marginTop: 12, padding: '8px 10px',
                  background: 'var(--sev-critical-bg)',
                  border: '1px solid var(--sev-critical-bd)',
                  borderRadius: 4, color: 'var(--sev-critical)',
                  fontSize: 12, display:'flex', alignItems:'center', gap: 8,
                }}>
                  <I.AlertCirc size={13} /> {mfaErr}
                </div>
              )}

              <button
                type="submit"
                disabled={submitting || mfa.length !== 6}
                className="btn primary"
                style={{
                  width:'100%', padding:'10px', justifyContent:'center',
                  marginTop: 18, fontSize: 13,
                  opacity: (mfa.length !== 6) ? 0.6 : 1,
                }}
              >
                {submitting
                  ? <><span className="li-spinner" /> Verifying…</>
                  : <>verify & sign in <I.ArrowRight size={13} /></>}
              </button>

              <div className="row" style={{ justifyContent: 'space-between', marginTop: 14, fontSize: 11.5 }}>
                <button type="button" style={{ color: 'var(--accent)' }} onClick={() => {
                  setMfa('');
                  setMfaErr('');
                  append({ kind:'info', text:'mfa · resend requested · new code dispatched' });
                  window.toast('New code sent', { kind:'info', sub: 'Check your authenticator' });
                }}>
                  resend code
                </button>
                <span className="muted mono">demo code · 123456</span>
              </div>
            </form>
          )}

          {/* ─────────── WebAuthn ─────────── */}
          {step === 'webauthn' && (
            <div>
              <h2 className="login-h">Touch your security key</h2>
              <p className="login-sub">
                Awaiting confirmation from your authenticator.{' '}
                <button type="button" onClick={() => setStep('credentials')} style={{ color: 'var(--accent)' }}>cancel</button>
              </p>
              <div style={{
                marginTop: 20, padding: 24,
                background: 'var(--bg-1)', border: '1px solid var(--bd-1)', borderRadius: 6,
                display:'flex', flexDirection:'column', alignItems:'center', gap: 14,
              }}>
                <div style={{
                  width: 60, height: 60, borderRadius: '50%',
                  background: 'var(--accent-bg)',
                  border: '1px solid var(--accent-bd)',
                  display:'flex', alignItems:'center', justifyContent:'center',
                  color: 'var(--accent)',
                  animation: 'pulse 1.4s ease-in-out infinite',
                }}>
                  <I.Key size={22} />
                </div>
                <div className="muted mono" style={{ fontSize: 11 }}>waiting for touch…</div>
              </div>
            </div>
          )}

          {/* ─────────── Success / redirecting ─────────── */}
          {step === 'success' && resolvedUser && (
            <div>
              <div style={{
                display:'flex', alignItems:'center', gap: 12,
                padding: 16, background: 'var(--sev-safe-bg)',
                border: '1px solid var(--sev-safe-bd)',
                borderRadius: 6, marginBottom: 16,
              }}>
                <div style={{
                  width: 40, height: 40, borderRadius: 20,
                  background: 'rgba(74,222,128,0.18)',
                  border: '1px solid var(--sev-safe-bd)',
                  display:'flex', alignItems:'center', justifyContent:'center',
                  color: 'var(--sev-safe)',
                }}>
                  <I.CheckCirc size={18} />
                </div>
                <div className="col" style={{ lineHeight: 1.25 }}>
                  <span style={{ color: 'var(--fg-0)', fontSize: 14, fontWeight: 600 }}>
                    Welcome back, {resolvedUser.name.split(' ')[0]}
                  </span>
                  <span style={{ color: 'var(--fg-2)', fontSize: 11.5 }}>
                    Signed in as <span className="mono" style={{ color: 'var(--fg-1)' }}>{resolvedUser.role}</span> · loading workspace…
                  </span>
                </div>
              </div>
              <div className="row gap-2" style={{ color: 'var(--fg-3)', fontSize: 11.5 }}>
                <span className="li-spinner" />
                <span>routing to {resolvedUser.role === 'viewer' ? 'read-only overview' : 'dashboard'}</span>
              </div>
            </div>
          )}

          <div style={{ marginTop: 32, fontSize: 10.5, color: 'var(--fg-muted)', fontFamily: 'var(--f-mono)', textAlign:'center' }}>
            lumina-fpm v2.4.1 · build 8a91c2 · {new Date().toISOString().slice(0,10)} · all sessions are monitored
          </div>
        </div>
      </div>

      {/* ── Right: terminal-style auth log ── */}
      <div className="login-side">
        <div className="login-side-head">
          <span className="dot" />
          <span className="label">auth-gateway · live</span>
          <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--fg-muted)' }}>region · eu-west-1</span>
        </div>

        <div className="login-log">
          {log.map((entry, i) => (
            <div key={i}>
              <span className="t-ts">{entry.t}</span>{' '}
              <span className={`t-${entry.kind === 'err' ? 'err' : entry.kind === 'ok' ? 'ok' : entry.kind === 'warn' ? 'warn' : 'info'}`}>
                [{entry.kind}]
              </span>{' '}
              <span style={{ color:'var(--fg-1)' }}>{entry.text}</span>
            </div>
          ))}
          <div style={{ marginTop: 8, color:'var(--fg-muted)' }}>
            <span className="t-acc">▌</span>
          </div>
        </div>

        <div style={{
          marginTop: 14, paddingTop: 12, borderTop: '1px solid var(--bd-1)',
          fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--f-mono)',
        }}>
          <div className="row gap-3" style={{ flexWrap: 'wrap' }}>
            <div><span className="muted">sso</span> <span style={{ color: 'var(--fg-1)' }}>okta · oidc</span></div>
            <div><span className="muted">mfa</span> <span style={{ color: 'var(--fg-1)' }}>totp + webauthn</span></div>
            <div><span className="muted">ip-allow</span> <span style={{ color: 'var(--fg-1)' }}>10.0.0.0/8</span></div>
            <div><span className="muted">retention</span> <span style={{ color: 'var(--fg-1)' }}>2y</span></div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50%      { opacity: 0.55; }
        }
        .li-spinner {
          display: inline-block;
          width: 12px; height: 12px;
          border: 2px solid currentColor;
          border-top-color: transparent;
          border-radius: 50%;
          margin-right: 6px;
          animation: li-spin 0.7s linear infinite;
        }
        @keyframes li-spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}

export { Login };
