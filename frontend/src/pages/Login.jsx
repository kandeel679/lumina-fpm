import { useState } from 'react';
import { ShieldAlert, Eye, EyeOff, LogIn, AlertCircle, Activity, Code, Server, Lock, CheckCircle, Key } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { mockUsers } from '../data/mockUsers';

export default function Login() {
  const { login } = useAuth();
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw]     = useState(false);
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  // New State for MFA and Forgot Password
  const [mfaStep, setMfaStep]           = useState(false);
  const [mfaCode, setMfaCode]           = useState('');
  const [mfaError, setMfaError]         = useState('');
  const [showForgotPw, setShowForgotPw] = useState(false);
  const [forgotEmail, setForgotEmail]   = useState('');
  const [forgotSuccess, setForgotSuccess] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!email.trim() || !password.trim()) {
      setError('Please enter your email and password.');
      return;
    }
    setLoading(true);
    await new Promise(r => setTimeout(r, 600));
    setLoading(false);
    
    // Validate credentials before MFA (using a mock check)
    const validUser = mockUsers.find(
      u => u.email.toLowerCase() === email.toLowerCase() && u.password === password
    );
    
    if (!validUser) {
      setError('Invalid email or password.');
      return;
    }
    
    setMfaStep(true);
  };

  const handleMfaSubmit = async (e) => {
    e.preventDefault();
    setMfaError('');
    if (mfaCode.trim().length !== 6) {
      setMfaError('Please enter a valid 6-digit code.');
      return;
    }
    setLoading(true);
    await new Promise(r => setTimeout(r, 600));
    const result = login(email, password);
    setLoading(false);
    if (!result.success) setMfaError(result.error);
  };

  const handleForgotSubmit = async (e) => {
    e.preventDefault();
    if (!forgotEmail) return;
    setLoading(true);
    await new Promise(r => setTimeout(r, 800));
    setLoading(false);
    setForgotSuccess(true);
  };

  const quickLogin = (user) => {
    setEmail(user.email);
    setPassword(user.password);
    setError('');
  };

  return (
    <div style={{
      minHeight: '100vh', background: 'var(--bg-primary)',
      display: 'flex', width: '100%', overflow: 'hidden',
      alignItems: 'center', justifyContent: 'center',
      position: 'relative'
    }}>
      {/* Background Patterns */}
      <div style={{
        position: 'absolute', inset: 0,
        backgroundImage: `
          linear-gradient(var(--border) 1px, transparent 1px),
          linear-gradient(90deg, var(--border) 1px, transparent 1px)
        `,
        backgroundSize: '64px 64px',
        opacity: 0.15, pointerEvents: 'none',
      }} />
      <div style={{
        position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
        width: '80vw', height: '80vw', borderRadius: '50%',
        background: 'radial-gradient(circle, var(--accent-glow) 0%, transparent 40%)',
        pointerEvents: 'none', mixBlendMode: 'screen', opacity: 0.4
      }} />
      
      {/* ── Center Card: Form ── */}
      <div style={{
        width: '100%', maxWidth: '460px', margin: '0 1.5rem',
        display: 'flex', flexDirection: 'column',
        padding: '3rem', position: 'relative',
        zIndex: 10, background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 24,
        boxShadow: '0 32px 64px rgba(0,0,0,0.2)'
      }}>
        <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', width: '100%' }}>
          
          {/* Logo */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '3rem' }}>
            <div style={{
              width: 44, height: 44, background: 'linear-gradient(135deg, var(--accent), #6366f1)',
              borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 24px var(--accent-glow)',
            }}>
              <ShieldAlert size={22} color="#fff" />
            </div>
            <div>
              <h1 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0, fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em', lineHeight: 1.1 }}>
                Lumina <span style={{ color: 'var(--accent)' }}>FPM</span>
                <Lock size={16} color="var(--safe)" />
              </h1>
              <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Secure Access Portal
              </p>
            </div>
          </div>

          {!mfaStep ? (
            <>
              <div style={{ marginBottom: '2rem' }}>
                <h2 style={{ margin: 0, fontSize: '1.8rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.03em' }}>
                  Welcome back
                </h2>
                <p style={{ margin: '0.5rem 0 0', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                  Enter your credentials to access the SOC environment.
                </p>
              </div>

              <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                {/* Email */}
                <div>
                  <label htmlFor="login-email" style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                    Email address
                  </label>
                  <input
                    id="login-email"
                    type="email"
                    autoComplete="email"
                    placeholder="analyst@lumina.local"
                    value={email}
                    onChange={e => { setEmail(e.target.value); setError(''); }}
                    style={{
                      width: '100%', padding: '0.75rem 1rem',
                      background: 'var(--bg-surface)', border: `1px solid ${error ? 'var(--critical)' : 'var(--border)'}`,
                      borderRadius: 10, color: 'var(--text-primary)', fontSize: '0.9rem', outline: 'none',
                      transition: 'border-color 0.15s, box-shadow 0.15s',
                      boxSizing: 'border-box',
                    }}
                    onFocus={e => {
                      e.target.style.borderColor = 'var(--accent)';
                      e.target.style.boxShadow = '0 0 0 3px var(--accent-glow)';
                    }}
                    onBlur={e => {
                      e.target.style.borderColor = error ? 'var(--critical)' : 'var(--border)';
                      e.target.style.boxShadow = 'none';
                    }}
                  />
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.4rem', textAlign: 'right' }}>
                    Last login attempt: {new Date().toLocaleDateString()} {new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                  </div>
                </div>

                {/* Password */}
                <div>
                  <label htmlFor="login-password" style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                    <span>Password</span>
                    <button type="button" onClick={() => setShowForgotPw(true)} style={{ background: 'none', border: 'none', padding: 0, color: 'var(--accent)', fontSize: '0.75rem', cursor: 'pointer' }}>
                      Forgot password?
                    </button>
                  </label>
              <div style={{ position: 'relative' }}>
                <input
                  id="login-password"
                  type={showPw ? 'text' : 'password'}
                  autoComplete="current-password"
                  placeholder="••••••••"
                  value={password}
                  onChange={e => { setPassword(e.target.value); setError(''); }}
                  style={{
                    width: '100%', padding: '0.75rem 2.8rem 0.75rem 1rem',
                    background: 'var(--bg-surface)', border: `1px solid ${error ? 'var(--critical)' : 'var(--border)'}`,
                    borderRadius: 10, color: 'var(--text-primary)', fontSize: '0.9rem', outline: 'none',
                    transition: 'border-color 0.15s, box-shadow 0.15s', boxSizing: 'border-box',
                  }}
                  onFocus={e => {
                    e.target.style.borderColor = 'var(--accent)';
                    e.target.style.boxShadow = '0 0 0 3px var(--accent-glow)';
                  }}
                  onBlur={e => {
                    e.target.style.borderColor = error ? 'var(--critical)' : 'var(--border)';
                    e.target.style.boxShadow = 'none';
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(s => !s)}
                  style={{
                    position: 'absolute', right: '1rem', top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--text-muted)', display: 'flex', padding: 0,
                  }}
                  title={showPw ? 'Hide password' : 'Show password'}
                >
                  {showPw ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: '0.5rem',
                background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)',
                borderRadius: 8, padding: '0.6rem 0.85rem',
                animation: 'fadeIn 0.2s ease',
              }}>
                <AlertCircle size={15} color="var(--critical)" style={{ flexShrink: 0 }} />
                <span style={{ fontSize: '0.82rem', color: '#f87171', fontWeight: 500 }}>{error}</span>
              </div>
            )}

            {/* Submit */}
            <button
              id="login-submit-btn"
              type="submit"
              disabled={loading}
              style={{
                width: '100%', padding: '0.85rem', marginTop: '0.5rem',
                background: loading ? 'var(--bg-surface)' : 'var(--text-primary)',
                border: 'none', borderRadius: 10, color: loading ? 'var(--text-muted)' : 'var(--bg-primary)',
                fontWeight: 600, fontSize: '0.95rem', cursor: loading ? 'not-allowed' : 'pointer',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem',
                transition: 'all 0.2s',
                boxShadow: loading ? 'none' : '0 8px 24px rgba(0,0,0,0.15)',
              }}
              onMouseEnter={e => !loading && (e.currentTarget.style.transform = 'translateY(-1px)')}
              onMouseLeave={e => !loading && (e.currentTarget.style.transform = 'none')}
            >
              {loading ? (
                <span style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <span className="spinner" />
                  Authenticating…
                </span>
              ) : (
                <>
                  <LogIn size={18} />
                  Authorize Session
                </>
              )}
            </button>
            <div style={{ textAlign: 'center', marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              🔒 Secure SOC Access – All sessions are monitored
            </div>
          </form>
            </>
          ) : (
            <>
              <div style={{ marginBottom: '2rem' }}>
                <h2 style={{ margin: 0, fontSize: '1.8rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.03em' }}>
                  Two-Factor Authentication
                </h2>
                <p style={{ margin: '0.5rem 0 0', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                  Enter the 6-digit verification code sent to your device.
                </p>
              </div>

              <form onSubmit={handleMfaSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                <div>
                  <label htmlFor="mfa-code" style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                    Verification Code
                  </label>
                  <input
                    id="mfa-code"
                    type="text"
                    maxLength={6}
                    placeholder="000000"
                    value={mfaCode}
                    onChange={e => { setMfaCode(e.target.value.replace(/\D/g, '')); setMfaError(''); }}
                    style={{
                      width: '100%', padding: '0.75rem 1rem', textAlign: 'center', letterSpacing: '0.5em',
                      background: 'var(--bg-surface)', border: `1px solid ${mfaError ? 'var(--critical)' : 'var(--border)'}`,
                      borderRadius: 10, color: 'var(--text-primary)', fontSize: '1.2rem', fontWeight: 700, outline: 'none',
                      transition: 'border-color 0.15s, box-shadow 0.15s', boxSizing: 'border-box',
                    }}
                    onFocus={e => { e.target.style.borderColor = 'var(--accent)'; e.target.style.boxShadow = '0 0 0 3px var(--accent-glow)'; }}
                    onBlur={e => { e.target.style.borderColor = mfaError ? 'var(--critical)' : 'var(--border)'; e.target.style.boxShadow = 'none'; }}
                  />
                  <div style={{ textAlign: 'right', marginTop: '0.5rem' }}>
                    <button type="button" style={{ background: 'none', border: 'none', color: 'var(--accent)', fontSize: '0.75rem', cursor: 'pointer' }}>
                      Resend code
                    </button>
                  </div>
                </div>

                {mfaError && (
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: '0.5rem',
                    background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)',
                    borderRadius: 8, padding: '0.6rem 0.85rem',
                    animation: 'fadeIn 0.2s ease',
                  }}>
                    <AlertCircle size={15} color="var(--critical)" style={{ flexShrink: 0 }} />
                    <span style={{ fontSize: '0.82rem', color: '#f87171', fontWeight: 500 }}>{mfaError}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading || mfaCode.length !== 6}
                  style={{
                    width: '100%', padding: '0.85rem', marginTop: '0.5rem',
                    background: (loading || mfaCode.length !== 6) ? 'var(--bg-surface)' : 'var(--text-primary)',
                    border: 'none', borderRadius: 10, color: (loading || mfaCode.length !== 6) ? 'var(--text-muted)' : 'var(--bg-primary)',
                    fontWeight: 600, fontSize: '0.95rem', cursor: (loading || mfaCode.length !== 6) ? 'not-allowed' : 'pointer',
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem',
                    transition: 'all 0.2s',
                    boxShadow: (loading || mfaCode.length !== 6) ? 'none' : '0 8px 24px rgba(0,0,0,0.15)',
                  }}
                  onMouseEnter={e => !(loading || mfaCode.length !== 6) && (e.currentTarget.style.transform = 'translateY(-1px)')}
                  onMouseLeave={e => !(loading || mfaCode.length !== 6) && (e.currentTarget.style.transform = 'none')}
                >
                  {loading ? (
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <span className="spinner" />
                      Verifying…
                    </span>
                  ) : (
                    <>
                      <Key size={18} />
                      Verify & Login
                    </>
                  )}
                </button>
                <div style={{ textAlign: 'center', marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  🔒 Secure SOC Access – All sessions are monitored
                </div>
                <button type="button" onClick={() => setMfaStep(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '0.8rem', cursor: 'pointer', marginTop: '1rem' }}>
                  ← Back to login
                </button>
              </form>
            </>
          )}

          {/* Demo Role Selector */}
          <div style={{ marginTop: '3rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <label htmlFor="demo-role" style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Demo Environment (Auto-fill)
            </label>
            <div style={{ position: 'relative' }}>
              <select
                id="demo-role"
                onChange={(e) => {
                  const role = e.target.value;
                  if (!role) return;
                  const user = mockUsers.find(u => u.role === role);
                  if (user) {
                    quickLogin(user);
                  }
                  e.target.value = ''; // Reset select after auto-fill
                }}
                style={{
                  width: '100%', padding: '0.85rem 1rem',
                  background: 'var(--bg-card)', border: '1px solid var(--border)',
                  borderRadius: 10, color: 'var(--text-primary)', fontSize: '0.9rem', outline: 'none',
                  cursor: 'pointer', appearance: 'none', transition: 'border-color 0.15s'
                }}
                onFocus={e => e.target.style.borderColor = 'var(--accent)'}
                onBlur={e => e.target.style.borderColor = 'var(--border)'}
              >
                <option value="">Select a role to auto-fill credentials...</option>
                <option value="Admin">Administrator</option>
                <option value="Analyst">Security Analyst</option>
                <option value="Read-Only">Read-Only / Auditor</option>
              </select>
              <div style={{ position: 'absolute', right: '1rem', top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none', color: 'var(--text-muted)' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
              </div>
            </div>
          </div>
          
          {/* Footer note */}
          <p style={{ textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '3rem' }}>
            Lumina FPM v2.4.1 · Enterprise Edition<br/>
            <span style={{ color: 'var(--critical)', fontWeight: 600, opacity: 0.8, display: 'block', marginTop: '0.4rem' }}>
              Unauthorized access is strictly prohibited
            </span>
          </p>
        </div>
      </div>

      <style>{`
        .spinner {
          width: 16px; height: 16px; border: 2px solid var(--text-muted);
          border-top-color: currentColor; border-radius: 50%;
          animation: spin 0.7s linear infinite; display: inline-block;
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-4px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @media (max-width: 900px) {
          .left-column { flex: 1 1 100% !important; max-width: none !important; }
          .right-column { display: none !important; }
        }
      `}</style>

      {/* ── Forgot Password Modal ── */}
      {showForgotPw && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 1000,
          background: 'rgba(0, 0, 0, 0.6)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyItems: 'center', justifyContent: 'center', padding: '1rem',
          animation: 'fadeIn 0.2s ease'
        }}>
          <div style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 16,
            width: '100%', maxWidth: 400, padding: '2rem', boxShadow: '0 32px 64px rgba(0,0,0,0.3)',
          }}>
            {!forgotSuccess ? (
              <>
                <h3 style={{ margin: '0 0 0.5rem', fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Password Reset
                </h3>
                <p style={{ margin: '0 0 1.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                  Enter your email address to receive secure reset instructions.
                </p>
                <form onSubmit={handleForgotSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div>
                    <label htmlFor="forgot-email" style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                      Email address
                    </label>
                    <input
                      id="forgot-email"
                      type="email"
                      required
                      value={forgotEmail}
                      onChange={e => setForgotEmail(e.target.value)}
                      style={{
                        width: '100%', padding: '0.75rem 1rem',
                        background: 'var(--bg-surface)', border: '1px solid var(--border)',
                        borderRadius: 10, color: 'var(--text-primary)', fontSize: '0.9rem', outline: 'none',
                        transition: 'border-color 0.15s, box-shadow 0.15s', boxSizing: 'border-box',
                      }}
                      onFocus={e => { e.target.style.borderColor = 'var(--accent)'; e.target.style.boxShadow = '0 0 0 3px var(--accent-glow)'; }}
                      onBlur={e => { e.target.style.borderColor = 'var(--border)'; e.target.style.boxShadow = 'none'; }}
                    />
                  </div>
                  <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
                    <button
                      type="button"
                      onClick={() => setShowForgotPw(false)}
                      style={{
                        flex: 1, padding: '0.8rem', background: 'transparent', border: '1px solid var(--border)',
                        borderRadius: 10, color: 'var(--text-primary)', fontWeight: 600, fontSize: '0.9rem', cursor: 'pointer',
                      }}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={loading}
                      style={{
                        flex: 1, padding: '0.8rem', background: 'var(--text-primary)', border: 'none',
                        borderRadius: 10, color: 'var(--bg-primary)', fontWeight: 600, fontSize: '0.9rem', cursor: loading ? 'not-allowed' : 'pointer',
                        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem',
                      }}
                    >
                      {loading ? <span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> : 'Send Link'}
                    </button>
                  </div>
                </form>
              </>
            ) : (
              <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                <CheckCircle size={48} color="var(--safe)" style={{ marginBottom: '1rem' }} />
                <h3 style={{ margin: '0 0 0.5rem', fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Request Sent
                </h3>
                <p style={{ margin: '0 0 1.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                  If an account matches <strong>{forgotEmail}</strong>, an administrator will send reset instructions securely.
                </p>
                <button
                  onClick={() => { setShowForgotPw(false); setForgotSuccess(false); setForgotEmail(''); }}
                  style={{
                    width: '100%', padding: '0.8rem', background: 'var(--text-primary)', border: 'none',
                    borderRadius: 10, color: 'var(--bg-primary)', fontWeight: 600, fontSize: '0.9rem', cursor: 'pointer',
                  }}
                >
                  Return to Login
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
