import React, { useState } from 'react';

function Login({ onLoginSuccess, onSwitchToRegister }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await fetch('http://127.0.0.1:5000/api/login', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json' 
        },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      if (res.ok) {
        sessionStorage.setItem('devsecops_token', data.token);
        sessionStorage.setItem('devsecops_user', data.user);
        onLoginSuccess(data.user);
      } else {
        setError(data.error || 'Credenciales incorrectas');
      }
    } catch (err) {
      setError('No se pudo conectar con el servidor backend');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      minHeight: '100vh',
      backgroundColor: '#0d1117',
      fontFamily: 'sans-serif'
    }}>
      <div style={{
        background: '#161b22',
        border: '1px solid #30363d',
        borderRadius: '8px',
        padding: '32px',
        width: '100%',
        maxWidth: '380px',
        boxShadow: '0 8px 24px rgba(0,0,0,0.5)'
      }}>
        <h2 style={{ color: '#c9d1d9', textAlign: 'center', marginBottom: '8px' }}>
          Acceso DevSecOps
        </h2>
        <p style={{ color: '#8b949e', fontSize: '13px', textAlign: 'center', marginBottom: '24px' }}>
          Centro de Control de Seguridad
        </p>

        {error && (
          <div style={{
            backgroundColor: 'rgba(248, 81, 73, 0.15)',
            border: '1px solid #f85149',
            color: '#f85149',
            padding: '10px',
            borderRadius: '6px',
            fontSize: '13px',
            marginBottom: '16px',
            textAlign: 'center'
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <label style={{ display: 'block', color: '#8b949e', fontSize: '12px', marginBottom: '6px' }}>
              Usuario
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              style={{
                width: '100%',
                boxSizing: 'border-box',
                background: '#0d1117',
                border: '1px solid #30363d',
                color: '#c9d1d9',
                padding: '8px 12px',
                borderRadius: '6px',
                outline: 'none'
              }}
            />
          </div>

          <div>
            <label style={{ display: 'block', color: '#8b949e', fontSize: '12px', marginBottom: '6px' }}>
              Contraseña
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={{
                width: '100%',
                boxSizing: 'border-box',
                background: '#0d1117',
                border: '1px solid #30363d',
                color: '#c9d1d9',
                padding: '8px 12px',
                borderRadius: '6px',
                outline: 'none'
              }}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              marginTop: '8px',
              backgroundColor: '#238636',
              color: '#ffffff',
              border: 'none',
              padding: '10px',
              borderRadius: '6px',
              cursor: 'pointer',
              fontWeight: '600',
              fontSize: '14px'
            }}
          >
            {loading ? 'Validando...' : 'Iniciar Sesión'}
          </button>
        </form>

        {/* Nuevo bloque para redirigir a Registro */}
        <div style={{ marginTop: '20px', textAlign: 'center', fontSize: '13px' }}>
          <span style={{ color: '#8b949e' }}>¿No tienes cuenta? </span>
          <button 
            onClick={onSwitchToRegister}
            style={{ 
              background: 'none', 
              border: 'none', 
              color: '#58a6ff', 
              cursor: 'pointer', 
              padding: 0,
              textDecoration: 'underline'
            }}
          >
            Regístrate aquí
          </button>
        </div>

      </div>
    </div>
  );
}

export default Login;