import React, { useState } from 'react';
import './App.css'; // Make sure this file exists in the same folder

// Helper function for error handling
async function fetchAPI(url, options) {
  try {
    const response = await fetch(url, options);
    const json = await response.json();
    if (!response.ok) {
      throw new Error(json.error || 'Something went wrong');
    }
    return json;
  } catch (error) {
    throw error;
  }
}

function App() {
  // States
  const [view, setView] = useState('login');
  const [message, setMessage] = useState('');
  const [loginInfo, setLoginInfo] = useState({ login: '', password: '' });
  const [registerInfo, setRegisterInfo] = useState({ login: '', password: '' });
  const [vaultEntry, setVaultEntry] = useState({ title: '', secret: '' });
  const [retrievedEntry, setRetrievedEntry] = useState({ title: '', secret: '' });
  const [searchTitle, setSearchTitle] = useState('');

  // Input updater factory
  const updateInput = (setter) => (e) => setter(prev => ({ ...prev, [e.target.name]: e.target.value }));

  // Handlers
  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const res = await fetchAPI('http://localhost:8080/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(registerInfo),
        credentials: 'include',
      });
      setMessage(res.message);
      setRegisterInfo({ login: '', password: '' });
    } catch (error) {
      setMessage(error.message);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await fetchAPI('http://localhost:8080/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginInfo),
        credentials: 'include',
      });
      setMessage(`Logged in with token: ${res.token}`);
      setLoginInfo({ login: '', password: '' });
      setView('vault');
    } catch (error) {
      setMessage(error.message);
    }
  };

  const handleAddEntry = async (e) => {
    e.preventDefault();
    try {
      const res = await fetchAPI('http://localhost:8080/makeVaultEntry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(vaultEntry),
        credentials: 'include',
      });
      setMessage(res.message);
      setVaultEntry({ title: '', secret: '' });
    } catch (error) {
      setMessage(error.message);
    }
  };

  const handleGetEntry = async (e) => {
    e.preventDefault();
    try {
      const res = await fetchAPI('http://localhost:8080/getVaultEntry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: searchTitle }),
        credentials: 'include',
      });
      setRetrievedEntry({ title: res.title, secret: res.secret });
      setMessage(`Entry "${res.title}" retrieved`);
    } catch (error) {
      setMessage(error.message);
      setRetrievedEntry({ title: '', secret: '' });
    }
  };

  return (
    <div className="App">
      <h1>Internet Vault Frontend</h1>

      <nav>
        <button onClick={() => setView('login')}>Login</button>
        <button onClick={() => setView('register')}>Register</button>
        <button onClick={() => setView('vault')}>Vault</button>
      </nav>

      {message && <div className="message">{message}</div>}

      {view === 'register' && (
        <form onSubmit={handleRegister}>
          <h2>Register</h2>
          <input
            type="text"
            name="login"
            placeholder="Login"
            value={registerInfo.login}
            onChange={updateInput(setRegisterInfo)}
          />
          <input
            type="password"
            name="password"
            placeholder="Password"
            value={registerInfo.password}
            onChange={updateInput(setRegisterInfo)}
          />
          <button type="submit">Register</button>
        </form>
      )}

      {view === 'login' && (
        <form onSubmit={handleLogin}>
          <h2>Login</h2>
          <input
            type="text"
            name="login"
            placeholder="Login"
            value={loginInfo.login}
            onChange={updateInput(setLoginInfo)}
          />
          <input
            type="password"
            name="password"
            placeholder="Password"
            value={loginInfo.password}
            onChange={updateInput(setLoginInfo)}
          />
          <button type="submit">Login</button>
        </form>
      )}

      {view === 'vault' && (
        <div className="vault-section">
          <h2>Create Vault Entry</h2>
          <form onSubmit={handleAddEntry}>
            <input
              type="text"
              name="title"
              placeholder="Entry Title"
              value={vaultEntry.title}
              onChange={updateInput(setVaultEntry)}
            />
            <input
              type="text"
              name="secret"
              placeholder="Secret"
              value={vaultEntry.secret}
              onChange={updateInput(setVaultEntry)}
            />
            <button type="submit">Add Entry</button>
          </form>

          <h2>Retrieve Vault Entry</h2>
          <form onSubmit={handleGetEntry}>
            <input
              type="text"
              name="searchTitle"
              placeholder="Entry Title"
              value={searchTitle}
              onChange={(e) => setSearchTitle(e.target.value)}
            />
            <button type="submit">Get Entry</button>
          </form>

          {retrievedEntry.title && (
            <div className="entry">
              <h3>{retrievedEntry.title}</h3>
              <p>{retrievedEntry.secret}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
