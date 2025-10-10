import { useState } from 'react';
import axios from 'axios';
import { generateRSAKeyPair, exportPublicKeyToBase64SPKI, deriveAESKeyFromPassword, encryptPrivateKey } from '../lib/crypto.js';

const API = import.meta.env.VITE_API_BASE;

export default function Register() {
  const [form, setForm] = useState({ username: '', email: '', password: '' });
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState('');

  const onChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const onSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMsg('');
    try {
      // Generate RSA key pair locally
      const { publicKey, privateKey } = await generateRSAKeyPair();
      const publicKeyB64 = await exportPublicKeyToBase64SPKI(publicKey);
      // Derive AES key from password + username, then encrypt private key for local storage
      const aesKey = await deriveAESKeyFromPassword(form.password, form.username);
      const { ciphertext, iv } = await encryptPrivateKey(privateKey, aesKey);
      localStorage.setItem('st_encrypted_private_key', ciphertext);
      localStorage.setItem('st_encrypted_private_key_iv', iv);
      localStorage.setItem('st_username', form.username);

      await axios.post(`${API}/auth/register`, { ...form, publicKey: publicKeyB64 });
      setMsg('Registered successfully. You can now log in.');
    } catch (err) {
      setMsg(err.response?.data?.error || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card space-y-4">
      <h2 className="text-xl font-semibold">Register</h2>
      <form onSubmit={onSubmit} className="space-y-3">
        <input className="input" name="username" placeholder="Username" value={form.username} onChange={onChange} required />
        <input className="input" name="email" type="email" placeholder="Email" value={form.email} onChange={onChange} required />
        <input className="input" name="password" type="password" placeholder="Password" value={form.password} onChange={onChange} required />
        <button className="btn" disabled={loading}>{loading ? 'Please wait...' : 'Register'}</button>
      </form>
      {msg && <p>{msg}</p>}
    </div>
  );
}