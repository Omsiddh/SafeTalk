import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const API = import.meta.env.VITE_API_BASE;

export default function Login() {
  const [form, setForm] = useState({ email: '', password: '' });
  const [msg, setMsg] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const onChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const onSubmit = async (e) => {
    e.preventDefault();
    setMsg('');
    setLoading(true);
    try {
      const { data } = await axios.post(`${API}/auth/login`, form);
      if (data.requires2FA) {
        sessionStorage.setItem('st_temp_token', data.tempToken);
        navigate('/verify-2fa');
      } else {
        localStorage.setItem('accessToken', data.accessToken);
        localStorage.setItem('refreshToken', data.refreshToken);
        navigate('/chat');
      }
    } catch (err) {
      setMsg(err.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card space-y-4">
      <h2 className="text-xl font-semibold">Login</h2>
      <form onSubmit={onSubmit} className="space-y-3">
        <input className="input" name="email" type="email" placeholder="Email" value={form.email} onChange={onChange} required />
        <input className="input" name="password" type="password" placeholder="Password" value={form.password} onChange={onChange} required />
        <button className="btn" disabled={loading}>{loading ? 'Please wait...' : 'Login'}</button>
      </form>
      {msg && <p>{msg}</p>}
    </div>
  );
}