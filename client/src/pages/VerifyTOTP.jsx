import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const API = import.meta.env.VITE_API_BASE;

export default function VerifyTOTP() {
  const [otp, setOtp] = useState('');
  const [msg, setMsg] = useState('');
  const navigate = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    setMsg('');
    const tempToken = sessionStorage.getItem('st_temp_token');
    if (!tempToken) return setMsg('Missing temp token');
    try {
      const { data } = await axios.post(`${API}/auth/verify-2fa`, { tempToken, otp });
      localStorage.setItem('accessToken', data.accessToken);
      localStorage.setItem('refreshToken', data.refreshToken);
      sessionStorage.removeItem('st_temp_token');
      navigate('/chat');
    } catch (err) {
      setMsg(err.response?.data?.error || 'Verification failed');
    }
  };

  return (
    <div className="card space-y-4">
      <h2 className="text-xl font-semibold">Verify 2FA</h2>
      <form onSubmit={submit} className="space-y-3">
        <input className="input" placeholder="OTP code" value={otp} onChange={(e)=>setOtp(e.target.value)} />
        <button className="btn">Verify</button>
      </form>
      {msg && <p>{msg}</p>}
    </div>
  );
}