import { Routes, Route, Link, useNavigate } from 'react-router-dom';
import Register from './pages/Register.jsx';
import Login from './pages/Login.jsx';
import VerifyTOTP from './pages/VerifyTOTP.jsx';
import ChatRoom from './pages/ChatRoom.jsx';
import AdminDashboard from './pages/AdminDashboard.jsx';

export default function App() {
  const navigate = useNavigate();
  const logout = () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    navigate('/login');
  };
  return (
    <div className="container">
      <header className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold"><Link to="/">SafeTalk</Link></h1>
        <nav className="space-x-4">
          <Link to="/register">Register</Link>
          <Link to="/login">Login</Link>
          <Link to="/chat">Chat</Link>
          <Link to="/admin">Admin</Link>
          <button className="btn" onClick={logout}>Logout</button>
        </nav>
      </header>
      <Routes>
        <Route path="/" element={<div className="card">Welcome to SafeTalk — end-to-end encrypted chat demo.</div>} />
        <Route path="/register" element={<Register />} />
        <Route path="/login" element={<Login />} />
        <Route path="/verify-2fa" element={<VerifyTOTP />} />
        <Route path="/chat" element={<ChatRoom />} />
        <Route path="/admin" element={<AdminDashboard />} />
      </Routes>
    </div>
  );
}