import { useEffect, useState } from 'react';
import axios from 'axios';

const API = import.meta.env.VITE_API_BASE;

export default function AdminDashboard() {
  const [users, setUsers] = useState([]);
  const token = localStorage.getItem('accessToken');

  useEffect(() => {
    async function load() {
      try {
        const { data } = await axios.get(`${API}/admin/users`, { headers: { Authorization: `Bearer ${token}` } });
        setUsers(data);
      } catch {}
    }
    load();
  }, [token]);

  const toggle = async (id, disabled) => {
    const { data } = await axios.patch(`${API}/admin/users/${id}/disable`, { disabled: !disabled }, { headers: { Authorization: `Bearer ${token}` } });
    setUsers((prev) => prev.map(u => u._id === id ? { ...u, disabled: data.user.disabled } : u));
  };

  return (
    <div className="card">
      <h2 className="text-xl font-semibold mb-2">Admin Dashboard</h2>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left"><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th></th></tr>
        </thead>
        <tbody>
          {users.map(u => (
            <tr key={u._id} className="border-t">
              <td>{u.username}</td>
              <td>{u.email}</td>
              <td>{u.role}</td>
              <td>{u.disabled ? 'Disabled' : 'Active'}</td>
              <td><button className="btn" onClick={() => toggle(u._id, u.disabled)}>{u.disabled ? 'Enable' : 'Disable'}</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}