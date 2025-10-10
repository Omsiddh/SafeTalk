import { useEffect, useMemo, useState } from 'react';
import io from 'socket.io-client';
import axios from 'axios';
import ChatBox from '../components/ChatBox.jsx';
import { importPublicKeyFromBase64, deriveAESKeyFromPassword, decryptPrivateKey, generateAESKey, encryptMessage, wrapAESKeyWithRSA, decryptMessage, unwrapAESKeyWithRSA } from '../lib/crypto.js';

const API = import.meta.env.VITE_API_BASE;
const SOCKET_URL = import.meta.env.VITE_SOCKET_URL;

export default function ChatRoom() {
  const [receiverUsername, setReceiverUsername] = useState('');
  const [password, setPassword] = useState('');
  const [unlocked, setUnlocked] = useState(false);
  const [recipient, setRecipient] = useState(null); // {id, username, publicKey}
  const [privateKey, setPrivateKey] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');

  const token = localStorage.getItem('accessToken');

  const socket = useMemo(() => {
    if (!token) return null;
    return io(SOCKET_URL, { auth: { token } });
  }, [token]);

  useEffect(() => {
    if (!socket) return;
    socket.on('message:receive', async (payload) => {
      // Try to decrypt if private key is unlocked
      if (privateKey) {
        try {
          const aesKey = await unwrapAESKeyWithRSA(payload.encryptedKey, privateKey);
          const text = await decryptMessage(payload.ciphertext, payload.iv, aesKey);
          setMessages((prev) => [...prev, { ...payload, text, fromSelf: false }]);
          return;
        } catch {}
      }
      setMessages((prev) => [...prev, { ...payload, fromSelf: false }]);
    });
    return () => {
      socket.off('message:receive');
      socket.disconnect();
    };
  }, [socket, privateKey]);

  const unlock = async () => {
    try {
      const username = localStorage.getItem('st_username');
      const enc = localStorage.getItem('st_encrypted_private_key');
      const iv = localStorage.getItem('st_encrypted_private_key_iv');
      const aesKey = await deriveAESKeyFromPassword(password, username);
      const pk = await decryptPrivateKey(enc, iv, aesKey);
      setPrivateKey(pk);
      setUnlocked(true);
    } catch (e) {
      alert('Failed to unlock private key');
    }
  };

  const findRecipient = async () => {
    const { data } = await axios.get(`${API}/auth/users/${receiverUsername}`, { headers: { Authorization: `Bearer ${token}` } });
    setRecipient(data);
  };

  const sendMessage = async () => {
    if (!recipient) return alert('Choose a recipient first');
    try {
      // Encrypt message: generate AES key, encrypt text, wrap AES key with recipient public key
      const publicKey = await importPublicKeyFromBase64(recipient.publicKey);
      const aesKey = await generateAESKey();
      const { ciphertext, iv } = await encryptMessage(input, aesKey);
      const wrapped = await wrapAESKeyWithRSA(aesKey, publicKey);

      // Persist via REST
      await axios.post(`${API}/messages/send`, {
        receiverId: recipient.id,
        ciphertext,
        encryptedKey: wrapped,
        iv,
      }, { headers: { Authorization: `Bearer ${token}` } });

      setMessages((prev) => [...prev, { to: recipient.id, text: input, fromSelf: true, timestamp: Date.now() }]);
      setInput('');
    } catch (e) {
      alert('Send failed');
    }
  };

  return (
    <div className="space-y-4">
      <div className="card space-y-2">
        <div className="flex gap-2 items-end">
          <div className="flex-1">
            <label className="block text-sm">Recipient username</label>
            <input className="input" value={receiverUsername} onChange={(e)=>setReceiverUsername(e.target.value)} placeholder="e.g. alice" />
          </div>
          <button className="btn" onClick={findRecipient}>Load</button>
          {recipient && <span>→ {recipient.username}</span>}
        </div>
        <div className="flex gap-2 items-end">
          <div className="flex-1">
            <label className="block text-sm">Unlock with password</label>
            <input className="input" type="password" value={password} onChange={(e)=>setPassword(e.target.value)} placeholder="Account password" />
          </div>
          <button className="btn" onClick={unlock} disabled={unlocked}>{unlocked ? 'Unlocked' : 'Unlock'}</button>
        </div>
      </div>
      <ChatBox messages={messages} />
      <div className="flex gap-2">
        <input className="input flex-1" value={input} onChange={(e)=>setInput(e.target.value)} placeholder="Type a message..." />
        <button className="btn" onClick={sendMessage}>Send</button>
      </div>
    </div>
  );
}