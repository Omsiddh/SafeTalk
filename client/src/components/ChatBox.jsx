import { useEffect, useRef } from 'react';
import MessageBubble from './MessageBubble.jsx';

export default function ChatBox({ messages }) {
  const bottomRef = useRef(null);
  useEffect(()=>{ bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);
  return (
    <div className="h-96 overflow-y-auto border rounded p-2 bg-white">
      {messages.map((m) => (
        <MessageBubble key={m._id || m.timestamp} fromSelf={m.fromSelf} text={m.text || '[encrypted]'} />
      ))}
      <div ref={bottomRef} />
    </div>
  );
}