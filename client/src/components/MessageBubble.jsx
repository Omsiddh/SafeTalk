export default function MessageBubble({ fromSelf, text }) {
  return (
    <div className={`w-full flex ${fromSelf ? 'justify-end' : 'justify-start'} my-1`}>
      <div className={`px-3 py-2 rounded max-w-[70%] ${fromSelf ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-900'}`}>
        {text}
      </div>
    </div>
  );
}