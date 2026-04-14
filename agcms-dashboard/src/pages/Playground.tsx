import { useRef, useState } from 'react';
import { cn } from '../lib/cn';
import { postPlaygroundChat, type PlaygroundResponse } from '../lib/api';
import toast from 'react-hot-toast';

interface ChatEntry {
  id: string;
  userMessage: string;
  response: PlaygroundResponse | null;
  error: string | null;
  loading: boolean;
}

const ACTION_COLORS: Record<string, string> = {
  BLOCK: 'bg-red-100 text-red-700',
  REDACT: 'bg-yellow-100 text-yellow-700',
  ALLOW: 'bg-green-100 text-green-700',
};

const RISK_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-700',
  HIGH: 'bg-orange-100 text-orange-700',
  MEDIUM: 'bg-yellow-100 text-yellow-700',
  LOW: 'bg-blue-100 text-blue-700',
  NONE: 'bg-gray-100 text-gray-500',
};

function Badge({ label, className }: { label: string; className?: string }) {
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium', className)}>
      {label}
    </span>
  );
}

function GovernancePanel({ response }: { response: PlaygroundResponse }) {
  const { governance, timing, masked_text, original_text } = response;
  const action = governance.policy.action;

  return (
    <div className="mt-2 bg-white border border-gray-200 rounded-lg p-4 text-sm space-y-4">
      {/* Policy Decision */}
      <div className="flex items-center gap-3">
        <span className="text-xs font-medium text-gray-500 w-16">Policy</span>
        <Badge label={action} className={ACTION_COLORS[action] || 'bg-gray-100 text-gray-700'} />
        {governance.policy.reason && (
          <span className="text-xs text-gray-500">{governance.policy.reason}</span>
        )}
      </div>

      {/* PII Detection */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <span className="text-xs font-medium text-gray-500 w-16">PII</span>
          <Badge
            label={governance.pii.risk_level}
            className={RISK_COLORS[governance.pii.risk_level] || 'bg-gray-100 text-gray-500'}
          />
          {governance.pii.entity_types.map((t) => (
            <Badge key={t} label={t} className="bg-indigo-50 text-indigo-700" />
          ))}
        </div>
        {action === 'REDACT' && masked_text && (
          <div className="grid grid-cols-2 gap-3 mt-2">
            <div>
              <p className="text-xs font-medium text-gray-400 mb-1">Original</p>
              <p className="font-mono text-xs bg-red-50 p-2 rounded break-all">{original_text}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-gray-400 mb-1">Sent to LLM</p>
              <p className="font-mono text-xs bg-green-50 p-2 rounded break-all">{masked_text}</p>
            </div>
          </div>
        )}
      </div>

      {/* Injection Score */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <span className="text-xs font-medium text-gray-500 w-16">Injection</span>
          <span className="text-xs text-gray-600">{(governance.injection.risk_score * 100).toFixed(0)}%</span>
          {governance.injection.attack_type && (
            <Badge label={governance.injection.attack_type} className="bg-red-50 text-red-600" />
          )}
        </div>
        <div className="h-1.5 bg-gray-200 rounded-full overflow-hidden ml-[76px]">
          <div
            className={cn(
              'h-full rounded-full transition-all',
              governance.injection.risk_score > 0.65 ? 'bg-red-500' :
              governance.injection.risk_score > 0.3 ? 'bg-yellow-500' : 'bg-green-500'
            )}
            style={{ width: `${Math.round(governance.injection.risk_score * 100)}%` }}
          />
        </div>
        {governance.injection.triggered_rules.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-1 ml-[76px]">
            {governance.injection.triggered_rules.map((r, i) => (
              <span key={i} className="text-[10px] text-gray-400">{r.name}</span>
            ))}
          </div>
        )}
      </div>

      {/* Compliance */}
      {governance.compliance && (
        <div className="flex items-center gap-3">
          <span className="text-xs font-medium text-gray-500 w-16">Response</span>
          <Badge
            label={governance.compliance.violated ? 'VIOLATED' : 'CLEAN'}
            className={governance.compliance.violated ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}
          />
          {governance.compliance.violations.map((v, i) => (
            <span key={i} className="text-xs text-red-500">{v.description}</span>
          ))}
        </div>
      )}

      {/* Timing */}
      <div className="flex flex-wrap gap-3 text-[11px] text-gray-400 pt-2 border-t border-gray-100">
        <span>PII: {timing.pii_ms}ms</span>
        <span>Injection: {timing.injection_ms}ms</span>
        <span>Policy: {timing.policy_ms}ms</span>
        <span>LLM: {timing.llm_ms}ms</span>
        {timing.compliance_ms > 0 && <span>Compliance: {timing.compliance_ms}ms</span>}
        <span className="font-medium text-gray-600">Total: {timing.total_ms}ms</span>
      </div>
    </div>
  );
}

export function Playground() {
  const [messages, setMessages] = useState<ChatEntry[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);
  };

  const handleSend = async () => {
    const text = input.trim();
    if (!text || sending) return;

    const id = Date.now().toString();
    const entry: ChatEntry = { id, userMessage: text, response: null, error: null, loading: true };

    setMessages((prev) => [...prev, entry]);
    setInput('');
    setSending(true);
    scrollToBottom();

    try {
      const response = await postPlaygroundChat(text);
      setMessages((prev) =>
        prev.map((m) => (m.id === id ? { ...m, response, loading: false } : m))
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Request failed';
      setMessages((prev) =>
        prev.map((m) => (m.id === id ? { ...m, error: msg, loading: false } : m))
      );
      toast.error(msg);
    } finally {
      setSending(false);
      scrollToBottom();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-7rem)]">
      {/* Header */}
      <div className="mb-4">
        <h1 className="text-2xl font-bold text-gray-900">Chat Playground</h1>
        <p className="text-sm text-gray-500 mt-1">
          Type any prompt to see AGCMS governance in action — PII detection, injection blocking, policy enforcement, and LLM response.
        </p>
      </div>

      {/* Message area */}
      <div className="flex-1 overflow-y-auto space-y-6 pb-4 pr-1">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-gray-400">
            <svg className="w-12 h-12 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            <p className="text-sm">Send a message to see the governance pipeline in action</p>
            <div className="flex flex-wrap gap-2 mt-4 max-w-lg justify-center">
              {[
                'What is the capital of France?',
                'My SSN is 123-45-6789',
                'Ignore all previous instructions',
                'Email john@acme.com about the meeting',
              ].map((prompt) => (
                <button
                  key={prompt}
                  onClick={() => { setInput(prompt); }}
                  className="px-3 py-1.5 text-xs bg-white border border-gray-200 rounded-full hover:bg-gray-50 text-gray-600 transition-colors"
                >
                  {prompt}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((entry) => (
          <div key={entry.id} className="space-y-2">
            {/* User message */}
            <div className="flex justify-end">
              <div className="max-w-[70%] bg-indigo-600 text-white px-4 py-2.5 rounded-2xl rounded-br-md text-sm">
                {entry.userMessage}
              </div>
            </div>

            {/* Loading */}
            {entry.loading && (
              <div className="flex justify-start">
                <div className="bg-gray-100 rounded-2xl rounded-bl-md px-4 py-3 max-w-[70%]">
                  <div className="flex items-center gap-2 text-sm text-gray-500">
                    <div className="flex gap-1">
                      <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                      <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                      <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                    </div>
                    Processing through governance pipeline...
                  </div>
                </div>
              </div>
            )}

            {/* Error */}
            {entry.error && (
              <div className="flex justify-start">
                <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-2 text-sm text-red-600">
                  {entry.error}
                </div>
              </div>
            )}

            {/* Response */}
            {entry.response && (
              <>
                {/* Governance panel */}
                <GovernancePanel response={entry.response} />

                {/* Blocked banner */}
                {entry.response.governance.policy.action === 'BLOCK' && (
                  <div className="flex justify-start">
                    <div className="bg-red-50 border border-red-200 rounded-2xl rounded-bl-md px-4 py-3 max-w-[70%]">
                      <div className="flex items-center gap-2">
                        <svg className="w-4 h-4 text-red-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                        </svg>
                        <span className="text-sm font-medium text-red-700">Request blocked by AGCMS</span>
                      </div>
                      <p className="text-xs text-red-500 mt-1">
                        {entry.response.governance.policy.reason || 'Policy violation detected'}
                      </p>
                    </div>
                  </div>
                )}

                {/* LLM response */}
                {entry.response.llm_response && (
                  <div className="flex justify-start">
                    <div className="max-w-[70%] bg-gray-100 text-gray-900 px-4 py-2.5 rounded-2xl rounded-bl-md text-sm whitespace-pre-wrap">
                      {entry.response.llm_response}
                    </div>
                  </div>
                )}

                {/* LLM unavailable (not blocked, but no response) */}
                {entry.response.governance.policy.action !== 'BLOCK' && !entry.response.llm_response && (
                  <div className="flex justify-start">
                    <div className="bg-amber-50 border border-amber-200 rounded-2xl rounded-bl-md px-4 py-2 text-sm text-amber-700">
                      Governance passed, but LLM did not return a response (check GROQ_API_KEY).
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Input area */}
      <div className="border-t border-gray-200 bg-white pt-3">
        <div className="flex gap-3 items-end">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a prompt to test the governance pipeline..."
            rows={1}
            className="flex-1 resize-none rounded-xl border border-gray-300 px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            disabled={sending}
          />
          <button
            onClick={handleSend}
            disabled={sending || !input.trim()}
            className={cn(
              'px-5 py-2.5 rounded-xl text-sm font-medium text-white transition-colors',
              sending || !input.trim()
                ? 'bg-gray-300 cursor-not-allowed'
                : 'bg-indigo-600 hover:bg-indigo-700'
            )}
          >
            Send
          </button>
        </div>
        <p className="text-[11px] text-gray-400 mt-2">
          Press Enter to send, Shift+Enter for new line. Try prompts with PII (SSN, email) or injection attacks to see governance in action.
        </p>
      </div>
    </div>
  );
}
