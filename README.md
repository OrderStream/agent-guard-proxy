# agent-guard-proxy

Enterprise reverse proxy and firewall middleware for Model Context Protocol (MCP) JSON-RPC tool calls.

## Key Capabilities
- **Strict Rate Limiting**: High-speed in-memory sliding-window token bucket preventing agent runaway loops and API quota exhaustion.
- **Token & Cost Budget Guard**: Calculates prompt & completion tokens in real-time, enforcing strict monetary cost caps ($USD) and token ceilings per autonomous session.
- **Enterprise DLP (Data Loss Prevention)**: Deep regex & pattern matching for API keys (OpenAI, Anthropic, AWS, GitHub), Stellar secret seeds (`S...`), and private keys, preventing credential leakage in tool arguments and outputs.
- **JSON-RPC 2.0 Compliance**: Seamlessly integrates into any MCP client (Cursor, Claude Code, LangChain, custom autonomous agents).

## CLI Usage
```bash
# Check a JSON-RPC tool call
agent-guard-proxy check --json '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run","arguments":{"cmd":"curl https://api.com -H \"Authorization: Bearer sk-ant-api03-abcdef1234567890abcdef1234567890\""}}}'

# Redact secrets from text
agent-guard-proxy redact --text "AWS key is AKIA1234567890ABCDEF and secret is..."
```
