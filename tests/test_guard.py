import pytest
from agent_guard_proxy.budget import BudgetConfig, BudgetGuard, BudgetViolation
from agent_guard_proxy.dlp import DLPFilter, SecretType
from agent_guard_proxy.proxy import MCPGuardProxy
from agent_guard_proxy.rate_limiter import RateLimitExceeded, SlidingWindowRateLimiter


def test_dlp_secret_redaction():
    filter = DLPFilter(redact_mode=True)
    text = "Deploying with key sk-ant-abcdef1234567890abcdef1234567890 and stellar seed SBWKGXJ2A2QYGYLUSV2N77S77G77OQ4L75J7NZ35ZOP5Z36K7U7NILK7"
    cleaned, viols = filter.redact_text(text)

    assert len(viols) == 2
    assert "sk-ant" in viols[0].matched_snippet
    assert "SBWK" in viols[1].matched_snippet
    assert "sk-ant-abcdef1234567890abcdef1234567890" not in cleaned
    assert "SBWKGXJ2A2QYGYLUSV2N77S77G77OQ4L75J7NZ35ZOP5Z36K7U7NILK7" not in cleaned


def test_rate_limiter_enforcement():
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=10.0)
    client = "agent_worker_1"

    limiter.record_request(client, timestamp=100.0)
    limiter.record_request(client, timestamp=101.0)
    limiter.record_request(client, timestamp=102.0)

    # 4th request must fail
    with pytest.raises(RateLimitExceeded):
        limiter.record_request(client, timestamp=103.0)

    # After window moves past 110.1s, should succeed
    limiter.record_request(client, timestamp=111.0)


def test_budget_ceiling_enforcement():
    cfg = BudgetConfig(max_session_cost_usd=0.01, max_session_tokens=500)
    guard = BudgetGuard(cfg)

    # Small call
    guard.track_call({"data": "short text"})
    assert guard.total_calls == 1

    # Massive call that exceeds budget
    huge_payload = {"data": "A" * 10_000}
    with pytest.raises(BudgetViolation):
        guard.track_call(huge_payload)


def test_mcp_guard_proxy_full_cycle():
    proxy = MCPGuardProxy(
        rate_limit_rpm=5,
        budget_config=BudgetConfig(max_session_cost_usd=1.0),
        redact_dlp=True,
        block_on_secret_leak=False,
    )

    call = {
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {
                "command": "echo 'GitHub token: ghp_111122223333444455556666777788889999'",
            },
        },
    }

    res = proxy.intercept_request(call)
    assert res.allowed is True
    assert len(res.dlp_violations) == 1
    # Check that the token in arguments was redacted
    cmd = res.sanitized_message["params"]["arguments"]["command"]
    assert "ghp_111122223333444455556666777788889999" not in cmd
    assert "****" in cmd

    # Test response tracking
    resp = {
        "jsonrpc": "2.0",
        "id": "call-1",
        "result": {
            "content": "Secret exposed: sk-ant-secretkey999988887777666655554444",
        },
    }
    clean_resp, viols = proxy.intercept_response(resp)
    assert len(viols) == 1
    assert "sk-ant-secretkey999988887777666655554444" not in str(clean_resp)
    assert proxy.budget_guard.total_tokens_consumed > 0
