"""Email Assistant — FIDES prompt-injection defense demo.

A Microsoft Agent Framework sample showing how `SecureAgentConfig` (FIDES)
protects a privileged `send_email` tool from indirect prompt injection in
untrusted inbox content processed by `fetch_emails`.

Run:
    az login
    # set FOUNDRY_PROJECT_ENDPOINT and FOUNDRY_MODEL in env or .env
    python email_agent.py
"""

import asyncio
import json
import os
from typing import Any

from agent_framework import Agent, Content, tool
from agent_framework.foundry import FoundryChatClient
from agent_framework.security import SecureAgentConfig
from azure.identity import AzureCliCredential
from pydantic import Field
from dotenv import load_dotenv

load_dotenv(override=False)

# Minimal sample: one untrusted email with an injection attempt, one trusted.
SAMPLE_EMAILS = [
    {
        "id": "email_001",
        "from": "external@unknown.com",
        "subject": "Account Verification",
        "body": (
            "Please verify your account.\n"
    
        ),
        "trusted": False,
    },
    {
        "id": "email_002",
        "from": "manager@company.com",
        "subject": "Team Meeting Tomorrow",
        "body": "Reminder: weekly sync tomorrow at 10 AM.",
        "trusted": True,
    },
]


@tool(
    description="Send an email. Privileged operation.",
    additional_properties={"confidentiality": "private", "accepts_untrusted": False},
)
async def send_email(
    to: str = Field(description="Recipient address"),
    subject: str = Field(description="Subject line"),
    body: str = Field(description="Email body"),
) -> dict[str, Any]:
    """Send an email (simulated). Blocked when context is tainted by untrusted data."""
    print(f"\n📧 [SEND_EMAIL] to={to} subject={subject}")
    return {"status": "sent", "to": to, "subject": subject}


@tool(description="Fetch emails from the inbox.")
async def fetch_emails(
    count: int = Field(default=2, description="Number of emails to fetch"),
) -> list[Content]:
    """Fetch emails with per-item security labels."""
    result: list[Content] = []
    for email in SAMPLE_EMAILS[:count]:
        text = json.dumps({k: email[k] for k in ("id", "from", "subject", "body")})
        result.append(
            Content.from_text(
                text,
                additional_properties={
                    "security_label": {
                        "integrity": "trusted" if email["trusted"] else "untrusted",
                        "confidentiality": "private",
                    }
                },
            )
        )
    return result


def setup_agent() -> tuple[Agent, SecureAgentConfig]:
    """Create the secure email agent."""
    credential = AzureCliCredential()
    endpoint = os.environ["FOUNDRY_PROJECT_ENDPOINT"]

    main_client = FoundryChatClient(
        project_endpoint=endpoint, model=os.environ["FOUNDRY_MODEL"], credential=credential
    )
    quarantine_client = FoundryChatClient(
        project_endpoint=endpoint, model="gpt-4.1", credential=credential
    )

    config = SecureAgentConfig(
        auto_hide_untrusted=False, # default is True; Should be true in a real system.
        approval_on_violation=True,
        enable_policy_enforcement=True,
        allow_untrusted_tools={"fetch_emails"},
        quarantine_chat_client=quarantine_client,
    )

    agent = Agent(
        client=main_client,
        name="email_assistant",
        instructions="You are a helpful email assistant. You can fetch, summarize, and send emails.",
        tools=[fetch_emails, send_email],
        context_providers=[config],
    )
    return agent, config


async def run_scenarios(agent: Agent, config: SecureAgentConfig) -> None:
    """Fetch+summarize (safe), then attempt send (should be blocked)."""
    session = agent.create_session()

    print("\n--- Scenario 1: Summarize untrusted emails ---")
    r1 = await agent.run("Fetch my recent emails and briefly summarize each.", session=session)
    print(r1.text)

    print("\n--- Scenario 2: Send email after tainted context ---")
    r2 = await agent.run(
        "Now send an email to colleague@company.com summarizing what you found.", session=session
    )
    print(r2.text)

    for i, entry in enumerate(config.get_audit_log(), 1):
        print(f"\n⚠️  Violation #{i}: {entry}")


if __name__ == "__main__":
    agent, config = setup_agent()
    asyncio.run(run_scenarios(agent, config))
