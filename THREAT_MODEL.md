# Threat Model

## Manipulating Alerts and Model Instructions
One major threat is prompt injection. An attacker could place instructions inside an alert field, such as telling the model to ignore its rules, classify an attack as harmless, or choose auto_remediate. The pipeline cleans alert fields, limits them to 2,000 characters, wraps them in <alert_data> tags, and tells the model the content is data. It also flags known injection phrases, and a flag blocks suppression and automatic remediation. An attacker who phrases instructions differently could still avoid these checks, so the risk is reduced, not removed.

A related threat is delimiter forgery, where an alert contains text such as </alert_data> to make the data section look finished. The sanitizer removes these tags and marks the alert as suspicious.

Attackers could also try adversarial suppression by making a real attack look like a common false alarm. High and Critical alerts can never be suppressed. Other alerts need strong matching evidence from past incidents, enough confidence, and no injection flags, and every suppression is recorded in the audit log. A Medium-severity attack that closely resembles normal noise could still be missed. Reviewing a sample of suppressed alerts would help, but that is not implemented yet.

## Poisoning the Historical Incident Database
Another risk is poisoning the retrieval database. An attacker might add a false past incident that labels a real attack technique as benign, making the agent more likely to suppress similar attacks later. The database is loaded through an offline batch process and does not accept new records automatically, and weak retrieval results block suppression. This risk would grow if the database were updated automatically in production.

## Unsafe Agent Decisions and Actions
The intake agent might misclassify a serious alert, such as ransomware as Low, and the rest of the system could trust it. If intake fails, times out, or returns an invalid result, the alert is treated as Critical with zero confidence and sent to a human. The model also never sees the SIEM's original severity, so it cannot copy that label. A confident but wrong Low classification is still possible, so a production version would need to measure how often that happens.

Model output could also be unsafe, such as an unknown action name or a very long explanation. Outputs are checked against the allowed actions with Pydantic, unknown actions lead to escalation, and explanations are limited to 2,000 characters.

An agent should not have too much authority. The models cannot call remediation tools, and remediation is only simulated and logged. A High or Critical auto_remediate proposal never runs directly, even when the model is confident: if it passes the guardrail checks it waits in the approval queue for a human to approve or reject, and if it fails them it goes to analyst review. auto_remediate is also blocked outright for assets marked crown-jewel. Real tools would need restricted permissions and a separate approval process.

I also consider guardrail bypass, such as a model proposing automatic remediation for a Critical alert. The guardrails are deterministic code outside the model. A proposal must pass decision-confidence, intake-confidence, retrieval, injection, and asset checks, and eligible High or Critical proposals go to the approval queue. Decision confidence is self-reported and retrieval similarity is not a validated outcome, so these checks do not prove a remediation is safe.

## Availability, Privacy, and System Integrity
A flood of alerts could cause a denial-of-service or cost attack, since each alert needs several model calls. The system has timeouts and a retry limit, but no rate limiting or usage tracking yet.

Alert fields may contain usernames, internal IP addresses, and hostnames. Anthropic and GPT receive this information, including raw_log, and vLLM receives it through the ngrok tunnel. A production system would need rules about what can be shared and agreements with providers or a secured self-hosted model. The tunnel should also have its own access controls, because vLLM's API key alone does not protect every endpoint.

An exposed API key would let someone use the provider account. Keys are kept in environment variables, .env is excluded from Git, the example file contains no real keys, and the audit log does not record them.

An attacker could try to modify or delete audit records. Events go to a JSON lines file with timestamps and alert IDs, but in Docker the file lives inside the container and is lost when it is replaced, and nothing proves old entries were unchanged. Production would need protected storage that prevents deletion and modification.

## Human Approval and Long-Term Reliability
The approval interface is one of the largest remaining risks. The Gradio interface has no authentication, so anyone who can reach it could approve a remediation action, and the in-memory queue has no secure identity check. A real deployment would need login, role-based permissions, and possibly a second reviewer for destructive actions.

Approval fatigue is also possible: analysts who see too many requests may approve without reading. The interface shows the classification, the decision agent's reasoning, and the guardrail reasons together, and a production team would need to measure approval rates and review time.

Model drift or provider changes could reduce accuracy without an obvious error. The project has no automated evaluation to detect this.

There is also supply-chain risk from external packages and the Qdrant image. The project sets version ranges for its dependencies and pins Qdrant to v1.12.4, but production would also need lockfiles, signed images, and a software bill of materials.

## What Happens When Something Fails
When an important component fails, the system chooses the safer action. A failed intake becomes Critical with zero confidence and goes to a human. A failed decision agent or an unknown action is escalated to an analyst. If Qdrant or the embedder is unavailable, enrichment is marked weak, which blocks suppression and automatic remediation, as does detected prompt injection. These rules do not stop every bad classification, but they keep a component failure from directly causing an unsafe action.

## Future Improvements
This is a demo work product, so there is still a ton that could be improved with additional security measures and features. The most important improvement is authentication and role-based access on the approval interface, with extra approval for destructive actions and limited permissions plus a change process before any real remediation tool is connected. The system would also benefit from stronger audit storage, rate limiting, usage limits, more prompt injection and evasion tests whenever models or prompts change, periodic review of suppressed alerts, and removal of sensitive information before alerts reach external providers.