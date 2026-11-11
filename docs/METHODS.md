# Injection methods and the sensor for each

The rule engine was written against published descriptions of how instructions are injected into text an agent reads. This table maps each method to the rule that answers it, or says that none does. `xksid rules` prints the rules with their weights; a turn is an alert at a total of 6.

## Sources

- Maloyan, Namiot: *Prompt Injection Attacks on Agentic Coding Assistants*, arXiv 2601.17548. Delivery vectors, modalities.
- Wang et al.: *The Landscape of Prompt Injection Threats in LLM Agents*, arXiv 2602.10453. 37 attack papers by payload method.
- Alon, Kamfonas: *Taxonomy, Evaluation and Exploitation of IPI-Centric LLM Agent Defense Frameworks*, arXiv 2511.15203. Template attacks of the benchmarks.
- Cloud Security Alliance: *Hidden Unicode Instruction Injection in AI Agent Skills* (research note, March 2026). Tag characters, zero-width encodings, look-alike letters.
- Swanda: *Understanding and Mitigating Unicode Tag Prompt Injection*, Cisco blog, 2024. Tag block byte range.
- Beurer-Kellner, Fischer: *MCP Security Notification: Tool Poisoning Attacks*, Invariant Labs, 2025.
- OWASP: *Secure Coding with AI Cheat Sheet*; *MCP Tool Poisoning*. Carriers in the development loop.

## Wording

| Method | Rule |
|---|---|
| Instruction negation: an override verb aimed at the earlier instructions | X301 |
| Role hijacking, context override: text that addresses an AI and overrides or orders | X302 |
| Concealment that names the user ("do not tell the user") | X303, alone |
| Hierarchy exploitation: a claimed system notice or authority next to instructions or an AI addressee | X304, S203 |
| Exfiltration order addressed to an AI | X305 |
| Priority framing of tool poisoning ("before using this tool", "important") next to a secret, an upload or a quiet concealment order | X306 |
| The benchmark template: four urgent-order phrases stacked | X307 |
| A credential file named next to an AI addressee or a concealment order | X308 |
| Memory poisoning: an order to keep something for later sessions | X309, alone |
| Completion attack: the task is declared finished and a new one begins | X310 |

A single phrase never fires a rule, with two exceptions marked "alone". Everything else needs two classes of wording close together, because recorded tool output is full of words like "important", "ignore" and `~/.ssh`.

## Hidden characters

| Method | Rule |
|---|---|
| Unicode tag block, U+E0000 to U+E007F, spelling invisible ASCII | U101; the hidden text is decoded and read (D002). Tag characters that follow a black flag form a flag emoji and are left alone |
| Zero-width characters inside words, to break keyword matching | U103; the normaliser removes them, so the wording rules still see the phrase |
| Zero-width bit streams (zero-width space = 0, non-joiner = 1) in an apparently blank line | U106; the bits are decoded and read (D002) |
| Bidirectional controls | U102 |
| Variation-selector runs | U104 |
| Look-alike letters of Greek and Cyrillic, full-width letters | U105; the normaliser writes them as Latin, so the wording rules still see the phrase |

## Encodings

| Method | Rule |
|---|---|
| Base64 | D001 |
| Hexadecimal, groups of binary digits | D003 |
| ROT13 | D004 |

Decoded text fires its rule only if the wording rules score it at 5 or more.

## Structure and sinks

| Method | Rule |
|---|---|
| Harness tags inside recorded text | S201 |
| Chat-template control tokens (the "ChatInject" family) | S202 |
| Tool-call or role markup that imitates the conversation | S205 |
| Hidden-render markup with instruction wording | S204 |
| Data carried out in the query string of an image link, markdown or HTML | K501 |
| A download piped into a shell | K502 |

## Not answered by the rules

| Method | Why | What remains |
|---|---|---|
| Optimised adversarial strings (gradient or search based) | They are not wording, and tool output is full of unreadable strings | The vector layer, unmeasured for this case |
| Poisoned MCP tool descriptions, changed after approval | Tool definitions are not turns; XKS-Memory does not record them | Nothing. The result of calling such a tool is a tool result and is read |
| Other languages | The phrase lists are English | The vector layer; the model behind it covers 16 languages |
| A payload split over several turns | Each turn is read by itself | Nothing |
| Leetspeak, ASCII art | Not decoded | The vector layer, unmeasured |
| A false statement with no instruction | There is nothing to match | Nothing |
