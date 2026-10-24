# PhishGuard reasoning report

*Knowledge base:* PhishGuard scam-message rules v1.0 · 48 rules · threshold 0.2

## Signals found

| Signal | Status | Certainty |
|---|---|---|
| Pushes you to act immediately or within hours | detected | +1.00 |
| Threatens suspension, locking, fines or legal action | detected | +1.00 |
| Asks you to log in, verify an account or share a password or code | detected | +1.00 |
| Generic greeting such as "Dear customer" | detected | +1.00 |
| Claims to be from a known company or bank | detected | +1.00 |
| Link or sender uses a lookalike of a real brand's domain | detected | +1.00 |
| Sender's address does not belong to the company it names | detected | +1.00 |
| Replies would go to a different domain than the sender | detected | +1.00 |
| Contains web links | detected | +1.00 |
| Link uses plain http:// instead of https:// | detected | +1.00 |
| Names a company but links to a website that is not theirs | detected | +1.00 |

## What to do

| # | Priority | Recommendation | Certainty |
|---|---|---|---|
| 1 | DANGER | Do not click the link or enter any password or code. If you already did, change that password now and turn on two-factor authentication. | 0.98 (certain) |
| 2 | CAUTION | Contact the company using the app, website or phone number you already know, not the details in this message. | 0.89 (very likely) |
| 3 | CAUTION | Hover over (or long-press) the link to see its real address before doing anything. Type the official address yourself instead. | 0.83 (very likely) |
| 4 | ADVICE | Report the message as phishing in your email app (or forward scam texts to your carrier's spam number), then delete it. | 0.98 (certain) |
| 5 | ADVICE | Scammers rely on urgency. A genuine deadline will survive a few minutes of checking. | 0.77 (likely) |

## Conclusions

| Conclusion | Certainty |
|---|---|
| Pretends to be a trusted organisation | 0.99 (certain) |
| Credential phishing (tries to steal your login) | 0.98 (certain) |
| Uses pressure to rush you | 0.96 (certain) |
| Contains a dangerous link | 0.93 (very likely) |
| Sender identity looks forged | 0.88 (very likely) |
| High-risk, multi-signal scam | 0.87 (very likely) |

## Inference trace

| Step | Rule | IF | THEN | CF |
|---|---|---|---|---|
| 1 | S4 | `claims_brand` ∧ `lookalike_domain` | `impersonation` | 0.85 |
| 2 | S6 | `claims_brand` ∧ `generic_greeting` | `impersonation` | 0.90 |
| 3 | S7 | `claims_brand` ∧ `brand_link_mismatch` | `impersonation` | 0.97 |
| 4 | L5 | `lookalike_domain` ∧ `has_links` | `risky_link` | 0.85 |
| 5 | L7 | `insecure_link` ∧ `asks_credentials` | `risky_link` | 0.93 |
| 6 | T1 | `urgent_tone` ∧ `threat_language` | `pressure_tactics` | 0.85 |
| 7 | S1 | `sender_mismatch` | `sender_spoofing` | 0.70 |
| 8 | S2 | `reply_to_mismatch` | `sender_spoofing` | 0.88 |
| 9 | T2 | `urgent_tone` | `pressure_tactics` | 0.93 |
| 10 | T3 | `threat_language` | `pressure_tactics` | 0.96 |
| 11 | S3 | `claims_brand` ∧ `sender_spoofing` | `impersonation` | 0.99 |
| 12 | C11 | `asks_credentials` ∧ `pressure_tactics` | `credential_phishing` | 0.53 |
| 13 | A10 | `pressure_tactics` | `slow_down` | 0.77 |
| 14 | C1 | `asks_credentials` ∧ `impersonation` | `credential_phishing` | 0.93 |
| 15 | C2 | `asks_credentials` ∧ `risky_link` | `credential_phishing` | 0.98 |
| 16 | A7 | `impersonation` | `verify_independently` | 0.89 |
| 17 | A8 | `risky_link` | `check_link_destination` | 0.83 |
| 18 | X1 | `credential_phishing` ∧ `pressure_tactics` | `targeted_attack` | 0.87 |
| 19 | A1 | `credential_phishing` | `dont_enter_credentials` | 0.98 |
| 20 | A12 | `credential_phishing` | `report_message` | 0.88 |
| 21 | A11 | `targeted_attack` | `report_message` | 0.98 |

## How each recommendation was reached

```text
dont_enter_credentials  [CF 0.98]  Do not click the link or enter any password or code. If you already did, change that password now and turn on two-factor authentication.
└─ credential_phishing  [CF 0.98]  Credential phishing (tries to steal your login)   → A1
   ├─ asks_credentials: detected   → C11
   ├─ pressure_tactics  [CF 0.96]  Uses pressure to rush you   → C11
   │  ├─ urgent_tone: detected   → T1
   │  ├─ threat_language: detected   → T1
   │  ├─ urgent_tone: detected   → T2
   │  └─ threat_language: detected   → T3
   ├─ asks_credentials: detected   → C1
   ├─ impersonation  [CF 0.99]  Pretends to be a trusted organisation   → C1
   │  ├─ claims_brand: detected   → S4
   │  ├─ lookalike_domain: detected   → S4
   │  ├─ claims_brand: detected   → S6
   │  ├─ generic_greeting: detected   → S6
   │  ├─ claims_brand: detected   → S7
   │  ├─ brand_link_mismatch: detected   → S7
   │  ├─ claims_brand: detected   → S3
   │  └─ sender_spoofing  [CF 0.88]  Sender identity looks forged   → S3
   │     ├─ sender_mismatch: detected   → S1
   │     └─ reply_to_mismatch: detected   → S2
   ├─ asks_credentials: detected   → C2
   └─ risky_link  [CF 0.93]  Contains a dangerous link   → C2
      ├─ lookalike_domain: detected   → L5
      ├─ has_links: detected   → L5
      ├─ insecure_link: detected   → L7
      └─ asks_credentials: detected   → L7
```

```text
verify_independently  [CF 0.89]  Contact the company using the app, website or phone number you already know, not the details in this message.
└─ impersonation  [CF 0.99]  Pretends to be a trusted organisation   → A7
   ├─ claims_brand: detected   → S4
   ├─ lookalike_domain: detected   → S4
   ├─ claims_brand: detected   → S6
   ├─ generic_greeting: detected   → S6
   ├─ claims_brand: detected   → S7
   ├─ brand_link_mismatch: detected   → S7
   ├─ claims_brand: detected   → S3
   └─ sender_spoofing  [CF 0.88]  Sender identity looks forged   → S3
      ├─ sender_mismatch: detected   → S1
      └─ reply_to_mismatch: detected   → S2
```

```text
check_link_destination  [CF 0.83]  Hover over (or long-press) the link to see its real address before doing anything. Type the official address yourself instead.
└─ risky_link  [CF 0.93]  Contains a dangerous link   → A8
   ├─ lookalike_domain: detected   → L5
   ├─ has_links: detected   → L5
   ├─ insecure_link: detected   → L7
   └─ asks_credentials: detected   → L7
```

```text
report_message  [CF 0.98]  Report the message as phishing in your email app (or forward scam texts to your carrier's spam number), then delete it.
├─ credential_phishing  [CF 0.98]  Credential phishing (tries to steal your login)   → A12
│  ├─ asks_credentials: detected   → C11
│  ├─ pressure_tactics  [CF 0.96]  Uses pressure to rush you   → C11
│  │  ├─ urgent_tone: detected   → T1
│  │  ├─ threat_language: detected   → T1
│  │  ├─ urgent_tone: detected   → T2
│  │  └─ threat_language: detected   → T3
│  ├─ asks_credentials: detected   → C1
│  ├─ impersonation  [CF 0.99]  Pretends to be a trusted organisation   → C1
│  │  ├─ claims_brand: detected   → S4
│  │  ├─ lookalike_domain: detected   → S4
│  │  ├─ claims_brand: detected   → S6
│  │  ├─ generic_greeting: detected   → S6
│  │  ├─ claims_brand: detected   → S7
│  │  ├─ brand_link_mismatch: detected   → S7
│  │  ├─ claims_brand: detected   → S3
│  │  └─ sender_spoofing  [CF 0.88]  Sender identity looks forged   → S3
│  │     ├─ sender_mismatch: detected   → S1
│  │     └─ reply_to_mismatch: detected   → S2
│  ├─ asks_credentials: detected   → C2
│  └─ risky_link  [CF 0.93]  Contains a dangerous link   → C2
│     ├─ lookalike_domain: detected   → L5
│     ├─ has_links: detected   → L5
│     ├─ insecure_link: detected   → L7
│     └─ asks_credentials: detected   → L7
└─ targeted_attack  [CF 0.87]  High-risk, multi-signal scam   → A11
   ├─ credential_phishing  [CF 0.98]  Credential phishing (tries to steal your login)   → X1
   │  ├─ asks_credentials: detected   → C11
   │  ├─ pressure_tactics  [CF 0.96]  Uses pressure to rush you   → C11
   │  │  ├─ urgent_tone: detected   → T1
   │  │  ├─ threat_language: detected   → T1
   │  │  ├─ urgent_tone: detected   → T2
   │  │  └─ threat_language: detected   → T3
   │  ├─ asks_credentials: detected   → C1
   │  ├─ impersonation  [CF 0.99]  Pretends to be a trusted organisation   → C1
   │  │  ├─ claims_brand: detected   → S4
   │  │  ├─ lookalike_domain: detected   → S4
   │  │  ├─ claims_brand: detected   → S6
   │  │  ├─ generic_greeting: detected   → S6
   │  │  ├─ claims_brand: detected   → S7
   │  │  ├─ brand_link_mismatch: detected   → S7
   │  │  ├─ claims_brand: detected   → S3
   │  │  └─ sender_spoofing  [CF 0.88]  Sender identity looks forged   → S3
   │  │     ├─ sender_mismatch: detected   → S1
   │  │     └─ reply_to_mismatch: detected   → S2
   │  ├─ asks_credentials: detected   → C2
   │  └─ risky_link  [CF 0.93]  Contains a dangerous link   → C2
   │     ├─ lookalike_domain: detected   → L5
   │     ├─ has_links: detected   → L5
   │     ├─ insecure_link: detected   → L7
   │     └─ asks_credentials: detected   → L7
   └─ pressure_tactics  [CF 0.96]  Uses pressure to rush you   → X1
      ├─ urgent_tone: detected   → T1
      ├─ threat_language: detected   → T1
      ├─ urgent_tone: detected   → T2
      └─ threat_language: detected   → T3
```

```text
slow_down  [CF 0.77]  Scammers rely on urgency. A genuine deadline will survive a few minutes of checking.
└─ pressure_tactics  [CF 0.96]  Uses pressure to rush you   → A10
   ├─ urgent_tone: detected   → T1
   ├─ threat_language: detected   → T1
   ├─ urgent_tone: detected   → T2
   └─ threat_language: detected   → T3
```


> Educational rule-based analysis: a verdict is an assessment of warning signs, not proof. When in doubt, contact the organisation through a channel you already trust.
