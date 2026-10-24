# PhishGuard reasoning report

*Knowledge base:* PhishGuard scam-message rules v1.0 · 48 rules · threshold 0.2

## Signals found

| Signal | Status | Certainty |
|---|---|---|
| Pushes you to act immediately or within hours | probably present | +0.80 |
| Asks you to keep it confidential or not tell anyone | detected | +1.00 |
| Asks for a payment, fee, gift cards or crypto | detected | +1.00 |
| Claims to be from a known company or bank | probably present | +0.80 |
| A company is writing from a free email account (Gmail, Outlook…) | detected | +1.00 |

## What to do

| # | Priority | Recommendation | Certainty |
|---|---|---|---|
| 1 | DANGER | Do not pay, buy gift cards or send crypto. Genuine organisations do not ask for payment this way. | 0.96 (certain) |
| 2 | CAUTION | Check the request with the person directly, by phone or face to face, before acting on it. | 0.85 (very likely) |
| 3 | CAUTION | Contact the company using the app, website or phone number you already know, not the details in this message. | 0.50 (possible) |
| 4 | ADVICE | Report the message as phishing in your email app (or forward scam texts to your carrier's spam number), then delete it. | 0.84 (very likely) |
| 5 | ADVICE | Scammers rely on urgency. A genuine deadline will survive a few minutes of checking. | 0.61 (likely) |

## Conclusions

| Conclusion | Certainty |
|---|---|
| Boss / CEO impersonation scam | 0.85 (very likely) |
| Payment scam | 0.76 (likely) |
| Uses pressure to rush you | 0.76 (likely) |
| Pretends to be a trusted organisation | 0.56 (possible) |
| High-risk, multi-signal scam | 0.48 (possible) |

## Inference trace

| Step | Rule | IF | THEN | CF |
|---|---|---|---|---|
| 1 | S5 | `claims_brand` ∧ `free_mail_brand` | `impersonation` | 0.56 |
| 2 | C9 | `secrecy_request` ∧ `asks_payment` | `ceo_fraud` | 0.85 |
| 3 | T2 | `urgent_tone` | `pressure_tactics` | 0.40 |
| 4 | T5 | `secrecy_request` | `pressure_tactics` | 0.76 |
| 5 | C3 | `asks_payment` ∧ `pressure_tactics` | `payment_scam` | 0.57 |
| 6 | A4 | `ceo_fraud` | `dont_pay` | 0.85 |
| 7 | A9 | `ceo_fraud` | `confirm_with_sender` | 0.85 |
| 8 | A10 | `pressure_tactics` | `slow_down` | 0.61 |
| 9 | C4 | `asks_payment` ∧ `impersonation` | `payment_scam` | 0.76 |
| 10 | A7 | `impersonation` | `verify_independently` | 0.50 |
| 11 | X2 | `payment_scam` ∧ `impersonation` | `targeted_attack` | 0.48 |
| 12 | A2 | `payment_scam` | `dont_pay` | 0.96 |
| 13 | A13 | `payment_scam` | `report_message` | 0.69 |
| 14 | A11 | `targeted_attack` | `report_message` | 0.84 |

## How each recommendation was reached

```text
dont_pay  [CF 0.96]  Do not pay, buy gift cards or send crypto. Genuine organisations do not ask for payment this way.
├─ ceo_fraud  [CF 0.85]  Boss / CEO impersonation scam   → A4
│  ├─ secrecy_request: detected   → C9
│  └─ asks_payment: detected   → C9
└─ payment_scam  [CF 0.76]  Payment scam   → A2
   ├─ asks_payment: detected   → C3
   ├─ pressure_tactics  [CF 0.76]  Uses pressure to rush you   → C3
   │  ├─ urgent_tone: probably present (0.80)   → T2
   │  └─ secrecy_request: detected   → T5
   ├─ asks_payment: detected   → C4
   └─ impersonation  [CF 0.56]  Pretends to be a trusted organisation   → C4
      ├─ claims_brand: probably present (0.80)   → S5
      └─ free_mail_brand: detected   → S5
```

```text
confirm_with_sender  [CF 0.85]  Check the request with the person directly, by phone or face to face, before acting on it.
└─ ceo_fraud  [CF 0.85]  Boss / CEO impersonation scam   → A9
   ├─ secrecy_request: detected   → C9
   └─ asks_payment: detected   → C9
```

```text
verify_independently  [CF 0.50]  Contact the company using the app, website or phone number you already know, not the details in this message.
└─ impersonation  [CF 0.56]  Pretends to be a trusted organisation   → A7
   ├─ claims_brand: probably present (0.80)   → S5
   └─ free_mail_brand: detected   → S5
```

```text
report_message  [CF 0.84]  Report the message as phishing in your email app (or forward scam texts to your carrier's spam number), then delete it.
├─ payment_scam  [CF 0.76]  Payment scam   → A13
│  ├─ asks_payment: detected   → C3
│  ├─ pressure_tactics  [CF 0.76]  Uses pressure to rush you   → C3
│  │  ├─ urgent_tone: probably present (0.80)   → T2
│  │  └─ secrecy_request: detected   → T5
│  ├─ asks_payment: detected   → C4
│  └─ impersonation  [CF 0.56]  Pretends to be a trusted organisation   → C4
│     ├─ claims_brand: probably present (0.80)   → S5
│     └─ free_mail_brand: detected   → S5
└─ targeted_attack  [CF 0.48]  High-risk, multi-signal scam   → A11
   ├─ payment_scam  [CF 0.76]  Payment scam   → X2
   │  ├─ asks_payment: detected   → C3
   │  ├─ pressure_tactics  [CF 0.76]  Uses pressure to rush you   → C3
   │  │  ├─ urgent_tone: probably present (0.80)   → T2
   │  │  └─ secrecy_request: detected   → T5
   │  ├─ asks_payment: detected   → C4
   │  └─ impersonation  [CF 0.56]  Pretends to be a trusted organisation   → C4
   │     ├─ claims_brand: probably present (0.80)   → S5
   │     └─ free_mail_brand: detected   → S5
   └─ impersonation  [CF 0.56]  Pretends to be a trusted organisation   → X2
      ├─ claims_brand: probably present (0.80)   → S5
      └─ free_mail_brand: detected   → S5
```

```text
slow_down  [CF 0.61]  Scammers rely on urgency. A genuine deadline will survive a few minutes of checking.
└─ pressure_tactics  [CF 0.76]  Uses pressure to rush you   → A10
   ├─ urgent_tone: probably present (0.80)   → T2
   └─ secrecy_request: detected   → T5
```


> Educational rule-based analysis: a verdict is an assessment of warning signs, not proof. When in doubt, contact the organisation through a channel you already trust.
