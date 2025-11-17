# Entra ID P2 Licensing Audit Tool

This repository provides a PowerShell audit tool to identify:

1. **Which users are legitimately licensed for Entra ID P2**
2. **Which users are benefitting from P2-only features**
3. **Which users are in scope of P2-based Conditional Access (risk-based policies)**
4. **Which users are in scope of Identity Protection (optional)**
5. **Which users are UNLICENSED but benefitting from P2 functionality**  
   → This is the key discrepancy behind the typical “700 users using P2” vs “31 P2 licences owned” problem.

Microsoft Entra licensing is **trust-based**, meaning Microsoft does not hard-block P2 features for unlicensed users.  
This tool highlights that gap clearly.

---

## 🚀 What This Tool Does

### ✔ Identifies users legitimately licensed with:
- **Entra ID P2**
- **Microsoft 365 E5** (includes P2 rights)

### ✔ Analyses Conditional Access policies that use:
- **Sign-in risk**
- **User risk**

> These are P2-only features and a major driver of inflated utilisation reports.

### ✔ Optionally analyses Identity Protection risky users:
- Risky Users API  
- Risk Detections API  
*(requires extra scopes)*

### ✔ Produces four CSV reports:
| File | Description |
|------|-------------|
| **P2LicensedUsers.csv** | Users legitimately licensed for P2/E5 |
| **P2FeatureScopedUsers.csv** | Users affected by P2-only CA policies |
| **P2BenefittingNoP2License.csv** | Users benefitting from P2 *without* P2/E5 licences |
| **RiskyUsersNoP2License.csv** | (optional) Identity Protection risky users without licensing |

---

## 📦 Requirements

- PowerShell 7 recommended (Windows PowerShell also works)
- Microsoft Graph PowerShell SDK

Install the SDK:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

---

## 🔐 Permissions Required

The script will request Microsoft Graph scopes:

- `User.Read.All`
- `Directory.Read.All`
- `Policy.Read.All`
- `IdentityRiskyUser.Read.All` (optional)
- `IdentityRiskEvent.Read.All` (optional)

Admins typically use:
- **Global Administrator**
- **Security Administrator**
- **Reports Reader**
- **Conditional Access Administrator**

---

## ▶️ Usage

### Basic usage

```powershell
.\Analyse-EntraP2Usage.ps1 -OutputPath "C:\Reports\P2"
```

### Include Identity Protection analysis

```powershell
.\Analyse-EntraP2Usage.ps1 -OutputPath "C:\Reports\P2" -IncludeIdentityProtection
```

---

## 📁 Output Example

```
C:\Reports\P2│
├── P2LicensedUsers.csv
├── P2FeatureScopedUsers.csv
├── P2BenefittingNoP2License.csv
└── RiskyUsersNoP2License.csv   (if enabled)
```

---

## 📊 Why This Tool Exists

Microsoft’s licence utilisation reports count **any user in scope of a P2 feature**, not just those assigned a P2 SKU.

This often results in:

> “Why does Microsoft say 700 users are using P2 when we only bought 31 licences?”

The answer is normally:
- **Risk-based Conditional Access** policies apply tenant-wide
- **Identity Protection** signals apply to all users
- **P2 features are enabled for unlicensed users**
- The tenant operates under Microsoft’s trust-based licensing model

This tool surfaces the exact users affected.

---

## 📚 Notes & Best Practice

To align P2 usage with licensing:

- Create a group like  
  **`entra-p2-licensed-users`**
- Assign P2/E5 licences to that group
- Scope all P2-only CA policies to that group
- Remove “All Users” from any policy using:
  - Sign-in risk
  - User risk
  - Identity Protection requirements  
- Re-run this script to confirm usage matches licence count

---

## 📝 License

MIT License

---

## 🤝 Contributing

Pull requests welcome.  
If you want this extended (PIM, Access Reviews, Entitlement Management), raise an issue.
