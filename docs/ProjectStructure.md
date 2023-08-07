# Project Structure

**Crates:**

* `algebra-core` - Higher order abstractions
* `spectrum-network` - Networking framework
* `spectrum-mcast` - Impl of multicasting protocol
* `spectrum-handel` - Impl of Handel protocol
* `spectrum-diffusion` - Impl of diffusion protocol
* `spectrum-crypto` - Common crypto primitives
* `spectrum-ledger` - Ledger models and types
* `spectrum-vfr` - VRF impl
* `spectrum-kes` - KES impl
* `spectrum-sigma` - Impl of Sigma Aggregation protocol
* `spectrum-view` - View of the ledger state
* `spectrum-consensus` - Consensus rules
* `spectrum-node` - Wired Node App

**Dependency graph:**

```mermaid
flowchart TD
    SN[spectrum-network]
    SM[spectrum-mcast]
    AC[algebra-core]
    SH[spectrum-handel]
    SD[spectrum-diffusion]
    SC[spectrum-crypto]
    SL[spectrum-ledger]
    SV[spectrum-vfr]
    SK[spectrum-kes]
    SS[spectrum-sigma]
    SVI[spectrum-view]
    SI[spectrum-node]
    SCS[spectrum-consensus]
    SL --> SS
    SL --> SV
    SL --> SK
    SH --> SN
    SM --> SN
    SD --> SN
    SS --> AC
    SS --> SH
    SS --> SM
    SK --> SC
    SV --> SC
    SM --> SC
    SH --> SC
    SVI --> SL
    SI --> SD
    SD --> SVI
    SCS --> SVI
    SI --> SCS
```
