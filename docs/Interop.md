# Interoperability flow withing Spectrum

Relevant Types:

- `Mode = Leader | Member | Idle`
- `Slot = u64`
- `ForeignTx = ForeignTx { .. }` // Foreign transaction
- `IEff = InboundCreated(..) | OutboundCertified(..) | Eliminated(..)` // How [ForeignTx] affects Spectrum state
- `ForeignView = Set{H(IEff)}` // Local state to track updates from foreign system

Relevant components:

- `Adapter::Bridge`
    - State:
        - `mode: Mode`
        - `slot: Slot`
        - `buff: [IEff]`
- `NodeView`
- `Consensus: ProtocolHandler`

We now step-by-step describe how foreign transactions are processed by Spectrum.

1. `Adapter::Bridge`: Read `[ForeignTx]` from L1
2. `Adapter::Bridge`: Project `[ForeignTx] => [IEff]`
3. `Adapter::Bridge`: Stream `[IEff]` to `Consensus`
4. `Consensus`:
    - If `mode = Leader`: Buffer `[IEff]`
    - If `mode = Member`: Project `[IEff]` onto `ForeignView`
    - Else: Skip
5. `Consensus`:
    - If `mode = Leader`: Upon collection of enough effects: batch buffer content; propose the batch; flush the buffer;
      aggregate cert.
    - If `mode = Member`: Upon receival of batch proposal: validate the batch against local `ForeignView`; aggregate
      cert.
    - Else: Skip
6. `Consensus`:
    - If `mode = Leader`: Upon successful notarization: apply the batch to `NodeView`.
    - If `mode = Member`: Upon successful notarization: send the batch to leader; apply the batch to `NodeView`.
    - Else: Skip
7. `NodeView`: First the batch is applied to interop history, when it's mature enough it's moved to global history and is applied to Spectrum state.
