# Interoperability flow withing Spectrum

Relevant Types:

- `Mode = Leader | Member | Idle`
- `Slot = u64`
- `ForeignTx = ForeignTx { .. }` // Foreign transaction
- `IEff = InboundCreated(..) | OutboundCertified(..) | Eliminated(..)` // How [ForeignTx] affects Spectrum state
- `GEff = Programmable(...)` // How [InternalTx] affects Spectrum state
- `ForeignView = Set{H(IEff)}` // Local state to track updates from foreign system
- `GlobalView = Set{H(GEff)}` // Global state
- `IEff = InboundCreated(..) | OutboundCertified(..) | Eliminated(..)` // How [ForeignTx] affects Spectrum state

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
   - Else: Skip.
5. `Consensus`:
   - If `mode = Leader`: Upon collection of enough effects: batch buffer content; propose the batch; flush the buffer;
     aggregate cert.
   - If `mode = Member`: Upon receival of batch proposal: validate the batch against local `ForeignView`; aggregate
     cert.
   - Else: Skip.
6. `Consensus`:
   - If `mode = Leader`: Upon successful notarization: send the batch to known peers from other local committees; apply the batch to `NodeView`.
   - If `mode = Member`: Upon successful notarization: send the batch to the leader; send the batch to known peers from other local committees; apply the batch to `NodeView`.
   - Else: Skip.
7. `Consensus`:
   * If `mode = Leader | Member`: Continuously receive batches from members of other local committees and save them to a buffer; send the received batches to the local known peers.
   * Else: Skip.
8. `Consensus`:
   * If `mode = Leader`: Upon collecting enough local batches and batches from other local committees form a block with all the batches and internal transactions included; sign the block; broadcast the block to all known peers; apply the block to `NodeView`; flush the buffer.
   * If `mode = Member`: Upon recieving the block validate it against the local `GlobalView`; apply the block to `NodeView`; flush the buffer.
   * Else: Skip.
9. `NodeView`: First the batch is applied to interop history, when it's included in the block by the leader with all other batches and internal updates and when the block is applied to the global Spectrum state.
