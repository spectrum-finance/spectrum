pub trait ProtocolParams {
    fn fk(&self) -> u64;
    fn base_vrf_range(&self) -> u32;
    fn consensus_selection_frac(&self) -> (u32, u32);
}
