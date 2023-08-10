pub trait ProtocolParams {
    fn fk(&self) -> u64;
    fn base_vrf_range(&self) -> u32;
}
