use super::integer::IntegerConfig;
use super::main_gate::MainGateConfig;

mod base_field_ecc;
mod general_ecc;

#[derive(Clone, Debug)]
pub struct EccConfig {
    integer_chip_config: IntegerConfig,
    main_gate_config: MainGateConfig,
}
