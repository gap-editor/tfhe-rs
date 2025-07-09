use super::dp_ks_modswitch::dp_ks_modswitch;
use super::utils::traits::*;
use crate::core_crypto::commons::parameters::CiphertextModulusLog;

pub fn br_dp_ks_modswitch<
    InputCt,
    PBSResult,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    PBSKey,
    DPScalar,
    KsKey,
    DriftKey,
    Accumulator,
    Resources,
>(
    input: InputCt,
    bsk: &PBSKey,
    scalar: DPScalar,
    ksk: &KsKey,
    mod_switch_noise_reduction_key: &DriftKey,
    accumulator: &Accumulator,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> (
    InputCt,
    PBSResult,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
)
where
    // We need to be able to allocate the result and bootstrap the Input
    PBSKey: AllocateBlindRotationResult<Output = PBSResult, SideResources = Resources>
        + StandardFftBootstrap<InputCt, PBSResult, Accumulator, SideResources = Resources>,
    // Result of the PBS/Blind rotate needs to be multipliable by the scalar
    PBSResult: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
    // We need to be able to allocate the result and keyswitch the result of the ScalarMul
    KsKey: AllocateKeyswtichResult<Output = KsResult, SideResources = Resources>
        + Keyswitch<ScalarMulResult, KsResult, SideResources = Resources>,
    // We need to be able to allocate the result and apply drift technique + mod switch it
    DriftKey: AllocateDriftTechniqueStandardModSwitchResult<
            AfterDriftOutput = DriftTechniqueResult,
            AfterMsOutput = MsResult,
            SideResources = Resources,
        > + DrifTechniqueStandardModSwitch<
            KsResult,
            DriftTechniqueResult,
            MsResult,
            SideResources = Resources,
        >,
{
    let mut pbs_result = bsk.allocated_blind_rotation_result(side_resources);
    bsk.standard_fft_pbs(&input, &mut pbs_result, accumulator, side_resources);
    let (pbs_result, after_dp, ks_result, drift_technique_result, ms_result) = dp_ks_modswitch(
        pbs_result,
        scalar,
        ksk,
        mod_switch_noise_reduction_key,
        br_input_modulus_log,
        side_resources,
    );

    (
        input,
        pbs_result,
        after_dp,
        ks_result,
        drift_technique_result,
        ms_result,
    )
}
