use super::data_formats::{
    RecoveryExtensionAction, RecoveryExtensionInput, RecoveryExtensionOutput,
};
use super::status_code::Ctap2StatusCode;

//Takes RecoveryExtensionInput, processes it and returns the appropriate output.
pub fn process_recovery(
    inputs: RecoveryExtensionInput,
) -> Result<RecoveryExtensionOutput, Ctap2StatusCode> {
    if inputs.action == RecoveryExtensionAction::State {
        Ok(process_state_command())
    } else if inputs.action == RecoveryExtensionAction::Generate {
        Ok(process_generate_command())
    } else if inputs.action == RecoveryExtensionAction::Recover {
        Ok(process_recover_command())
    } else {
        Err(Ctap2StatusCode::CTAP1_ERR_OTHER)
    }
}

//Retrieves the state and returns a RecoveryExtensionOutput struct with the appropriate information.
fn process_state_command() -> RecoveryExtensionOutput {
    RecoveryExtensionOutput {
        action: RecoveryExtensionAction::State,
        state: 0,
        creds: None,
        cred_id: None,
        sig: None,
    }
}

//Creates backup credentials for each stored backup device.
fn process_generate_command() -> RecoveryExtensionOutput {
    RecoveryExtensionOutput {
        action: RecoveryExtensionAction::Generate,
        state: 0,
        creds: None,
        cred_id: None,
        sig: None,
    }
}

//Processes backup credential for account recovery.
fn process_recover_command() -> RecoveryExtensionOutput {
    RecoveryExtensionOutput {
        action: RecoveryExtensionAction::Recover,
        state: 0,
        creds: None,
        cred_id: None,
        sig: None,
    }
}
