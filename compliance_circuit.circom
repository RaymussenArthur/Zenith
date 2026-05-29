pragma circom 2.1.6;

template ComplianceCheck() {
    signal input secretData;
    signal input publicThreshold;
    signal output result;

    result <== secretData * publicThreshold;
}

component main {public [publicThreshold]} = ComplianceCheck();