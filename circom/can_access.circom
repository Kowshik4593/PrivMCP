pragma circom 2.0.0;

include "comparators.circom";

template CanAccess() {
    signal input user_role;
    signal input min_role;
    signal input query_type; // Not used in this circuit

    signal output allowed;

    component ge = GreaterEqThan(32);
    ge.in[0] <== user_role;
    ge.in[1] <== min_role;
    allowed <== ge.out;
}

component main = CanAccess();
