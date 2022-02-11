
# `maingate`

`maingate` implements various standart like plonk arithmetic gates for halo2 backend. `MainGateInstructions` trait has many primitives such as arithemtic operations, assignments, assertions and branching instructions.

## Main Gate

Currently one four width gate and one five width gate are available with following expressions:

* `a * s_a + b * s_b + a * b * s_mul + c * s_c + d * s_d + s_constant`
* `a * s_a + b * s_b + a * b * s_mul_ab + c * s_c + d * s_d + c * d * s_mul_cd + s_constant`

## Range Gate

Range gate utilizes witness columns in the main gate. So it's a custom gate only with some selector column contributions. Range gates basically combines upto 5 limbs of a value where limbs are tested against tables. For example for 55 bit value range gate combines three 17 bit limbs and one 4 bit limb. In that case we have two tables one commits to values in `[0, 2^17)` and the other to `[0, 2^4)`.

Upto 4 limbs range proof takes only single row with 5 limbs it will be two rows.
