import time
from typing import List, Tuple, Optional

import gurobipy as gp
from gurobipy import GRB, Var, Model

# ========================================================================================
# 1. Global Cryptographic Constants
# ========================================================================================

# CRAFT 64-bit Block Cipher Constants
BLOCK_SIZE = 64
NIBBLE_COUNT = 16

P: List[int] = [15, 12, 13, 14, 10, 9, 8, 11, 6, 5, 4, 7, 1, 2, 3, 0]

InvP: List[int] = [0] * NIBBLE_COUNT
for i in range(NIBBLE_COUNT):
    InvP[P[i]] = i

# ========================================================================================
# 2. MILP Constraint Generators
# ========================================================================================

def add_mix_column_forward_constraints(model: Model, state_in: List[Var], state_out: List[Var]) -> None:
    """Generates linear constraints for MixColumns forward propagation."""
    for col in range(4):
        idx = [col, col + 4, col + 8, col + 12]
        model.addGenConstrOr(state_out[idx[0]], [state_in[idx[0]], state_in[idx[2]], state_in[idx[3]]])
        model.addGenConstrOr(state_out[idx[1]], [state_in[idx[1]], state_in[idx[3]]])
        model.addConstr(state_out[idx[2]] == state_in[idx[2]])
        model.addConstr(state_out[idx[3]] == state_in[idx[3]])

def add_mix_column_backward_determin_constraints(model: Model, state_in: List[Var], state_out: List[Var]) -> None:
    """Generates constraints for MixColumns backward determination."""
    for col in range(4):
        idx = [col, col + 4, col + 8, col + 12]
        model.addGenConstrOr(state_out[idx[3]], [state_in[idx[0]], state_in[idx[1]], state_in[idx[3]]])
        model.addGenConstrOr(state_out[idx[2]], [state_in[idx[0]], state_in[idx[2]]])
        model.addConstr(state_out[idx[1]] == state_in[idx[1]])
        model.addConstr(state_out[idx[0]] == state_in[idx[0]])

def add_middle_key_consumption_constraints(model: Model, diff_in: List[Var], diff_out: List[Var], middle_k_vars: List[Var]) -> None:
    """Generates constraints for middle key consumption in the meet-in-the-middle phase."""
    for i in range(4):
        model.addGenConstrMin(middle_k_vars[i], [diff_in[i], diff_in[i + 8], diff_in[i + 12], diff_out[P[i]]])
        model.addGenConstrMin(middle_k_vars[i + 4], [diff_in[i + 4], diff_in[i + 12], diff_out[P[i + 4]]])
        model.addGenConstrMin(middle_k_vars[i + 8], [diff_in[i + 8], diff_out[P[i + 8]]])
        model.addGenConstrMin(middle_k_vars[i + 12], [diff_in[i + 12], diff_out[P[i + 12]]])


# ========================================================================================
# 3. Core MILP Solver
# ========================================================================================

def solve_craft_ds_mitm_milp(R: int, num_Z_limit: int, key_limit: int, Rin: int, Rout: int) -> Tuple[Optional[float], Tuple[int, int]]:
    """Builds and solves the MILP model for the CRAFT DS-MITM attack."""
    model = gp.Model("CRAFT_DS_MITM")
    model.setParam('OutputFlag', 0)
    model.setParam('Threads', 4)

    try:
        ax = model.addVars(R + 1, NIBBLE_COUNT, vtype=GRB.BINARY, name="ax")
        ay = model.addVars(R + 1, NIBBLE_COUNT, vtype=GRB.BINARY, name="ay")
        az = model.addVars(R + 1, NIBBLE_COUNT, vtype=GRB.BINARY, name="az")

        middlek = model.addVars(R + 1, NIBBLE_COUNT, vtype=GRB.BINARY, name="middlek")

        state = model.addVars(R + 1, NIBBLE_COUNT, vtype=GRB.BINARY, name="state")
        guess_key = model.addVars(R + 1, NIBBLE_COUNT, vtype=GRB.BINARY, name="guess_key")
        guess_state = model.addVars(R + 1, NIBBLE_COUNT, vtype=GRB.BINARY, name="guess_state")
        guess_key_needed = model.addVars(R + 1, NIBBLE_COUNT, vtype=GRB.BINARY, name="gk_needed")

        akin = model.addVars(R + 1, NIBBLE_COUNT, vtype=GRB.BINARY, name="akin")
        akout = model.addVars(R + 1, NIBBLE_COUNT, vtype=GRB.BINARY, name="akout")

        for r in range(Rin, Rout):
            mc_out = [ax[r + 1, InvP[i]] for i in range(16)]
            add_mix_column_forward_constraints(model, [ax[r, i] for i in range(16)], mc_out)

        for r in range(Rout, Rin, -1):
            inv_p_out = [ay[r, P[i]] for i in range(16)]
            add_mix_column_backward_determin_constraints(model, inv_p_out, [ay[r - 1, i] for i in range(16)])

        for r in range(R + 1):
            if Rin <= r <= Rout:
                for i in range(16):
                    model.addGenConstrMin(az[r, i], [ax[r, i], ay[r, i]])
            else:
                for i in range(16): model.addConstr(az[r, i] == 0)

        for r in range(1, R):
            if Rin <= r < Rout:
                add_middle_key_consumption_constraints(model,
                                                       [az[r, i] for i in range(16)],
                                                       [az[r + 1, i] for i in range(16)],
                                                       [middlek[r, i] for i in range(16)])
            else:
                for i in range(16): model.addConstr(middlek[r, i] == 0)

        for i in range(16):
            model.addConstr(middlek[0, i] == 0)
            model.addConstr(middlek[R, i] == 0)

        mk_even = model.addVars(16, vtype=GRB.BINARY)
        mk_odd = model.addVars(16, vtype=GRB.BINARY)

        for i in range(16):
            e_rds = [middlek[r, i] for r in range(R + 1) if r % 2 == 0]
            if e_rds:
                model.addGenConstrMax(mk_even[i], e_rds)
            else:
                model.addConstr(mk_even[i] == 0)

            o_rds = [middlek[r, i] for r in range(R + 1) if r % 2 == 1]
            if o_rds:
                model.addGenConstrMax(mk_odd[i], o_rds)
            else:
                model.addConstr(mk_odd[i] == 0)

        total_middle_clear = middlek.sum() - (mk_even.sum() + mk_odd.sum())

        for i in range(16): model.addConstr(state[Rin, i] == az[Rin, i])

        for r in range(Rin, 0, -1):
            inv_p = [state[r, P[i]] for i in range(16)]
            add_mix_column_forward_constraints(model, inv_p, [state[r - 1, i] for i in range(16)])

        for r in range(Rin + 1, R + 1):
            for i in range(16): model.addConstr(state[r, i] == 0)

        for r in range(Rin + 1):
            for i in range(16):
                model.addConstr(guess_key[r, i] + guess_state[r, i] == state[r, i])

        for i in range(16): model.addConstr(guess_key_needed[Rin, i] == guess_key[Rin, i])

        for r in range(Rin, 0, -1):
            curr_akin = [guess_key_needed[r, P[i]] for i in range(16)]
            for i in range(16): model.addConstr(akin[r, i] == curr_akin[i])

            akin_out_mc = model.addVars(16, vtype=GRB.BINARY)
            add_mix_column_backward_determin_constraints(model, curr_akin, akin_out_mc)

            for i in range(16):
                model.addGenConstrOr(guess_key_needed[r - 1, i], [guess_key[r - 1, i], akin_out_mc[i]])

        for r in range(Rin + 1, R + 1):
            for i in range(16):
                model.addConstr(guess_key_needed[r, i] == 0)
                model.addConstr(akin[r, i] == 0)

        if R - Rout >= 2:
            add_mix_column_backward_determin_constraints(model,
                                                         [az[Rout, i] for i in range(16)],
                                                         [akout[Rout, i] for i in range(16)])
            for r in range(Rout, R - 1):
                akout_after_p = [akout[r, P[i]] for i in range(16)]
                add_mix_column_backward_determin_constraints(model, akout_after_p, [akout[r + 1, i] for i in range(16)])

        for r in range(Rout):
            for i in range(16): model.addConstr(akout[r, i] == 0)
        for i in range(16): model.addConstr(akout[R, i] == 0)

        model.addConstr(az.sum(Rin, '*') >= 2)
        model.addConstr(az.sum(Rout, '*') >= 1)

        br_even = model.addVars(16, vtype=GRB.BINARY)
        br_odd = model.addVars(16, vtype=GRB.BINARY)

        for i in range(16):
            r_even = [akin[r, i] for r in range(R + 1) if r % 2 == 1 and r < Rin] + \
                     [akout[r, i] for r in range(R + 1) if r % 2 == 0 and r > Rout + 1]
            if r_even:
                model.addGenConstrMax(br_even[i], r_even)
            else:
                model.addConstr(br_even[i] == 0)

            r_odd = [akin[r, i] for r in range(R + 1) if r % 2 == 0 and r < Rin] + \
                    [akout[r, i] for r in range(R + 1) if r % 2 == 1 and r > Rout]
            if r_odd:
                model.addGenConstrMax(br_odd[i], r_odd)
            else:
                model.addConstr(br_odd[i] == 0)

        total_bridge = br_even.sum() + br_odd.sum()
        total_guess = guess_state.sum()
        key = total_bridge + total_guess

        model.addConstr(key <= key_limit, "Complexity_Limit")

        real_num_Z = az.sum() - total_middle_clear
        model.addConstr(real_num_Z <= num_Z_limit, "Z_Limit")

        improve_store = az.sum() - middlek.sum()
        model.setObjective(improve_store, GRB.MINIMIZE)

        model.optimize()

        if model.Status == GRB.OPTIMAL:
            return model.ObjVal, (Rin, Rout)
        else:
            return None, (Rin, Rout)

    except gp.GurobiError:
        return None, (Rin, Rout)

# ========================================================================================
# 4. Main Execution
# ========================================================================================

if __name__ == "__main__":
    TARGET_ROUNDS = 21
    MAX_Z_SIZE = 31
    MAX_KEY_GUESS = 31

    SEARCH_RIN_START = 0
    SEARCH_RIN_END = TARGET_ROUNDS - 3

    print(f"Starting CRAFT Analysis: R={TARGET_ROUNDS}, KeyLimit={MAX_KEY_GUESS}")
    print("-" * 60)

    start_time = time.time()
    best_obj = float('inf')
    best_config = None

    for r_in in range(SEARCH_RIN_START, SEARCH_RIN_END):
        for r_out in range(r_in + 4, TARGET_ROUNDS - 2):
            obj, config = solve_craft_ds_mitm_milp(
                TARGET_ROUNDS, MAX_Z_SIZE, MAX_KEY_GUESS, r_in, r_out
            )

            # 找到解时打印一行提示
            if obj is not None:
                print(f"Found feasible solution: Rin={r_in:2d}, Rout={r_out:2d} | Objective (|Z_guess|) = {obj}")
                if obj < best_obj:
                    best_obj = obj
                    best_config = config

    elapsed = time.time() - start_time
    print("-" * 60)
    print(f"Search Completed in {elapsed:.2f}s")

    # 最终只打印最好的结果
    if best_config:
        r_in_best, r_out_best = best_config
        print(f"\n>>> BEST RESULT FOUND: Rin={r_in_best}, Rout={r_out_best}, |Z|={best_obj}")
    else:
        print("\n>>> No solution found within constraints.")
