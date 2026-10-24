from .ir import lower_condition
from .linsolve import atoms_of
from .refine import _neg


def atoms_of_cond(cond_text):
    return atoms_of(lower_condition(cond_text))


def negate_atoms(cond_text):
    return atoms_of(_neg(lower_condition(cond_text)))
