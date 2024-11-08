from aligned_py.core.types import PriceEstimate
from aligned_py.sdk import compute_max_fee, estimate_fee

HOLESKY_PUBLIC_RPC_URL = "https://ethereum-holesky-rpc.publicnode.com"


def test_computed_max_fee_for_larger_batch_is_smaller():
    small_fee = compute_max_fee(HOLESKY_PUBLIC_RPC_URL, 2, 10)
    large_fee = compute_max_fee(HOLESKY_PUBLIC_RPC_URL, 5, 10)

    assert small_fee < large_fee

def test_computed_max_fee_for_more_proofs_larger_than_for_less_proofs():
    small_fee = compute_max_fee(HOLESKY_PUBLIC_RPC_URL, 5, 20)
    large_fee = compute_max_fee(HOLESKY_PUBLIC_RPC_URL, 5, 10)

    assert small_fee < large_fee

def test_estimate_fee_are_larger_than_one_another():
    min_fee = estimate_fee(HOLESKY_PUBLIC_RPC_URL, PriceEstimate.Min)
    default_fee = estimate_fee(HOLESKY_PUBLIC_RPC_URL, PriceEstimate.Default)
    instant_fee = estimate_fee(HOLESKY_PUBLIC_RPC_URL, PriceEstimate.Instant)

    assert min_fee < default_fee
    assert default_fee < instant_fee
