#!/bin/bash
# Run targeted validator tests for unbond, withdraw, and join-window fixes

# Navigate to the finalis-core repository root
cd "$(dirname "$0")"

echo "Running targeted validator security tests..."
echo "============================================"
echo ""

# List of tests specifically related to our fixes
TESTS=(
  "test_validator_min_bond_enforced"
  "test_validator_onboarding_registers_without_bond_and_upgrades_only_via_register_bond"
  "test_validator_onboarding_cannot_use_bonded_exit_path_before_register_bond"
  "test_validator_cooldown_enforced_for_exit_rejoin"
  "test_unbond_signature_and_rule_validation"
  "test_unbond_delay_enforced"
  "test_unbond_finalize_withdrawal_clears_live_bond_state"
  "test_banned_validator_cannot_unbond_scvalreg"
  "test_validator_join_window_replay_deterministic"
  "test_validator_join_window_ignores_non_finalized_paths"
)

passed=0
failed=0

for test in "${TESTS[@]}"; do
  echo -n "Running $test... "
  # Extract just the test result from the full output
  output=$(timeout 30 ./build/finalis-tests 2>&1 | grep -A1 "^\[run.*\] $test")
  
  if echo "$output" | grep -q "^\[ok"; then
    echo "✓ PASSED"
    ((passed++))
  elif echo "$output" | grep -q "^\[fail"; then
    echo "✗ FAILED"
    echo "  $output"
    ((failed++))
  else
    echo "? UNKNOWN (test harness issue)"
  fi
done

echo ""
echo "============================================"
echo "Test Results: $passed passed, $failed failed"
echo "============================================"

if [ $failed -eq 0 ]; then
  echo "✓ All validator security tests PASSED"
  exit 0
else
  echo "✗ Some tests FAILED"
  exit 1
fi
