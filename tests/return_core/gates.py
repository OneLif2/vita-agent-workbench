"""02.18: the R1 physical review prompt and the old R1/quick listener gate were
removed. Check (from the actual source) that the listener path can no longer
reach any owner prompt, R1 grant, or button gate before binding SSH. The
executable gate behaviour (power drain -> net -> bind) is compiled and run by
tests/startup_power_ux. No Vita I/O."""
from pathlib import Path

code = (Path(__file__).resolve().parents[2] / 'source/vita_ssh_status.c').read_text(encoding='utf-8')
main = code[code.index('int main(void) {'):code.index('\nout:', code.index('int main(void) {'))]
for banned in ('review_return_local()', 'review_return_expected(', 'await_choice(', 'prep_listener()',
               'r1_boot(', 'apply-return', 'quick_veto()', 'wb_standing_reenroll_local('):
    assert banned not in main, 'listener path still reaches ' + banned
startup = main[main.index('bool owner_confirmed = false;'):main.index('ui_refresh(NULL,"AGENT MODE READY");')]
order = [startup.index(s) for s in ('wb_ssh_prepare(', 'initial_power_drain(', 'net_setup()', 'wb_ssh_open(')]
assert order == sorted(order), 'startup order changed'
assert 'ui_refresh(NULL,"AGENT MODE READY");' in main
# Core-update path: the WBQ2 queue check and updater launch stay; R1 commands are refused.
assert 'ERR r1-removed: Workbench 2.0 uses zero-button update stage + update apply' in code
assert 'queued_core_check()' in code and 'wb_updater_launch()' in code
print('PASS 02.18 listener: no owner prompt / R1 / button gate before bind; WBQ2 update path retained')
