"""Restore a staged Redis rotation from exclusive, verified backups.

The caller owns the execution permit and lock. No errors or document contents
are emitted here; failure is represented only by a boolean.
"""


def restore(ops, permit, state):
    good = True
    try:
        ops.restore_files(permit, state)
    except Exception:
        good = False
    if not good:
        return False
    state.rollback_active = True
    actions = (
        lambda: ops.restart_redis(permit, state),
        lambda: ops.ping(state.old_credential),
        lambda: ops.restart_site(permit, state, "api"),
        lambda: ops.restart_site(permit, state, "worker"),
        lambda: ops.process_online("api"),
        lambda: ops.process_online("worker"),
        lambda: ops.preflight_restored(state),
    )
    for action in actions:
        try:
            if action() is False:
                good = False
        except Exception:
            good = False
    return good
