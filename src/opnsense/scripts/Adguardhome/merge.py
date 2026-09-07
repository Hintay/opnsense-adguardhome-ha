#!/usr/local/bin/python3
"""Three-way merge of the two synchronized AdGuard Home configurations.

Synchronization pushes AdGuardHome.yaml from the source to the receiver, but
the AdGuard Home web interface of both nodes is usually bound to the CARP
address, so the only reachable interface during a failover is the receiver's
and changes are made there.  Both nodes therefore keep the last payload they
agreed on as a base document.  Comparing base, ours and theirs tells a local
edit apart from a stale copy, leaf by leaf:

    base == ours, base != theirs    only they changed it, adopt their value
    base != ours, base == theirs    only we changed it, keep ours
    base != ours, base != theirs    both changed it, the CARP master wins
    ours == theirs                  nothing to do

Leaves are compared as whole values, so a list such as ``user_rules`` is
adopted or kept in one piece.  Node-local keys are never touched and the
members AdGuard Home generates by itself never count as a change.

Every function here is pure; the caller reads and writes the documents.
"""

import copy
from pathlib import Path
import sys

SCRIPT_DIRECTORY = str(Path(__file__).resolve().parent)
if SCRIPT_DIRECTORY not in sys.path:
    sys.path.insert(0, SCRIPT_DIRECTORY)

import agh_api  # noqa: E402  sibling module in the plugin script directory


def comparable(document):
    """Return the view of a document that a comparison may look at."""
    return agh_api.strip_generated(document)


def paths_of(*documents):
    """Return every non-local leaf path of the given views, sorted."""
    found = set()
    for document in documents:
        found.update(path for path, _value in agh_api.leaves(document) if not agh_api.is_local(path))
    return sorted(found)


def value_of(document, view, path):
    """Prefer the value as the document stores it over the normalized one.

    The comparison runs on normalized views, where AdGuard Home durations are
    seconds and generated members are gone; what is written back must stay in
    the notation the peer's AdGuard Home wrote.
    """
    value = agh_api.lookup(document, path)
    return agh_api.lookup(view, path) if value is agh_api.MISSING else value


def take(merged, theirs, view, path):
    """Copy one leaf of theirs into the merged document, removal included."""
    value = value_of(theirs, view, path)
    if value is agh_api.MISSING:
        agh_api.remove(merged, path)
    else:
        agh_api.assign(merged, path, copy.deepcopy(value))


def three_way(base, ours, theirs, ours_is_master):
    """Merge theirs into ours against the common base.

    Returns the merged document, the sorted leaves adopted from theirs and the
    conflicting leaves as {leaf: (ours, theirs, winner)}, where the winner is
    'source' while ours_is_master and 'receiver' otherwise.  Without a base no
    change can be attributed to either side, so ours is returned unchanged.
    """
    merged = copy.deepcopy(ours) if isinstance(ours, dict) else {}
    if base is None:
        return merged, [], {}
    base_view = comparable(base)
    ours_view = comparable(ours)
    theirs_view = comparable(theirs)
    adopted = []
    conflicts = {}
    for path in paths_of(base_view, ours_view, theirs_view):
        mine = agh_api.lookup(ours_view, path)
        yours = agh_api.lookup(theirs_view, path)
        if mine == yours:
            continue
        common = agh_api.lookup(base_view, path)
        if common != mine and common != yours:
            winner = 'source' if ours_is_master else 'receiver'
            conflicts[path] = (value_of(ours, ours_view, path), value_of(theirs, theirs_view, path), winner)
            if winner == 'source':
                continue
        elif common != mine:
            continue  # only this node changed the leaf
        else:
            adopted.append(path)
        take(merged, theirs, theirs_view, path)
    return merged, adopted, conflicts


def drift(base, current):
    """Return the sorted non-local leaves current changed against the base."""
    base_view = comparable(base)
    current_view = comparable(current)
    return [path for path in paths_of(base_view, current_view)
            if agh_api.lookup(base_view, path) != agh_api.lookup(current_view, path)]


def differing(paths, ours, theirs):
    """Return the subset of paths the two documents disagree on, sorted."""
    ours_view = comparable(ours)
    theirs_view = comparable(theirs)
    return [path for path in sorted(set(paths))
            if agh_api.lookup(ours_view, path) != agh_api.lookup(theirs_view, path)]
