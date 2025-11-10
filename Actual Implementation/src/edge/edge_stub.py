# src/edge/edge_stub.py
# Simple Edge Authority (EA) storage stub for TSKs.
# For demo we store TSKs in-memory (dict uid -> list of tsk objects).
# In production this would be a secure store, possibly encrypted at rest.

from typing import Dict, List
from collections import defaultdict

class EdgeAuthorityStub:
    def __init__(self):
        # map uid -> list of TSK dicts
        self.tsk_store = defaultdict(list)

    def store_tsk_for_uid(self, uid: str, tsk_list: List[Dict]):
        """
        Store TSKs (list of dicts). Overwrites previous TSKs for simplicity.
        """
        self.tsk_store[uid] = tsk_list.copy()
        return True

    def get_tsk_for_uid(self, uid: str):
        return self.tsk_store.get(uid, []).copy()

    def attempt_recover_sk(self, uid: str):
        """
        EA's naive attempt to recover SKs from TSKs without user's d.
        It simply returns 'impossible' because EA lacks d.
        For demo we show EA cannot derive original SK scalars.
        """
        tsk_list = self.tsk_store.get(uid, [])
        if not tsk_list:
            return None
        # EA can't invert TSK -> SK without d (we demonstrate this by returning None)
        return None
