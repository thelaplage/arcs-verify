"""
Epistemic Benchmark — SUT Adapters
====================================
Each module in this package wraps one system-under-test and implements
``runner.EpistemicSUTAdapter``.

Available adapters
------------------
- counterpedia.CounterpediaAdapter   — Counterpedia public read API
- amnesiac.AmnesiacAdapter           — Amnesiac memory accountability system
- rag_system.RAGSystemAdapter        — Generic RAG system skeleton

To add a new adapter, inherit from ``runner.EpistemicSUTAdapter`` and
implement ``name``, ``version``, and ``respond``.
"""
