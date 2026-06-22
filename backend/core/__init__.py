"""Core cross-cutting concerns for LuminaFPM (config, logging, security).

Per Volume 2 §14.1 the target backend layout groups these under ``core/``. This
package is introduced incrementally (ADR LFPM-IMPL-003) alongside the existing
flat module layout; modules are migrated phase by phase without a big-bang move.
"""
