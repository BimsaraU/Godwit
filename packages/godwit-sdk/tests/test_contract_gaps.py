"""What godwit-sdk needed from the contracts and did not get.

``strict=True``: the day a gap is closed these XPASS and fail the run, so the workaround
is retired on purpose rather than forgotten.
"""

from __future__ import annotations

import godwit_contracts
import pytest
from godwit_contracts import Acquisition, FeatureSpec, SourceKind


@pytest.mark.xfail(strict=True, reason="CR-A9-source-kind-is-closed-to-plugins")
def test_a_plugin_source_has_a_kind_of_its_own() -> None:
    assert SourceKind("plugin")


@pytest.mark.xfail(strict=True, reason="CR-A9-acquisition-has-no-generic-catalog-route")
def test_plugin_catalog_statistics_have_their_own_route() -> None:
    assert Acquisition("catalog_bounds")
    assert Acquisition("catalog_value_list")


@pytest.mark.xfail(strict=True, reason="CR-A9-sdk-surface-rests-on-unpromised-types")
def test_the_types_under_the_sdk_surface_are_contracts() -> None:
    for name in ("AccessModeMap", "ContextEvent", "Direction", "PanelView"):
        assert hasattr(godwit_contracts, name), name


@pytest.mark.xfail(strict=True, reason="CR-A9-feature-expression-semantics-unspecified")
def test_a_feature_spec_says_what_its_expression_is() -> None:
    assert "expression_kind" in FeatureSpec.model_fields
