import pytest
from demo import SCENARIOS, run_scenario


@pytest.mark.parametrize("scenario", ["missing", "amount_changed", "recipient_changed"])
def test_refusal_never_enters_provider(scenario):
    result = run_scenario(scenario)
    assert result["provider_entries"] == 0
    assert result["events"][0]["status"] == "refused"


def test_approved_call_returns_unchanged_arguments():
    result = run_scenario("approved")
    assert result["provider_entries"] == 1
    assert result["synthetic_refunds"] == [result["approved_request"]]
    assert result["events"][0]["status"] == "completed"


def test_replay_does_not_repeat_refund():
    result = run_scenario("replay")
    assert result["provider_entries"] == 1
    assert [event["status"] for event in result["events"]] == ["completed", "refused"]
    assert result["events"][1]["reason"] == "replay_refused"


def test_response_loss_keeps_authorization_consumed():
    result = run_scenario("response_lost")
    assert result["provider_entries"] == 1
    assert [event["status"] for event in result["events"]] == ["unknown", "refused"]
    assert result["events"][1]["reason"] == "replay_refused"


def test_demo_runs_are_isolated():
    assert run_scenario("approved")["provider_entries"] == 1
    assert run_scenario("approved")["provider_entries"] == 1


def test_invalid_scenario_is_not_a_new_approval():
    with pytest.raises(ValueError):
        run_scenario("approve_everything")


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_gradio_callback(scenario):
    from app import compare

    summary, result = compare(scenario)
    assert summary.startswith("## ")
    assert result["scenario"] == scenario


def test_gradio_app_builds_without_model_credentials():
    from app import create_app, readable_theme

    app = create_app()
    assert app.config["components"]
    assert readable_theme().body_background_fill_dark == "#f7f5ef"
