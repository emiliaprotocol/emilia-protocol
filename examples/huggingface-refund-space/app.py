"""Local Gradio UI and Hugging Face Space entrypoint. Synthetic actions only."""

import gradio as gr
from demo import SCENARIOS, run_scenario


def readable_theme():
    # Keep the demo on a light surface even when the surrounding app is dark.
    palette = {
        "body_background_fill": "#f7f5ef",
        "body_text_color": "#172c28",
        "body_text_color_subdued": "#445852",
        "background_fill_primary": "#ffffff",
        "background_fill_secondary": "#efeee7",
        "block_background_fill": "#ffffff",
        "block_label_text_color": "#172c28",
        "block_title_text_color": "#172c28",
        "input_background_fill": "#ffffff",
        "input_background_fill_hover": "#f3f5f1",
        "input_background_fill_focus": "#ffffff",
        "border_color_primary": "#c8d1ca",
        "checkbox_label_background_fill": "#ffffff",
        "checkbox_label_background_fill_hover": "#edf4ee",
        "checkbox_label_background_fill_selected": "#e0efe6",
        "checkbox_label_text_color": "#172c28",
        "checkbox_label_text_color_selected": "#172c28",
        "button_primary_background_fill": "#175743",
        "button_primary_background_fill_hover": "#104633",
        "button_primary_text_color": "#ffffff",
        "code_background_fill": "#edf1ec",
    }
    return gr.themes.Default(primary_hue="teal", text_size="lg").set(
        **palette, **{name + "_dark": value for name, value in palette.items()}
    )


def compare(scenario):
    result = run_scenario(scenario)
    statuses = [event["status"] for event in result["events"]]
    if "unknown" in statuses:
        headline = "Response lost. The same approval cannot run again."
        explanation = "Our synthetic provider recorded one refund before timing out. The adapter cannot know that from the timeout. It consumes the approval and refuses its reuse; a real deployment needs provider reconciliation."
    elif statuses == ["completed", "refused"]:
        headline = "One refund. The second attempt is refused."
        explanation = "The first call consumed this approval. Reusing it does not enter the provider again."
    elif statuses == ["completed"]:
        headline = "The exact approved refund went through."
        explanation = (
            "The signed request matches the tool name, recipient, amount, and currency."
        )
    else:
        headline = "No refund was made."
        explanation = "The call needs a valid approval for these exact arguments. The adapter refused it before entering the provider."
    return (
        f"## {headline}\n\n{explanation}\n\n**Synthetic refunds recorded: {result['provider_entries']}**",
        result,
    )


def create_app():
    with gr.Blocks(
        title="EMILIA | An agent's refund, within your approval",
        analytics_enabled=False,
    ) as app:
        gr.Markdown(
            "# Let your agent prepare the refund.\n# Decide what it may execute."
        )
        gr.Markdown(
            "The demo approves **$42 to Alice**. Try changing the amount, changing the recipient, or sending the same request twice. Everything runs inside this demo against a synthetic provider. No account or API key needed. Each click starts a fresh simulated session."
        )
        scenario = gr.Radio(
            choices=[(label, name) for name, label in SCENARIOS.items()],
            value="approved",
            label="What should the agent try?",
        )
        run = gr.Button("Try this call", variant="primary")
        summary = gr.Markdown("Choose a scenario, then try the call.")
        with gr.Accordion("See the exact call and result", open=False):
            details = gr.JSON(label="Demonstration result")
        run.click(
            compare,
            inputs=scenario,
            outputs=[summary, details],
            api_visibility="private",
        )
        gr.Markdown(
            "### Use it with your own tool\nWrap a `smolagents.Tool` with `guard_smolagents_tool`. Keep approvals in host-owned code, outside the model's tool arguments. See the package README included with this example.\n\nThis demo uses a temporary software issuer and an in-memory store. It does not prove a human approved, guarantee a provider outcome, or prevent calls that bypass the wrapper. For production, put the provider credentials behind the Gate and use shared durable consumption state."
        )
    return app


if __name__ == "__main__":
    create_app().launch(
        theme=readable_theme(),
        css=".gradio-container { max-width: 1040px !important; margin: auto; } .prose p { font-size: 18px; line-height: 1.6; } .prose h1 { font-size: clamp(28px, 4vw, 40px); line-height: 1.15; }",
        show_error=False,
    )
